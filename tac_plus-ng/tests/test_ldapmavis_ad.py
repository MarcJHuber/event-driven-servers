"""LDAP back-ends against Active Directory (a Samba AD DC): ldapmavis-mt, the Perl and the Python back-end.

samba-dc/start runs the DC in a container and prints the TACTEST_SAMBA_*
variables (see README); without TACTEST_SAMBA_DC the tests are skipped.
Each test class adds its users and groups to an OU of its own, with the
ldap-utils commands over LDAPS as the domain administrator, and removes
them at the end. So the tests can run again against the same DC. The
back-ends get no LDAP_FILTER: they must detect AD to find the users by
sAMAccountName.
"""

from __future__ import annotations

import base64
import os
import secrets
import shutil
import string
import subprocess
import tempfile
import time
import unittest
from typing import ClassVar
from unittest import mock

from tactest import DaemonTestCase, prefix
from tactest.tls import CA
from test_ldapmavis import LDAP_PERL, LDAPMAVIS, PERL, perl_ldap, slapd_arg

URL = os.environ.get("TACTEST_SAMBA_DC")
LDAP_PYTHON = os.path.join(prefix(), "lib", "mavis", "mavis_tacplus_ldap.py")
# the interpreter of the "#!" line of the Python back-end
PYTHON = "/usr/bin/python3" if os.access("/usr/bin/python3", os.X_OK) else shutil.which("python3") or "python3"
SETTINGS = ("TACTEST_SAMBA_BASE", "TACTEST_SAMBA_ADMIN", "TACTEST_SAMBA_PASSWORD", "TACTEST_SAMBA_CA")
SKIP_REASON = "TACTEST_SAMBA_DC is unset (see samba-dc/start in README)"

SECOND = -10000000          # AD time spans: 100 ns units, negative
PASSWORD_MAX_AGE = 1        # seconds, for the users with an expired password
LOCKOUT_THRESHOLD = 2
POSIX_GID = 4711
# the domain password policy of samba-dc/entrypoint: the tests change passwords at once and repeat them
DOMAIN_POLICY = {"pwdProperties": "0", "pwdHistoryLength": "0", "minPwdLength": "1", "minPwdAge": "0",
                 "maxPwdAge": "-9223372036854775808"}

# a fine-grained password policy (PSO) for some users of the OU
PSO = string.Template("""\
dn: $dn
objectClass: msDS-PasswordSettings
msDS-PasswordSettingsPrecedence: 10
msDS-PasswordReversibleEncryptionEnabled: FALSE
msDS-PasswordHistoryLength: 0
msDS-PasswordComplexityEnabled: FALSE
msDS-MinimumPasswordLength: 1
msDS-MinimumPasswordAge: 0
msDS-MaximumPasswordAge: $max_age
msDS-LockoutThreshold: $lockout
msDS-LockoutObservationWindow: $hour
msDS-LockoutDuration: $hour
$applies""")

# the bind errors of AD for the correct password: user, data code, the text of the back-ends
BIND_ERRORS = (
    ("mustchange", "773", "User must reset password."),
    ("disabled", "533", "Account disabled."),
    ("expired", "701", "Account expired."),
    ("nohours", "530", "Not permitted to logon at this time."),
    ("elsewhere", "531", "Not permitted to logon at this workstation."),
    ("pwexpired", "532", "Password expired."),
    ("locked", "775", "User account locked."),
)


def settings():
    """The TACTEST_SAMBA_* values; with TACTEST_SAMBA_DC set, a missing one is an error."""
    missing = [k for k in SETTINGS if not os.environ.get(k)]
    if missing:
        raise AssertionError("TACTEST_SAMBA_DC is set, but not " + ", ".join(missing))
    return {k: os.environ[k] for k in SETTINGS}


def python_ldap3():
    """The Python back-end needs the ldap3 module."""
    try:
        return subprocess.run([PYTHON, "-c", "import ldap3"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              check=False).returncode == 0
    except OSError:
        return False


def perl_string(value):
    """value as a Perl string literal: TLS_OPTIONS of the Perl back-end is Perl source."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def unicode_pwd(password):
    """The unicodePwd value for LDIF: the password in double quotes, UTF-16LE, base64."""
    return base64.b64encode(f'"{password}"'.encode("utf-16-le")).decode()


def ldap_tool(tool, args, stdin, ok=(0,)):
    """Run an ldap-utils command as the domain administrator, with the certificate check of the DC; returns its output."""
    s = settings()
    path = shutil.which(tool)
    if path is None:
        raise AssertionError(f"TACTEST_SAMBA_DC is set, but {tool} (ldap-utils) is missing")
    env = dict(os.environ, LDAPTLS_CACERT=s["TACTEST_SAMBA_CA"], LDAPTLS_REQCERT="demand")
    p = subprocess.run([path, "-x", "-H", URL, "-D", s["TACTEST_SAMBA_ADMIN"], "-w", s["TACTEST_SAMBA_PASSWORD"],
                        *args], input=stdin, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                       check=False, timeout=60)
    if p.returncode not in ok:
        raise AssertionError(f"{tool} failed ({p.returncode}):\n{p.stdout}")
    return p.stdout


def ldap_attributes(dn, *attributes):
    """The attributes of one entry, read by ldapsearch; one value each."""
    out = ldap_tool("ldapsearch", ["-LLL", "-o", "ldif-wrap=no", "-b", dn, "-s", "base", *attributes], None)
    return dict(line.split(": ", 1) for line in out.splitlines() if ": " in line and not line.startswith("dn: "))


class Domain:
    """The users and groups of one test class, in OU=tactest-<tag>; the login name of a user is <cn>-<tag>.

    alice is a member of netadmins, netadmins of staff, dave of staff;
    posix has the gidNumber of the posixGroup unix. The account states
    of the BIND_ERRORS users, and of reset (773) and aged (532), give
    the bind errors of AD.
    """

    # cn: (userAccountControl, more LDIF lines); 512: a normal account, 514: disabled
    USERS: ClassVar[dict[str, tuple[int, str]]] = {
        "reader": (512, ""),
        "alice": (512, ""),
        "bob": (512, ""),
        "carol": (512, ""),
        "dave": (512, ""),
        "posix": (512, f"gidNumber: {POSIX_GID}\n"),
        "mustchange": (512, "pwdLastSet: 0\n"),
        "reset": (512, "pwdLastSet: 0\n"),
        "disabled": (514, ""),
        "expired": (512, "accountExpires: 1\n"),
        "nohours": (512, f"logonHours:: {base64.b64encode(bytes(21)).decode()}\n"),
        "elsewhere": (512, "userWorkstations: nowhere\n"),
        "pwexpired": (512, ""),
        "aged": (512, ""),
        "locked": (512, ""),
        "lockmsg": (512, ""),
    }

    def __init__(self):
        self.base = settings()["TACTEST_SAMBA_BASE"]
        self.tag = secrets.token_hex(3)
        self.ou = f"OU=tactest-{self.tag},{self.base}"
        self.psos = {what: f"CN=tactest-{self.tag}-{what},CN=Password Settings Container,CN=System,{self.base}"
                     for what in ("expired", "lockout")}
        self.created = None

    def login(self, cn):
        return f"{cn}-{self.tag}"

    def dn(self, cn):
        return f"CN={cn},{self.ou}"

    @staticmethod
    def password(cn):
        return cn + "-pw"

    def create(self):
        policy = ldap_attributes(self.base, *DOMAIN_POLICY)
        if policy != DOMAIN_POLICY:
            raise AssertionError(f"the DC does not have the password policy of samba-dc/entrypoint: {policy}")
        ldif = [f"dn: {self.ou}\nobjectClass: organizationalUnit\n"]
        for cn, (uac, more) in self.USERS.items():
            ldif.append(f"dn: {self.dn(cn)}\nobjectClass: user\nsAMAccountName: {self.login(cn)}\n"
                        f"unicodePwd:: {unicode_pwd(self.password(cn))}\nuserAccountControl: {uac}\n{more}")
        for cn, members in (("netadmins", ["alice"]), ("staff", ["netadmins", "dave"])):
            ldif.append(f"dn: {self.dn(cn)}\nobjectClass: group\nsAMAccountName: {self.login(cn)}\n"
                        + "".join(f"member: {self.dn(m)}\n" for m in members))
        ldif.append(f"dn: {self.dn('unix')}\nobjectClass: group\nobjectClass: posixGroup\n"
                    f"sAMAccountName: {self.login('unix')}\ngidNumber: {POSIX_GID}\n")
        hour = 3600 * SECOND
        for what, max_age, lockout, users in (("expired", PASSWORD_MAX_AGE * SECOND, 0, ("pwexpired", "aged")),
                                              ("lockout", 1000 * hour, LOCKOUT_THRESHOLD, ("locked", "lockmsg"))):
            applies = "".join(f"msDS-PSOAppliesTo: {self.dn(u)}\n" for u in users)
            ldif.append(PSO.substitute(dn=self.psos[what], max_age=max_age, lockout=lockout, hour=hour,
                                       applies=applies))
        ldap_tool("ldapadd", [], "\n".join(ldif))
        self.created = time.monotonic()

    # 32: no such object, after a create() that stopped early
    @staticmethod
    def remove_pso(dn):
        ldap_tool("ldapdelete", [dn], None, ok=(0, 32))

    def remove_ou(self):
        ldap_tool("ldapdelete", ["-r", self.ou], None, ok=(0, 32))

    def wait_password_expired(self):
        time.sleep(max(0.0, self.created + PASSWORD_MAX_AGE + 1 - time.monotonic()))


MODULE = string.Template("""
	mavis module = $module {
		setenv LDAP_HOSTS = "$url"
		setenv LDAP_BASE = "$base"
		setenv LDAP_USER = "$reader"
		setenv LDAP_PASSWD = "$readerpw"
$env
		exec = $exec
	}
""")

POLICY = string.Template("""
$module
	user backend = mavis
	login backend = mavis chpass
	pap backend = mavis
	group netadmins { }
	group staff { }
	group unix { }
	ruleset {
		rule nested {
			script { if (member == netadmins && memberof == "$staff") { motd banner = "netadmins in staff\\n" permit } }
		}
		rule netadmins {
			script { if (member == netadmins) { motd banner = "netadmins only\\n" permit } }
		}
		rule staff {
			script { if (memberof == "$staff") { motd banner = "staff\\n" permit } }
		}
		rule unix {
			script { if (member == unix) { motd banner = "unix\\n" permit } }
		}
		rule everyone { script { permit } }
	}
""")


class AdTests:
    """The tests for both back-ends; a subclass sets MODULE, EXEC and env() (its TLS settings)."""

    # the back-end checks the certificate of the DC with the CA of env()
    CHECKS_CA = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.domain = Domain()
        # a cleanup for each entry: unittest runs the others also when one fails
        cls.addClassCleanup(cls.domain.remove_ou)
        for dn in cls.domain.psos.values():
            cls.addClassCleanup(cls.domain.remove_pso, dn)
        cls.domain.create()

    def start(self, config="", **env):
        """Start the daemon; config goes in front of the MAVIS module, env into its setenv lines."""
        d = self.domain
        # the daemon reads a quoted string as slapd.conf does
        lines = "\n".join(f"\t\tsetenv {k} = {slapd_arg(v)}" for k, v in {**self.env(), **env}.items())
        module = MODULE.substitute(module=self.MODULE, url=URL, base=d.ou, reader=d.dn("reader"),
                                   readerpw=d.password("reader"), env=lines, exec=self.EXEC)
        return self.start_daemon(POLICY.substitute(module=config + module, staff=d.dn("staff")))

    def login(self, cn):
        return self.domain.login(cn)

    def lock(self, d, cn):
        """Lock the account cn with wrong passwords; the DC must then show it as locked."""
        for _ in range(LOCKOUT_THRESHOLD):
            with d.connect() as c:
                self.assertEqual(c.pap(self.login(cn), "wrong").status_name, "FAIL")
        self.assertNotEqual(ldap_attributes(self.domain.dn(cn), "lockoutTime").get("lockoutTime", "0"), "0",
                            f"{cn} is not locked")

    def test_lock_checks_the_lockout(self):
        """bob has no lockout policy: lock() must not pass on wrong passwords alone."""
        with self.assertRaisesRegex(AssertionError, "bob is not locked"):
            self.lock(self.start(), "bob")

    def test_pap(self):
        """No LDAP_FILTER: the AD default (sAMAccountName) finds the user."""
        d = self.start()
        for password, status in (("alice-pw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap(self.login("alice"), password).status_name, status)

    def test_ca_path_with_quotes(self):
        """The back-end gets a CA path with quotes and a backslash; with CHECKS_CA, another CA there fails."""
        other = CA("ad-other")
        self.addCleanup(other.remove)
        with tempfile.TemporaryDirectory() as tmp:
            ca = os.path.join(tmp, "it's \"a\" \\t", "ca.pem")
            os.mkdir(os.path.dirname(ca))
            for name, source, passes in (("dc", settings()["TACTEST_SAMBA_CA"], True),
                                         ("other", other.cert, not self.CHECKS_CA)):
                shutil.copy(source, ca)
                with mock.patch.dict(os.environ, TACTEST_SAMBA_CA=ca):
                    d = self.start()
                with self.subTest(ca=name), d.connect() as c:
                    self.assertEqual(c.pap(self.login("alice"), "alice-pw").status_name == "PASS", passes)

    def test_ascii_login(self):
        d = self.start()
        for password, status in (("bob-pw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.ascii_login(self.login("bob"), password).status_name, status)

    def test_unknown_user(self):
        d = self.start()
        with d.connect() as c:
            self.assertEqual(c.pap(self.login("nobody"), "alice-pw").status_name, "FAIL")

    def test_filter_characters(self):
        """No user name filter in the daemon: alice passes, a name with LDAP filter characters finds no user."""
        alice = self.login("alice")
        for name in (alice + "(", alice[:-1] + "*"):
            # a daemon for each name: a backend error can start the authentication fallback
            d = self.start(config="\tacl any_user { permit }\n\tmavis user filter = any_user\n")
            for user, status in ((alice, "PASS"), (name, "FAIL")):
                with self.subTest(name=name, user=user), d.connect() as c:
                    self.assertEqual(c.pap(user, "alice-pw").status_name, status)

    def test_groups(self):
        """memberOf of AD, nested: the group names become TACMEMBER, the group DNs MEMBEROF."""
        d = self.start()
        for user, motd in (("alice", "netadmins in staff\n"), ("dave", "staff\n"), ("bob", "")):
            with self.subTest(user=user), d.connect() as c:
                r = c.ascii_login(self.login(user), user + "-pw")
                self.assertEqual((r.status_name, r.server_msg), ("PASS", motd), r)

    def test_posixgroup(self):
        """On AD the back-ends skip the posixGroup search, unless LDAP_SKIP_POSIXGROUP=0."""
        for env, motd in (({}, ""), ({"LDAP_SKIP_POSIXGROUP": "0"}, "unix\n")):
            d = self.start(**env)
            with self.subTest(env=env), d.connect() as c:
                r = c.ascii_login(self.login("posix"), "posix-pw")
                self.assertEqual((r.status_name, r.server_msg), ("PASS", motd), r)

    def test_password_change(self):
        """The password change dialog sets unicodePwd (UTF-16LE: the new password is not ASCII)."""
        d = self.start()
        new = "carol-neu-ä€"
        with d.connect() as c:
            r = c.ascii_login(self.login("carol"), "", data=["wrong", new, new])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "FAIL"], r)
        with d.connect() as c:
            r = c.ascii_login(self.login("carol"), "", data=["carol-pw", new, new])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "PASS"], r)
        for password, status in ((new, "PASS"), ("carol-pw", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap(self.login("carol"), password).status_name, status)

    def test_bind_errors(self):
        """The correct password of an account that AD does not let log in: FAIL, also without a password change."""
        d = self.start()
        self.lock(d, "locked")
        self.domain.wait_password_expired()
        for user, code, _ in BIND_ERRORS:
            with self.subTest(user=user, code=code), d.connect() as c:
                self.assertEqual(c.pap(self.login(user), user + "-pw").status_name, "FAIL")
            if code in ("773", "533", "532"):
                continue
            with self.subTest(user=user, code=code, login="ascii"), d.connect() as c:
                self.assertEqual(c.ascii_login(self.login(user), user + "-pw").statuses, ["GETPASS", "FAIL"])


@unittest.skipUnless(URL, SKIP_REASON)
@unittest.skipUnless(os.path.exists(LDAPMAVIS), "the build has no ldapmavis-mt (OpenLDAP or pthreads missing)")
class AdMt(AdTests, DaemonTestCase):
    CONFIG = None
    MODULE = "external-mt"
    EXEC = f'"{LDAPMAVIS}" "ldapmavis-mt"'
    # ldapmavis-mt makes its TLS context before it reads the LDAP_OPT_X_TLS_* settings
    CHECKS_CA = False

    def env(self):
        return {"LDAP_OPT_X_TLS_CACERTFILE": settings()["TACTEST_SAMBA_CA"],
                "LDAP_OPT_X_TLS_REQUIRE_CERT": "LDAP_OPT_X_TLS_DEMAND"}

    @unittest.expectedFailure
    def test_filter_characters(self):
        """ldapmavis-mt puts the user name into the filter without escapes: the name with "*" finds alice."""
        super().test_filter_characters()


@unittest.skipUnless(URL, SKIP_REASON)
@unittest.skipUnless(perl_ldap(), "no Net::LDAP or IO::Socket::SSL for Perl")
class AdPerl(AdTests, DaemonTestCase):
    CONFIG = None
    MODULE = "external"
    EXEC = f'"{PERL}" "perl" "{LDAP_PERL}"'

    def env(self):
        # IO::Socket::SSL counts the timeout in whole seconds: with 1 s, an LDAPS handshake over a second boundary fails
        return {"TLS_OPTIONS": f"verify => 'require', cafile => {perl_string(settings()['TACTEST_SAMBA_CA'])}",
                "LDAP_CONNECT_TIMEOUT": "5"}

    def test_bind_error_messages(self):
        """The text for the "data" code of the AD bind error goes to the client."""
        d = self.start()
        self.lock(d, "lockmsg")
        self.domain.wait_password_expired()
        for user, code, text in BIND_ERRORS + (("alice", "52e", "Invalid credentials."),):
            user = "lockmsg" if user == "locked" else user     # test_bind_errors locks "locked"
            password = "wrong" if user == "alice" else user + "-pw"
            with self.subTest(user=user, code=code), d.connect() as c:
                r = c.pap(self.login(user), password)
                self.assertEqual((r.status_name, r.server_msg), ("FAIL", text + "\n"), r)

    def test_must_change(self):
        """A password that must change (773) or that expired (532) starts the password change dialog."""
        d = self.start()
        self.domain.wait_password_expired()
        for user in ("reset", "aged"):
            new = user + "-new"
            with self.subTest(user=user), d.connect() as c:
                r = c.ascii_login(self.login(user), user + "-pw", data=[new, new])
                self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "PASS"], r)
        # the policy of aged lets its new password expire at once
        for password, status in (("reset-new", "PASS"), ("reset-pw", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap(self.login("reset"), password).status_name, status)



@unittest.skipUnless(URL, SKIP_REASON)
@unittest.skipUnless(python_ldap3(), f"no ldap3 module for {PYTHON}")
class AdPython(AdTests, DaemonTestCase):
    """No certificate check: TLS_OPTIONS of mavis_tacplus_ldap.py cannot give ldap3 a CA."""

    CONFIG = None
    MODULE = "external"
    EXEC = f'"{PYTHON}" "python3" "{LDAP_PYTHON}"'
    CHECKS_CA = False

    def env(self):
        return {}

    @unittest.skip("mavis_tacplus_ldap.py gives ldap3 the old and the new password in the wrong order for AD")
    def test_password_change(self):
        pass


class DomainCleanup(unittest.TestCase):
    """The class cleanup of the AD tests, with stand-ins for the ldap-utils commands (no DC needed)."""

    # like OpenLDAP: one DN as the last argument, or with -c the DNs on stdin and the last nonzero exit code
    LDAPDELETE = """for a; do :; done
if [ "$a" = -c ]; then cat; else echo "$a"; fi | {
    rc=0
    while IFS= read -r dn; do
        echo "$dn" >> "$TACTEST_LDAP_LOG"
        case $dn in
            CN=*-expired,*) code=${DELETE_EXPIRED:-0};;
            CN=*-lockout,*) code=${DELETE_LOCKOUT:-0};;
            *) code=0;;
        esac
        [ "$code" = 0 ] || rc=$code
    done
    exit $rc
}"""

    def run_class(self, expired, lockout):
        """Run the setup and the cleanup of an AdTests class; returns the result and the DNs that ldapdelete got."""
        with tempfile.TemporaryDirectory() as tmp:
            ldif = "dn: x\n" + "".join(f"{k}: {v}\n" for k, v in DOMAIN_POLICY.items())
            with open(os.path.join(tmp, "policy.ldif"), "w") as f:
                f.write(ldif)
            for tool, body in (("ldapadd", "cat > /dev/null"), ("ldapsearch", f'cat "{tmp}/policy.ldif"'),
                               ("ldapdelete", self.LDAPDELETE)):
                with open(os.path.join(tmp, tool), "w") as f:
                    f.write("#!/bin/sh\n" + body + "\n")
                os.chmod(os.path.join(tmp, tool), 0o755)
            log = os.path.join(tmp, "ldapdelete.log")
            env = dict({k: "x" for k in SETTINGS}, DELETE_EXPIRED=str(expired), DELETE_LOCKOUT=str(lockout),
                       TACTEST_LDAP_LOG=log, PATH=tmp + os.pathsep + os.environ["PATH"])

            class Probe(AdTests, unittest.TestCase):
                def test_nothing(self):
                    pass

            result = unittest.TestResult()
            with mock.patch.dict(os.environ, env), mock.patch(f"{__name__}.URL", "ldaps://127.0.0.1:1"):
                unittest.TestSuite([Probe("test_nothing")]).run(result)
            with open(log) as f:
                return result, f.read().splitlines()

    def errors(self, result):
        return "\n".join(text for _, text in result.errors)

    def test_failed_pso_delete_is_an_error_when_the_other_pso_is_absent(self):
        """32 (no such object) of one PSO must not hide the failure of the other."""
        result, _ = self.run_class(expired=50, lockout=32)
        self.assertIn("ldapdelete failed (50)", self.errors(result))

    def test_each_pso_delete_runs_when_one_fails(self):
        for expired, lockout in ((50, 0), (0, 50)):
            with self.subTest(expired=expired, lockout=lockout):
                result, deleted = self.run_class(expired=expired, lockout=lockout)
                self.assertIn("ldapdelete failed (50)", self.errors(result))
                self.assertEqual(sorted(dn.split(",", 1)[0].rsplit("-", 1)[1] for dn in deleted if dn.startswith("CN=")),
                                 ["expired", "lockout"], deleted)

    def test_ou_delete_runs_when_a_pso_delete_fails(self):
        result, deleted = self.run_class(expired=50, lockout=0)
        self.assertIn("ldapdelete failed (50)", self.errors(result))
        self.assertTrue([dn for dn in deleted if dn.startswith("OU=tactest-")], deleted)

class SambaDcStart(unittest.TestCase):
    """samba-dc/start with stand-ins for docker and openssl (no DC needed)."""

    START = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samba-dc", "start")

    def test_missing_timeout(self):
        """Without the timeout command, start stops before the image build, with a message that names it."""
        with tempfile.TemporaryDirectory() as tmp:
            for tool in ("dirname", "mkdir", "cksum", "cut", "sed", "sleep"):
                os.symlink(shutil.which(tool), os.path.join(tmp, tool))
            log = os.path.join(tmp, "docker.log")
            # the container stops at once: without timeout, start then says that the DC does not answer
            for tool, body in (("docker", f'echo "$1" >> "{log}"\ncase $1 in port) echo 127.0.0.1:1;; '
                                          'inspect) echo false;; esac'),
                               ("openssl", "echo 00")):
                with open(os.path.join(tmp, tool), "w") as f:
                    f.write("#!/bin/sh\n" + body + "\n")
                os.chmod(os.path.join(tmp, tool), 0o755)
            p = subprocess.run(["/bin/sh", self.START], env={"PATH": tmp}, capture_output=True, text=True,
                               check=False)
            ran = os.path.exists(log)
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn("start: the timeout command is missing", p.stderr)
        self.assertFalse(ran, "start ran docker")


if __name__ == "__main__":
    unittest.main()
