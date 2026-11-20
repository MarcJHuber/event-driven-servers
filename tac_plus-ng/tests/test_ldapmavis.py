"""LDAP backends against a real OpenLDAP slapd: ldapmavis-mt, mavis_tacplus-ng_ldap.pl and mavis_tacplus_ldap.pl.

Every test starts a slapd of its own, as a normal process on a free
loopback port, with a database that slapadd fills before the start. The
anonymous user can only bind, so the backend must bind as LDAP_USER to
search. alice is a member of netadmins, and netadmins is a member of
staff; dave is a direct member of staff; bob is in no group. erin and
frank have the tacacs schema of mavis/perl; the password of frank expired.
"""

import glob
import os
import re
import select
import shutil
import socket
import string
import struct
import subprocess
import tempfile
import threading
import time
import unittest

from tactest import DaemonTestCase, Stub, prefix
from tactest.daemon import free_port, sanitizer_env

SLAPD = shutil.which("slapd") or "/usr/sbin/slapd"
SCHEMA_DIRS = ("/etc/ldap/schema", "/etc/openldap/schema")
# Debian and Ubuntu build the back-ends as modules in /usr/lib/ldap, Alpine in /usr/lib/openldap
MODULE_DIRS = ("/usr/lib/ldap", "/usr/lib/openldap", "/usr/lib64/openldap", "/usr/libexec/openldap")
LDAPMAVIS = os.path.join(prefix(), "sbin", "ldapmavis-mt")
LDAP_PERL = os.path.join(prefix(), "lib", "mavis", "mavis_tacplus-ng_ldap.pl")
LDAP_PERL_OLD = os.path.join(prefix(), "lib", "mavis", "mavis_tacplus_ldap.pl")
TACACS_SCHEMA = os.path.join(prefix(), "lib", "mavis", "extra", "tacacs.schema")
PERL = shutil.which("perl") or "/usr/bin/perl"
START_TIMEOUT = 10.0

BASE = "dc=example,dc=com"
READER = "cn=reader," + BASE
STAFF = "cn=staff,ou=groups," + BASE
WIDE = 2000                 # groups of one user, above the 1024 of the old fixed array
# memberOf as a plain attribute, the way Active Directory has it; no overlay needed
MEMBEROF_SCHEMA = "attributetype ( 1.2.840.113556.1.2.102 NAME 'memberOf' SUP distinguishedName )\n"

SLAPD_CONF = string.Template("""\
include $core
include $cosine
include $inetorgperson
include $nis
include $tacacs
include $memberof
$modules
sizelimit unlimited
pidfile $pidfile
argsfile $argsfile

access to dn.base="" by * read
access to dn.base="cn=Subschema" by * read
access to attrs=userPassword by self write by anonymous auth by * none
access to * by users read by * none

database mdb
suffix "$base"
directory $db
""")

LDIF = string.Template("""\
dn: $base
objectClass: dcObject
objectClass: organization
o: Example
dc: example

dn: ou=people,$base
objectClass: organizationalUnit
ou: people

dn: ou=groups,$base
objectClass: organizationalUnit
ou: groups

dn: $reader
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: reader
userPassword: readerpw

dn: uid=alice,ou=people,$base
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Alice
userPassword: alicepw

dn: uid=bob,ou=people,$base
objectClass: inetOrgPerson
uid: bob
cn: Bob
sn: Bob
userPassword: bobpw

dn: uid=carol,ou=people,$base
objectClass: inetOrgPerson
uid: carol
cn: Carol
sn: Carol
userPassword: carolpw

dn: uid=dave,ou=people,$base
objectClass: inetOrgPerson
uid: dave
cn: Dave
sn: Dave
userPassword: davepw

dn: cn=netadmins,ou=groups,$base
objectClass: groupOfNames
cn: netadmins
member: uid=alice,ou=people,$base

dn: $staff
objectClass: groupOfNames
cn: staff
member: cn=netadmins,ou=groups,$base
member: uid=dave,ou=people,$base

dn: uid=erin,ou=people,$base
objectClass: inetOrgPerson
objectClass: tacacsAccount
uid: erin
cn: Erin
sn: Erin
userPassword: erinpw

dn: uid=frank,ou=people,$base
objectClass: inetOrgPerson
objectClass: shadowAccount
objectClass: tacacsAccount
uid: frank
cn: Frank
sn: Frank
userPassword: frankpw
shadowExpire: 1
""").substitute(base=BASE, reader=READER, staff=STAFF)


def slapd_arg(value):
    """A slapd.conf argument: double quotes keep blanks, a backslash escapes a quote or a backslash."""
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


def person(uid, extra=""):
    """An LDIF entry for a user of one test, password <uid>pw; extra: more lines."""
    return (f"\ndn: uid={uid},ou=people,{BASE}\nobjectClass: inetOrgPerson\n{extra}"
            f"uid: {uid}\ncn: {uid}\nsn: {uid}\nuserPassword: {uid}pw\n")


def first_existing(paths):
    return next((p for p in paths if os.path.isdir(p)), None)


def modules():
    """moduleload lines for the mdb back-end, empty if slapd has it built in."""
    for d in MODULE_DIRS:
        if glob.glob(os.path.join(d, "back_mdb.*")):
            return f"modulepath {slapd_arg(d)}\nmoduleload back_mdb"
    return ""


def perl_ldap():
    """The Perl back-end needs Net::LDAP and IO::Socket::SSL."""
    try:
        return subprocess.run([PERL, "-MNet::LDAP", "-MIO::Socket::SSL", "-e", "1"], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, check=False).returncode == 0
    except OSError:
        return False


class Slapd:
    """slapd on 127.0.0.1, configuration and database in directory/"slapd data" (the blank tests the quoting)."""

    def __init__(self, directory, entries=""):
        directory = os.path.join(directory, "slapd data")
        os.mkdir(directory)
        self.dir = directory
        self.proc = None
        self.port = None
        self.log = os.path.join(directory, "slapd.log")
        self.conf = os.path.join(directory, "slapd.conf")
        schema = first_existing(SCHEMA_DIRS)
        if schema is None:
            raise AssertionError(f"no OpenLDAP schema directory in {SCHEMA_DIRS}")
        paths = {n: os.path.join(schema, n + ".schema") for n in ("core", "cosine", "inetorgperson", "nis")}
        paths.update(tacacs=TACACS_SCHEMA)
        paths.update(pidfile=os.path.join(directory, "slapd.pid"), argsfile=os.path.join(directory, "slapd.args"),
                     db=os.path.join(directory, "db"), memberof=os.path.join(directory, "memberof.schema"))
        with open(self.conf, "w") as f:
            f.write(SLAPD_CONF.substitute({k: slapd_arg(v) for k, v in paths.items()}, modules=modules(), base=BASE))
        with open(paths["memberof"], "w") as f:
            f.write(MEMBEROF_SCHEMA)
        os.mkdir(os.path.join(directory, "db"))
        ldif = os.path.join(directory, "data.ldif")
        with open(ldif, "w") as f:
            f.write(LDIF + entries)
        p = subprocess.run([SLAPD, "-T", "add", "-f", self.conf, "-l", ldif], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, check=False)
        if p.returncode:
            raise AssertionError("slapadd failed:\n" + p.stdout.decode("utf-8", "replace"))

    @property
    def url(self):
        return f"ldap://127.0.0.1:{self.port}"

    def start(self):
        self.port = free_port("127.0.0.1")
        with open(self.log, "ab") as log:
            # -d keeps slapd in the foreground; 256 logs the connections and operations
            self.proc = subprocess.Popen([SLAPD, "-d", "256", "-h", self.url + "/", "-f", self.conf],
                                         stdout=log, stderr=log, stdin=subprocess.DEVNULL)
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", self.port)) == 0:
                    return
            select.select([], [], [], 0.05)
        self.stop()
        with open(self.log, errors="replace") as f:
            raise AssertionError(f"slapd did not start on {self.url}:\n{f.read()[-3000:]}")

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


# ldapmavis-mt skips the groupOfNames search while LDAP_NESTED_GROUP_DEPTH is unset
MODULE = string.Template("""
	mavis module = $module {
		setenv LDAP_HOSTS = "$url"
		setenv LDAP_BASE = "$base"
		setenv LDAP_USER = "$reader"
		setenv LDAP_PASSWD = "readerpw"
		setenv LDAP_FILTER = "(&(objectClass=inetOrgPerson)(uid=%s))"
		setenv LDAP_NESTED_GROUP_DEPTH = "10"
$extra		exec = $exec
	}
""")

POLICY = string.Template("""
$module
	user backend = mavis
	login backend = mavis chpass
	pap backend = mavis
	authentication fallback = permit
	user rescue {
		fallback-only
		password pap = clear rescuepw
	}
	group netadmins { }
	group staff { }
	ruleset {
		rule wide {
			script { if (memberof == "cn=wide-$last,ou=groups,$base") { motd banner = "wide\\n" permit } }
		}
		rule sneaky {
			script { if (memberof == "cn=sneaky,ou=groups,$base") { motd banner = "sneaky\\n" permit } }
		}
		rule special {
			script {
				if (memberof == "cn=labs,ou=groups,$base" && memberof == "cn=xparent,ou=groups,$base") {
					motd banner = "labs and xparent\\n"
					permit
				}
			}
		}
		rule top {
			script { if (memberof == "cn=l3,ou=groups,$base") { motd banner = "l3\\n" permit } }
		}
		rule cycle {
			script {
				if (memberof == "cn=cyc-a,ou=groups,$base" && memberof == "cn=cyc-b,ou=groups,$base") {
					motd banner = "cycle\\n"
					permit
				}
			}
		}
		rule nested {
			script { if (member == netadmins && memberof == "$staff") { motd banner = "netadmins in staff\\n" permit } }
		}
		rule netadmins {
			script { if (member == netadmins) { motd banner = "netadmins only\\n" permit } }
		}
		rule staff {
			script { if (memberof == "$staff") { motd banner = "staff\\n" permit } }
		}
		rule everyone { script { permit } }
	}
""")


class LdapTests:
    """The tests for both back-ends; a subclass sets module(url, extra) to its "mavis module" block."""

    def slapd(self, ldif=""):
        """A running slapd; ldif: more entries."""
        # a directory of its own for every slapd: a test may start more than one
        slapd = Slapd(tempfile.mkdtemp(prefix="slapd-", dir=os.path.dirname(self.scratch_file("slapd", ""))), ldif)
        self.addCleanup(slapd.stop)
        slapd.start()
        return slapd

    def start(self, ldif="", policy="", **env):
        """Start slapd and the daemon; ldif: more entries, policy: more lines for the daemon, env: for the back-end."""
        slapd = self.slapd(ldif)
        extra = "".join(f'\t\tsetenv {name} = "{value}"\n' for name, value in env.items())
        return slapd, self.start_daemon(POLICY.substitute(module=self.module(slapd.url, extra), staff=STAFF,
                                                                            base=BASE, last=WIDE - 1) + policy)

    def test_pap(self):
        _, d = self.start()
        for password, status in (("alicepw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap("alice", password).status_name, status)

    def test_ascii_login(self):
        _, d = self.start()
        for password, status in (("bobpw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.ascii_login("bob", password).status_name, status)

    def test_unknown_user(self):
        _, d = self.start()
        with d.connect() as c:
            self.assertEqual(c.pap("mallory", "alicepw").status_name, "FAIL")

    def test_groups(self):
        """groupOfNames, nested: the group names become TACMEMBER, the group DNs MEMBEROF."""
        _, d = self.start()
        for user, password, motd in (("alice", "alicepw", "netadmins in staff\n"), ("dave", "davepw", "staff\n"),
                                     ("bob", "bobpw", "")):
            with self.subTest(user=user), d.connect() as c:
                r = c.ascii_login(user, password)
                self.assertEqual((r.status_name, r.server_msg), ("PASS", motd), r)

    def test_scope(self):
        """LDAP_SCOPE takes the documented values; the users are two levels below LDAP_BASE."""
        for scope, status in (("sub", "PASS"), ("one", "FAIL"), ("base", "FAIL")):
            with self.subTest(scope=scope):
                _, d = self.start(LDAP_SCOPE=scope)
                with d.connect() as c:
                    self.assertEqual(c.pap("alice", "alicepw").status_name, status)

    def test_group_scope(self):
        """LDAP_SCOPE_GROUP = one below LDAP_BASE_GROUP = ou=groups finds both groups of alice."""
        _, d = self.start(LDAP_SCOPE_GROUP="one", LDAP_BASE_GROUP="ou=groups," + BASE)
        with d.connect() as c:
            r = c.ascii_login("alice", "alicepw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "netadmins in staff\n"), r)

    def test_group_cycle(self):
        """cyc-a and cyc-b are members of each other: the walk ends, and both groups count."""
        ldif = person("ivan") + string.Template("""
dn: cn=cyc-a,ou=groups,$base
objectClass: groupOfNames
cn: cyc-a
member: uid=ivan,ou=people,$base
member: cn=cyc-b,ou=groups,$base

dn: cn=cyc-b,ou=groups,$base
objectClass: groupOfNames
cn: cyc-b
member: cn=cyc-a,ou=groups,$base
""").substitute(base=BASE)
        _, d = self.start(ldif=ldif)
        with d.connect() as c:
            r = c.ascii_login("ivan", "ivanpw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "cycle\n"), r)

    def test_filter_characters_in_a_group_dn(self):
        """A group DN with "(" or "*" finds its own parent group, and "*" matches no other group (RFC 4515)."""
        ldif = person("hank") + string.Template("""
dn: cn=ops(lab),ou=groups,$base
objectClass: groupOfNames
cn: ops(lab)
member: uid=hank,ou=people,$base

dn: cn=labs,ou=groups,$base
objectClass: groupOfNames
cn: labs
member: cn=ops(lab),ou=groups,$base

dn: cn=x*,ou=groups,$base
objectClass: groupOfNames
cn: x*
member: uid=hank,ou=people,$base

dn: cn=xparent,ou=groups,$base
objectClass: groupOfNames
cn: xparent
member: cn=x*,ou=groups,$base

dn: cn=sneaky,ou=groups,$base
objectClass: groupOfNames
cn: sneaky
member: cn=xylophone,ou=groups,$base
""").substitute(base=BASE)
        _, d = self.start(ldif=ldif)
        with d.connect() as c:
            r = c.ascii_login("hank", "hankpw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "labs and xparent\n"), r)

    def test_filter_characters_in_the_user_name(self):
        """A "*" in the user name matches no other user (RFC 4515), also when "mavis user filter" lets it through."""
        _, d = self.start(policy="\tacl any-user { permit }\n\tmavis user filter = any-user\n")
        for user in ("alic*", "*"):
            with self.subTest(user=user), d.connect() as c:
                self.assertEqual(c.pap(user, "alicepw").status_name, "FAIL")

    def test_empty_user_name(self):
        """tac_plus-ng passes no empty user name on (PAP: ERROR, ASCII: it asks again); the next login works."""
        _, d = self.start()
        with d.connect() as c:
            self.assertEqual(c.pap("", "alicepw").status_name, "ERROR")
        with d.connect() as c:
            s = c.session()
            self.assertEqual(s.start(user="").status_name, "GETUSER")
            self.assertEqual(s.cont("").status_name, "GETUSER")
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")

    def test_nested_memberof(self):
        """memberOf over three levels: nell is in l1, l1 in l2, l2 in l3."""
        ldif = person("nell", f"objectClass: extensibleObject\nmemberOf: cn=l1,ou=groups,{BASE}\n")
        for name, parent in (("l1", "l2"), ("l2", "l3"), ("l3", None)):
            ldif += f"\ndn: cn={name},ou=groups,{BASE}\nobjectClass: groupOfNames\nobjectClass: extensibleObject\n"
            ldif += f"cn: {name}\nmember: cn=nobody,{BASE}\n"
            if parent:
                ldif += f"memberOf: cn={parent},ou=groups,{BASE}\n"
        _, d = self.start(ldif=ldif)
        with d.connect() as c:
            r = c.ascii_login("nell", "nellpw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "l3\n"), r)

    def test_memberof_searches_once(self):
        """Depth 10, mos-1 in mos-2 ... in mos-9, the user is in all nine: the walk searches each group once."""
        chain = [f"mos-{i}" for i in range(1, 10)]
        ldif = person("mos", "objectClass: extensibleObject\n" + "".join(f"memberOf: cn={g},ou=groups,{BASE}\n"
                                                                         for g in chain))
        for name, parent in zip(chain, chain[1:] + [None]):
            ldif += f"\ndn: cn={name},ou=groups,{BASE}\nobjectClass: groupOfNames\nobjectClass: extensibleObject\n"
            ldif += f"cn: {name}\nmember: cn=nobody,{BASE}\n"
            ldif += f"memberOf: cn={parent},ou=groups,{BASE}\n" if parent else ""
        slapd, d = self.start(ldif=ldif, LDAP_NESTED_GROUP_DEPTH="10")
        with d.connect() as c:
            self.assertEqual(c.pap("mos", "mospw").status_name, "PASS")
        with open(slapd.log, errors="replace") as f:
            log = f.read()
        for name in chain:
            searches = re.findall(rf'SRCH base="cn={name},ou=groups,{BASE}" scope=0 ', log, re.IGNORECASE)
            self.assertEqual(len(searches), 1, name)

    def test_password_change(self):
        """An empty password at an ASCII login starts the password change dialog ("login backend = mavis chpass")."""
        _, d = self.start()
        with d.connect() as c:
            r = c.ascii_login("carol", "", data=["carolpw", "newpw", "newpw"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "PASS"], r)
        for password, status in (("newpw", "PASS"), ("carolpw", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap("carol", password).status_name, status)

    def test_server_stopped(self):
        """With slapd stopped the backend reports an error, so the fallback-only user can log in."""
        slapd, d = self.start()
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")
        slapd.stop()
        with d.connect(timeout=15.0) as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "FAIL")
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS")


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(os.path.exists(LDAPMAVIS), "the build has no ldapmavis-mt (OpenLDAP or pthreads missing)")
class LdapMt(LdapTests, DaemonTestCase):
    CONFIG = None

    def module(self, url, extra):
        return MODULE.substitute(module="external-mt", url=url, base=BASE, reader=READER, extra=extra,
                                 exec=f'"{LDAPMAVIS}" "ldapmavis-mt"')

    def test_request_without_a_user_name(self):
        """No or an empty user name: FAIL, and the backend answers the next request.

        tac_plus-ng sends no such request (see test_empty_user_name), so the
        test speaks the external-mt protocol to ldapmavis-mt itself.
        """
        slapd = self.slapd()
        env = {**sanitizer_env(), "LDAP_HOSTS": slapd.url, "LDAP_BASE": BASE, "LDAP_USER": READER,
               "LDAP_PASSWD": "readerpw"}
        with subprocess.Popen([LDAPMAVIS], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env=env) as p:
            watchdog = threading.Timer(60, p.kill)
            watchdog.start()
            try:
                for user, result in ((None, b"NAK"), (b"", b"NAK"), (b"alice", b"ACK")):
                    body = (b"" if user is None else b"4 " + user + b"\n") + b"8 alicepw\n21 serial\n49 AUTH\n\n"
                    p.stdin.write(struct.pack("!III", 0x4d610001, len(body), 0) + body)
                    p.stdin.flush()
                    header = p.stdout.read(12)
                    self.assertEqual(len(header), 12, f"no reply for user {user!r}, the backend exited")
                    reply = p.stdout.read(struct.unpack("!III", header)[1])
                    self.assertRegex(reply, rb"(?m)^6 " + result + rb"$", user)
            finally:
                watchdog.cancel()
                p.kill()

    def test_wide_group_tree(self):
        """A user in more groups than the old fixed array of the group walk had; the last group still counts."""
        ldif = "".join(f"\ndn: cn=wide-{i},ou=groups,{BASE}\nobjectClass: groupOfNames\ncn: wide-{i}\n"
                       f"member: uid=wide,ou=people,{BASE}\n" for i in range(WIDE))
        _, d = self.start(ldif=person("wide") + ldif, LDAP_SIZELIMIT=str(2 * WIDE))
        with d.connect(timeout=30.0) as c:
            r = c.ascii_login("wide", "widepw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "wide\n"), r)

    def test_wide_memberof_tree(self):
        """memberOf: the direct group of the user has WIDE parents, and only the last parent is in cn=wide-<last>."""
        last = f"cn=wide-{WIDE - 1},ou=groups,{BASE}"
        ldif = person("mowide", f"objectClass: extensibleObject\nmemberOf: cn=mo-direct,ou=groups,{BASE}\n")
        ldif += f"\ndn: cn=mo-direct,ou=groups,{BASE}\nobjectClass: groupOfNames\nobjectClass: extensibleObject\n"
        ldif += f"cn: mo-direct\nmember: cn=nobody,{BASE}\n"
        ldif += "".join(f"memberOf: cn=mo-{i},ou=groups,{BASE}\n" for i in range(WIDE))
        for i in range(WIDE):
            ldif += f"\ndn: cn=mo-{i},ou=groups,{BASE}\nobjectClass: groupOfNames\nobjectClass: extensibleObject\n"
            ldif += f"cn: mo-{i}\nmember: cn=nobody,{BASE}\n" + (f"memberOf: {last}\n" if i == WIDE - 1 else "")
        _, d = self.start(ldif=ldif)
        with d.connect(timeout=30.0) as c:
            r = c.ascii_login("mowide", "mowidepw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "wide\n"), r)


    def test_memberof_depth_order(self):
        """Depth 10, direct groups ord-a and ord-b: ord-a reaches ord-b at level 10, ord-b is in l3.

        l3 is two levels from the direct group ord-b, so both orders of the
        memberOf values must give l3.
        """
        chain = ["ord-a"] + [f"ord-{i}" for i in range(1, 9)] + ["ord-b", "l3"]
        ldif = ""
        for name, parent in zip(chain, chain[1:] + [None]):
            ldif += f"\ndn: cn={name},ou=groups,{BASE}\nobjectClass: groupOfNames\nobjectClass: extensibleObject\n"
            ldif += f"cn: {name}\nmember: cn=nobody,{BASE}\n"
            ldif += f"memberOf: cn={parent},ou=groups,{BASE}\n" if parent else ""
        for user, first, second in (("ordab", "ord-a", "ord-b"), ("ordba", "ord-b", "ord-a")):
            ldif += person(user, f"objectClass: extensibleObject\nmemberOf: cn={first},ou=groups,{BASE}\n"
                                 f"memberOf: cn={second},ou=groups,{BASE}\n")
        _, d = self.start(ldif=ldif, LDAP_NESTED_GROUP_DEPTH="10")
        for user in ("ordab", "ordba"):
            with self.subTest(user=user), d.connect() as c:
                r = c.ascii_login(user, user + "pw")
                self.assertEqual((r.status_name, r.server_msg), ("PASS", "l3\n"), r)


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(perl_ldap(), "no Net::LDAP or IO::Socket::SSL for Perl")
class LdapPerl(LdapTests, DaemonTestCase):
    CONFIG = None

    def module(self, url, extra):
        return MODULE.substitute(module="external", url=url, base=BASE, reader=READER, extra=extra,
                                 exec=f'"{PERL}" "perl" "{LDAP_PERL}"')


# mavis_tacplus_ldap.pl; one child, so a change of its state shows in its next request
MODULE_OLD = string.Template("""
	mavis module ldap = external {
		setenv LDAP_SERVER_TYPE = "tacacs_schema"
		setenv LDAP_HOSTS = "$url"
		setenv LDAP_BASE = "$base"
		setenv LDAP_USER = "$reader"
		setenv LDAP_PASSWD = "readerpw"
$extra		childs min = 1
		childs max = 1
		exec = "$perl" "perl" "$script"
	}
""")

POLICY_OLD = """
	user backend = mavis
	login backend = mavis
	pap backend = mavis
	ruleset { rule { script { permit } } }
"""


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(perl_ldap(), "no Net::LDAP or IO::Socket::SSL for Perl")
class LdapPerlTacacsSchema(DaemonTestCase):
    """mavis_tacplus_ldap.pl with LDAP_SERVER_TYPE = tacacs_schema; its default filter needs the tacacsAccount class."""

    CONFIG = None

    def start(self, stub=False, **env):
        """Start slapd and the daemon; stub: the stub back-end is the next MAVIS module."""
        slapd = Slapd(tempfile.mkdtemp(prefix="slapd-", dir=os.path.dirname(self.scratch_file("slapd", ""))))
        self.addCleanup(slapd.stop)
        slapd.start()
        extra = "".join(f'\t\tsetenv {name} = "{value}"\n' for name, value in env.items())
        module = MODULE_OLD.substitute(url=slapd.url, base=BASE, reader=READER, extra=extra, perl=PERL,
                                       script=LDAP_PERL_OLD)
        return self.start_daemon(module + (Stub.module(childs=(1, 1)) if stub else "") + POLICY_OLD)

    def test_expired_password(self):
        """The password of frank expired (shadowExpire); alice has no tacacsAccount class."""
        d = self.start()
        for user, password, status in (("erin", "erinpw", "PASS"), ("erin", "wrong", "FAIL"),
                                       ("frank", "frankpw", "FAIL"), ("alice", "alicepw", "FAIL")):
            with self.subTest(user=user, password=password), d.connect() as c:
                self.assertEqual(c.pap(user, password).status_name, status)

    def test_authorize_only(self):
        """FLAG_AUTHORIZE_ONLY: the back-end does not check the password, the next module does, in every request."""
        d = self.start(stub=True, FLAG_AUTHORIZE_ONLY="1")
        Stub(d).set(users={"erin": {"password": "stubpw"}, "frank": {"password": "stubpw"}})
        for user, password, status in (("erin", "wrong", "FAIL"), ("erin", "erinpw", "FAIL"),
                                       ("erin", "stubpw", "PASS"), ("frank", "stubpw", "PASS")):
            with self.subTest(user=user, password=password), d.connect() as c:
                self.assertEqual(c.pap(user, password).status_name, status)


if __name__ == "__main__":
    unittest.main()
