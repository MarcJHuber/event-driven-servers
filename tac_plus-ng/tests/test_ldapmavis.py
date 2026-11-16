"""LDAP backends against a real OpenLDAP slapd: ldapmavis-mt (external-mt) and mavis_tacplus-ng_ldap.pl (external).

Every test starts a slapd of its own, as a normal process on a free
loopback port, with a database that slapadd fills before the start. The
anonymous user can only bind, so the backend must bind as LDAP_USER to
search. alice is a member of netadmins, and netadmins is a member of
staff; dave is a direct member of staff; bob is in no group.
"""

import glob
import os
import select
import shutil
import socket
import string
import subprocess
import time
import unittest

from tactest import DaemonTestCase, prefix
from tactest.daemon import free_port

SLAPD = shutil.which("slapd") or "/usr/sbin/slapd"
SCHEMA_DIRS = ("/etc/ldap/schema", "/etc/openldap/schema")
# Debian and Ubuntu build the back-ends as modules in /usr/lib/ldap, Alpine in /usr/lib/openldap
MODULE_DIRS = ("/usr/lib/ldap", "/usr/lib/openldap", "/usr/lib64/openldap", "/usr/libexec/openldap")
LDAPMAVIS = os.path.join(prefix(), "sbin", "ldapmavis-mt")
LDAP_PERL = os.path.join(prefix(), "lib", "mavis", "mavis_tacplus-ng_ldap.pl")
PERL = shutil.which("perl") or "/usr/bin/perl"
START_TIMEOUT = 10.0

BASE = "dc=example,dc=com"
READER = "cn=reader," + BASE
STAFF = "cn=staff,ou=groups," + BASE

SLAPD_CONF = string.Template("""\
include $core
include $cosine
include $inetorgperson
$modules
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
""").substitute(base=BASE, reader=READER, staff=STAFF)


def slapd_arg(value):
    """A slapd.conf argument: double quotes keep blanks, a backslash escapes a quote or a backslash."""
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


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

    def __init__(self, directory):
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
        paths = {n: os.path.join(schema, n + ".schema") for n in ("core", "cosine", "inetorgperson")}
        paths.update(pidfile=os.path.join(directory, "slapd.pid"), argsfile=os.path.join(directory, "slapd.args"),
                     db=os.path.join(directory, "db"))
        with open(self.conf, "w") as f:
            f.write(SLAPD_CONF.substitute({k: slapd_arg(v) for k, v in paths.items()}, modules=modules(), base=BASE))
        os.mkdir(os.path.join(directory, "db"))
        ldif = os.path.join(directory, "data.ldif")
        with open(ldif, "w") as f:
            f.write(LDIF)
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
		exec = $exec
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
    """The tests for both back-ends; a subclass sets module(url) to its "mavis module" block."""

    def start(self):
        slapd = Slapd(os.path.dirname(self.scratch_file("slapd.conf", "")))
        self.addCleanup(slapd.stop)
        slapd.start()
        return slapd, self.start_daemon(POLICY.substitute(module=self.module(slapd.url), staff=STAFF))

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

    def module(self, url):
        return MODULE.substitute(module="external-mt", url=url, base=BASE, reader=READER,
                                 exec=f'"{LDAPMAVIS}" "ldapmavis-mt"')


@unittest.skipUnless(os.access(SLAPD, os.X_OK), "no OpenLDAP slapd")
@unittest.skipUnless(perl_ldap(), "no Net::LDAP or IO::Socket::SSL for Perl")
class LdapPerl(LdapTests, DaemonTestCase):
    CONFIG = None

    def module(self, url):
        return MODULE.substitute(module="external", url=url, base=BASE, reader=READER,
                                 exec=f'"{PERL}" "perl" "{LDAP_PERL}"')


if __name__ == "__main__":
    unittest.main()
