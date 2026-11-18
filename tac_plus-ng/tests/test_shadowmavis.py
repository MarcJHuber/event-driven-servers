"""mavis_tacplus_shadow.pl: the back-end for an /etc/shadow-like file, with the external module.

The tests run the installed script with a crypt() that has no MD5 and
without Crypt::Passwd::XS, as on a C library that does not support MD5
hashes. The script then uses MKPASSWD for new hashes. The mkpasswd of
the tests makes SHA-512 hashes with a fixed salt.
"""

import os
import shutil
import subprocess
import time
import unittest

from tactest import DaemonTestCase, prefix

SCRIPT = os.path.join(prefix(), "lib", "mavis", "mavis_tacplus_shadow.pl")
PERL = shutil.which("perl") or "/usr/bin/perl"
SALT = "$6$tactest$"

# loaded with -M before the script compiles
NO_MD5 = r"""package NoMd5;
BEGIN {
	*CORE::GLOBAL::crypt = sub ($$) { $_[1] =~ /^\$1\$/ ? '*0' : CORE::crypt($_[0], $_[1]) };
	unshift @INC, sub { die "no Crypt::Passwd::XS\n" if $_[1] eq 'Crypt/Passwd/XS.pm'; return };
}
1;
"""

MKPASSWD = """#!%s
# mkpasswd --stdin
chomp(my $p = <STDIN>);
print crypt($p, q(%s)), "\\n";
""" % (PERL, SALT)

POLICY = """
	mavis module = external {
		setenv SHADOWFILE = "%(shadow)s"
		setenv CI = "true"
%(extra)s		exec = "%(perl)s" "perl" "-I%(lib)s" "-MNoMd5" "%(script)s"
	}
	user backend = mavis
	login backend = mavis chpass
	pap backend = mavis
	ruleset { rule { script { permit } } }
"""


def sha512(password, salt=SALT):
    return subprocess.run([PERL, "-e", "print crypt($ARGV[0], $ARGV[1])", password, salt], stdout=subprocess.PIPE,
                          check=True).stdout.decode()


@unittest.skipUnless(sha512("x").startswith(SALT), "the crypt() of the C library has no SHA-512")
class NoMd5Crypt(DaemonTestCase):
    CONFIG = None

    def setUp(self):
        super().setUp()
        self.lib = os.path.dirname(self.scratch_file("NoMd5.pm", NO_MD5))
        self.mkpasswd = self.scratch_file("mkpasswd", MKPASSWD)
        os.chmod(self.mkpasswd, 0o755)

    def run_script(self, **env):
        """Start the script without requests; returns its standard error."""
        env = dict({k: v for k, v in os.environ.items() if k != "MKPASSWD"}, **env)
        return subprocess.run([PERL, "-I" + self.lib, "-MNoMd5", SCRIPT], stdin=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, env=env, timeout=30, check=True).stderr.decode()

    def test_warning_without_mkpasswd(self):
        warning = "Please install the mkpasswd utility."
        self.assertIn(warning, self.run_script())
        self.assertNotIn(warning, self.run_script(MKPASSWD=self.mkpasswd))

    def test_password_change_uses_mkpasswd(self):
        today = int(time.time()) // 86400
        shadow = self.scratch_file("shadow", "alice:%s:%d:0:99999:7:::\n" % (sha512("oldpw", "$6$old$"), today))
        d = self.start_daemon(POLICY % dict(shadow=shadow, extra='\t\tsetenv MKPASSWD = "%s"\n' % self.mkpasswd,
                                            perl=PERL, lib=self.lib, script=SCRIPT))
        with d.connect() as c:
            r = c.ascii_login("alice", "", data=["oldpw", "newpw", "newpw"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "GETDATA", "PASS"], r)
        with open(shadow) as f:
            self.assertEqual(f.read().split(":")[1], sha512("newpw"))
        for password, status in (("newpw", "PASS"), ("oldpw", "FAIL")):
            with self.subTest(password=password), d.connect() as c:
                self.assertEqual(c.pap("alice", password).status_name, status)


if __name__ == "__main__":
    unittest.main()
