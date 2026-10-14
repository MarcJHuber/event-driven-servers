# Copyright (C) 2026 TaranacLabs
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL ITS AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


"""MAVIS: the external module with the stub backend (tactest/mavis_stub.py)."""

import base64
import os
import struct
import subprocess
import sys
import time
import unittest

from tactest import LINUX, DaemonTestCase, Stub, config, detect, features, prefix
from tactest.daemon import alive as daemon_alive

BACKEND = """
	user backend = mavis
	login backend = mavis
	pap backend = mavis
"""

PERMIT = """
	ruleset {
		rule { script { permit } }
	}
"""


class Scenario(DaemonTestCase):
    """The stub changes its answers between requests, the daemon keeps running."""

    CONFIG = Stub.module(childs=(1, 1)) + BACKEND + PERMIT

    def setUp(self):
        super().setUp()
        self.stub = Stub(self.daemon)
        self.stub.set(users={"alice": {"password": "first"}})

    def test_scenario_changes_without_restart(self):
        """The state file is read for every request; "mavis cache timeout = 0" keeps the daemon from caching."""
        before = self.stub.count()
        self.assertEqual(self.connect().pap("alice", "first").status_name, "PASS")
        self.stub.set(users={"alice": {"password": "second"}})
        self.assertEqual(self.connect().pap("alice", "first").status_name, "FAIL")
        self.assertEqual(self.connect().pap("alice", "second").status_name, "PASS")
        auth = [e for e in self.stub.requests()[before:] if (e["type"], e["user"]) == ("AUTH", "alice")]
        self.assertEqual([e["result"] for e in auth], ["ACK", "NAK", "ACK"])
        self.assertEqual(len({e["pid"] for e in auth}), 1, "one MAVIS child expected: %s" % auth)

    def test_forced_results(self):
        """ERROR without a fallback user is a FAIL for the client too (the log tells them apart)."""
        for result, status in (("ACK", "PASS"), ("NAK", "FAIL"), ("NOTFOUND", "FAIL"), ("ERROR", "FAIL")):
            with self.subTest(result=result):
                self.stub.set(users={"alice": {"password": "first"}}, result={"alice:AUTH": result})
                self.assertEqual(self.connect().pap("alice", "wrong").status_name, status)

    def test_failure_with_a_multiline_message(self):
        """A FAIL with an LDAP error text from the backend must be answered at once.

        The client of #58 waited for a timeout. A line break in the text was
        the first suspect; it is fine (mavis.py sends it as CR). The cause
        was a NUL byte, see test_issue266.py.
        """
        self.stub.set(users={"alice": {"password": "first"}},
                      message="80090308: LdapErr: DSID-0C09044E\ncomment: AcceptSecurityContext error")
        for login in (self.connect().ascii_login, self.connect().pap):
            with self.subTest(login=login.__name__):
                self.assertEqual(login("alice", "wrong").status_name, "FAIL")


class Fallback(DaemonTestCase):
    """#98: after an ERROR from the backend a fallback-only user logs in with the local password.

    #98 itself was ldapmavis-mt not passing the backend error on (ee6eeb7);
    these tests pin the daemon's side of it. The realm remembers the failure for "authentication fallback period"
    (60 s), so every test has a daemon of its own.
    """

    CONFIG = None
    POLICY = Stub.module(childs=(1, 1)) + BACKEND + """
	authentication fallback = permit
	user rescue {
		fallback-only
		password login = clear rescuepw
		password pap = clear rescuepw
	}
""" + PERMIT

    def daemon_and_stub(self, **state):
        d = self.start_daemon(self.POLICY)
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw"}}, **state)
        return d, stub

    def test_issue98_backend_error_lets_the_fallback_user_in(self):
        d, stub = self.daemon_and_stub(result={"*": "ERROR"})
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "pw").status_name, "FAIL")
        self.assertEqual(stub.requests()[-1]["result"], "ERROR")
        with d.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS")
            self.assertEqual(c.ascii_login("rescue", "rescuepw").status_name, "PASS")
            self.assertEqual(c.pap("rescue", "wrong").status_name, "FAIL")

    def test_issue98_no_fallback_while_the_backend_works(self):
        d, stub = self.daemon_and_stub()
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")


class Cache(DaemonTestCase):
    """#69: authorization after authentication takes the user from the MAVIS cache."""

    CONFIG = None
    POLICY = Stub.module(childs=(1, 1)) + BACKEND + """
	profile admin {
		script { if (service == shell) { set priv-lvl = 15 permit } }
	}
	ruleset {
		rule { script { profile = admin permit } }
	}
"""

    def login_then_authorize(self, template):
        d = self.start_daemon(self.POLICY, template=template)
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw"}})
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
            before = stub.count()
            r = c.author("alice", ["service=shell", "cmd="])
        self.assertEqual(r.status_name, "PASS_ADD", r)
        return stub.requests()[before:]

    def test_issue69_authorization_uses_the_cache_by_default(self):
        """#69: the default cache period (120 s) was lost, every authorization asked the backend again."""
        template = config.BASE.replace("\tmavis cache timeout = 0\n", "")
        self.assertNotEqual(template, config.BASE)
        self.assertEqual(self.login_then_authorize(template), [])

    def test_authorization_asks_the_backend_without_cache(self):
        """The control: with "mavis cache timeout = 0" (the harness default) authorization sends INFO."""
        self.assertEqual([e["type"] for e in self.login_then_authorize(config.BASE)], ["INFO"])


def ssh_ed25519_key():
    """An OpenSSH public key line ("ssh-ed25519 <base64> comment"), the key itself made up."""
    def string(b):
        return struct.pack("!I", len(b)) + b
    blob = string(b"ssh-ed25519") + string(bytes(range(32)))
    return "ssh-ed25519 %s alice@example" % base64.b64encode(blob).decode()


GROUPS = ["group-with-a-rather-long-name-%03d" % i for i in range(200)]

# the "script out" of #189: append a group to whatever the backend returned
APPEND_GROUP = r"""
		script out {
			eval $$TACMEMBER =~ /^(.*)$$/
			set $$TACMEMBER = "$$1,\"no-login-profile\""
		}"""

GROUP_POLICY = BACKEND + "".join("\tgroup %s { }\n" % g for g in GROUPS) + """
	group no-login-profile { }
	profile admin {
		script { if (service == shell) { set priv-lvl = 15 permit } }
	}
	ruleset {
		rule last-group {
			script { if (member == %s && member == no-login-profile) { profile = admin permit } }
		}
	}
""" % GROUPS[-1]


@unittest.skipUnless("pcre2" in features(), "the script uses a PCRE")
class ManyGroups(DaemonTestCase):
    CONFIG = Stub.module(childs=(1, 1), script=APPEND_GROUP) + GROUP_POLICY

    def test_issue189_many_groups_through_script_out(self):
        """#189: "script out" copied TACMEMBER into a 4 kB buffer; with many groups only the appended one was left."""
        Stub(self.daemon).set(users={"alice": {"password": "pw", "member": GROUPS}})
        self.assertGreater(len(",".join('"%s"' % g for g in GROUPS)), 4096)
        self.assertEqual(self.connect().pap("alice", "pw").status_name, "PASS")
        r = self.connect().author("alice", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]))


@unittest.skipUnless("openssl" in features(), "SSH keys need a build with OpenSSL")
class SshKeys(DaemonTestCase):
    """#194: SSH keys in OpenSSH format ("type base64 comment") from the backend.

    The fix (beba55f, after dc7a4a8 was reverted) is that backends send
    each key in double quotes, as mavis_tacplus-ng_ldap.pl,
    mavis_tacplus_ldap.py and ldapmavis-mt do; unquoted, the blanks
    break the profile parser and the whole request fails.
    """

    CONFIG = Stub.module(childs=(1, 1)) + BACKEND + PERMIT

    def test_issue194_openssh_key_from_the_backend(self):
        stub = Stub(self.daemon)
        key = ssh_ed25519_key()
        for keys in (['"%s"' % key], ['"%s"' % key, '"%s"' % key.replace("alice@", "laptop@")]):
            with self.subTest(keys=len(keys)):
                stub.set(users={"bob": {"password": "pw", "sshkey": ",".join(keys)}})
                self.assertEqual(self.connect().pap("bob", "pw").status_name, "PASS")


class PasswordChange(DaemonTestCase):
    """#30: a user who must change the password and cancels is asked again next time.

    The password was cached after the first login, so the second one was
    answered from the cache without asking the backend, and without the
    change. Hence a cache period here.
    """

    CONFIG = None

    def test_issue30_password_change_asked_again_after_abort(self):
        template = config.BASE.replace("mavis cache timeout = 0", "mavis cache timeout = 60")
        self.assertNotEqual(template, config.BASE)
        d = self.start_daemon(Stub.module(childs=(1, 1)) + BACKEND + PERMIT, template=template)
        stub = Stub(d)
        stub.set(users={"alice": {"password": "old", "mustchange": True}})
        with d.connect() as c:
            s = c.session()
            r = s.start(user="alice")
            self.assertEqual(r.status_name, "GETPASS", r)
            r = s.cont("old")
            self.assertEqual(r.status_name, "GETDATA", r)
            s.cont(abort=True)
            self.assertTrue(c.silent(1.0))
        with d.connect() as c:
            r = c.ascii_login("alice", "old", data=["new", "new"])
        self.assertEqual(r.statuses, ["GETPASS", "GETDATA", "GETDATA", "PASS"], r)
        self.assertEqual([e["type"] for e in stub.requests()], ["AUTH", "AUTH", "CHPW"])


def cpu_seconds(pid):
    """utime + stime of a process (Linux)."""
    with open("/proc/%d/stat" % pid) as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


class Children(DaemonTestCase):
    """MAVIS children that die or misbehave; one child, so the stub's request counter is the child's."""

    CONFIG = None
    POLICY = Stub.module(childs=(1, 1)) + BACKEND + PERMIT

    def daemon_and_stub(self, check=True, **state):
        d = self.start_daemon(self.POLICY, check=check)
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw"}}, **state)
        return d, stub

    def forget_children(self, d):
        """The test killed MAVIS children on purpose: take the process set anew, keep the rest of the checks."""
        d.baseline = detect.Baseline(d, since=d.baseline)

    def test_child_exits_on_the_second_request(self):
        """The request a dying child took is sent to a new child."""
        d, stub = self.daemon_and_stub(exit=2)
        for _ in range(3):
            with d.connect() as c:
                self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
        self.forget_children(d)
        children = [(e["n"], e["result"]) for e in stub.requests()]
        self.assertEqual(children, [(1, "ACK"), (2, "exit"), (1, "ACK"), (2, "exit"), (1, "ACK")])
        self.assertEqual(len({e["pid"] for e in stub.requests()}), 3)

    @unittest.skipUnless(LINUX, "CPU time from /proc")
    def test_issue197_no_busy_loop_after_a_child_quit(self):
        """#197: after a child of the external module quit, the worker kept polling its closed pipe at 100% CPU.

        The child quits after it answered its second request (a backend
        without a request loop quits after the first; the daemon handles a
        child that dies before its second request otherwise). It quits
        once the client has the answer: the answer of a child that exits
        right after writing it is occasionally lost, which is not what
        this test is about.
        """
        d, stub = self.daemon_and_stub(quit=2)
        (worker,) = d.workers()
        for _ in range(2):
            with d.connect() as c:
                self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
        stub.release(2)
        child = stub.requests()[-1]["pid"]
        deadline = time.monotonic() + 5
        while daemon_alive(child) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(daemon_alive(child), "the child didn't quit")
        self.forget_children(d)
        before = cpu_seconds(worker)
        time.sleep(2)
        self.assertLess(cpu_seconds(worker) - before, 0.5)

    def test_issue228_demo_backend_answers_once(self):
        """#228: mavis_tacplus_demo.py wrote a second answer after is_tacplus()/valid() had answered."""
        demo = os.path.join(prefix(), "lib", "mavis", "mavis_tacplus_demo.py")
        env = dict(os.environ, PYTHONPATH=os.path.dirname(demo))
        for request in ("0 TACPLUS\n4 demo\n49 AUTH\n=\n",        # no password: valid() answers
                        "0 FTP\n4 demo\n8 demo\n49 AUTH\n=\n",   # not TACACS+: is_tacplus() answers
                        "0 TACPLUS\n4 demo\n8 demo\n49 AUTH\n=\n"):
            with self.subTest(request=request):
                out = subprocess.run([sys.executable, demo], input=request.encode(), stdout=subprocess.PIPE,
                                     timeout=30, env=env).stdout.decode()
                self.assertEqual(len([line for line in out.splitlines() if line.startswith("=")]), 1, out)

    def test_issue145_cache_directory_not_writable(self):
        """#145: tacinfo_cache and tacauth_limit dereferenced NULL when they couldn't write to their directory."""
        for module in ("tacinfo_cache", "tacauth_limit"):
            with self.subTest(module=module):
                body = "\tmavis module = %s { directory = /proc/tactest-not-writable }\n" % module + self.POLICY
                d = self.start_daemon(body, name=module)
                Stub(d).set(users={"alice": {"password": "pw"}})
                with d.connect() as c:
                    self.assertEqual(c.pap("alice", "pw").status_name, "PASS")


if __name__ == "__main__":
    unittest.main()
