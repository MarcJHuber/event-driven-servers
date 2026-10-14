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


"""Log destinations: what gets written, and where."""

import unittest

from tactest import DaemonTestCase

USERS = """
	device inbound {
		# 1: accept the password in an ASCII START, as IOS-XR sends it
		address = 127.0.0.5
		key = tactest
		bug compatibility = 1
	}
	user alice {
		password login = clear alicepw
		password pap = clear alicepw
		password chap = clear alicepw
		enable 15 = clear enablepw
	}
	user carol {
		password login = clear carolpw
		password pap = login
	}
	ruleset {
		rule { script { permit } }
	}
"""


def line(user, what):
    """The end of a line in the default authentication log format."""
    return "\t%s\ttty0\t127.0.0.1\t%s\n" % (user, what)


class FailedLogins(DaemonTestCase):
    """#242: since the MFA work, failed logins were missing from the authentication log."""

    CONFIG = USERS

    def check(self, login, user, what):
        r = login()
        self.assertEqual(r.status_name, "FAIL", r)
        self.wait_log("authentication", line(user, what))

    def test_issue242_failed_ascii_login_is_logged(self):
        self.check(lambda: self.connect().ascii_login("alice", "wrong"), "alice", "shell login failed")

    def test_issue242_failed_pap_login_is_logged(self):
        self.check(lambda: self.connect().pap("alice", "wrong"), "alice", "pap login failed")

    def test_issue242_failed_inbound_ascii_login_is_logged(self):
        """An ASCII START that carries the password (IOS-XR) goes to do_login(), where 3253342 moved report_auth().

        Pins the current behaviour: before 3253342 this was logged already.
        """
        def login():
            s = self.connect(source="127.0.0.5").session()
            return s.start(user="alice", data="wrong")
        self.check(login, "alice", "ascii login failed")

    def test_issue242_failed_pap_with_the_login_password_is_logged(self):
        """"password pap = login" goes on to do_login() too (logged as "ascii login").

        Pins the current behaviour, like the test above.
        """
        self.check(lambda: self.connect().pap("carol", "wrong"), "carol", "ascii login failed")

    def test_issue242_failed_chap_login_is_logged(self):
        self.check(lambda: self.connect().chap("alice", "wrong"), "alice", "chap login failed")

    def test_issue242_failed_enable_is_logged(self):
        self.check(lambda: self.connect().enable("wrong", user="alice"), "alice", "enable 15 failed")

    def test_successful_logins_are_logged(self):
        self.assertTrue(self.connect().ascii_login("alice", "alicepw").ok)
        self.wait_log("authentication", line("alice", "shell login succeeded"))
        self.assertTrue(self.connect().pap("carol", "carolpw").ok)
        self.wait_log("authentication", line("carol", "ascii login succeeded"))


class AccountingFilter(DaemonTestCase):
    """#243: a filter on one log destination dropped the record for all destinations after it.

    The filtered destination sits between two others, so one of them comes
    after it whichever way the list is walked.
    """

    CONFIG = """
	log filtered {
		destination = "$tmp/filtered.log"
		filter { if (user == bob) deny }
	}
	log everything {
		destination = "$tmp/everything.log"
	}
	accounting log = filtered
	accounting log = everything
	user alice { password login = clear pw }
	user bob { password login = clear pw }
	ruleset {
		rule { script { permit } }
	}
"""

    def test_issue243_filter_applies_to_its_destination_only(self):
        for user in ("bob", "alice"):
            r = self.connect().acct(user, ["service=shell", "cmd=show version <cr>", "task_id=1"])
            self.assertTrue(r.ok, r)
        record = "\t%s\ttty0\t"
        for log in ("accounting", "everything"):
            text = self.wait_log(log, record % "alice")
            self.assertIn(record % "bob", text, log)
        text = self.wait_log("filtered", record % "alice")
        self.assertNotIn(record % "bob", text)


class Prefix(DaemonTestCase):
    """#184: the parser skipped the token after 'prefix = "..."'."""

    CONFIG = None

    def test_issue184_empty_prefix_then_more_settings(self):
        d = self.start_daemon("""
	log plain {
		destination = "$tmp/plain.log"
		prefix = ""
		authentication format = "PLAIN $${user} $${authen-action}"
	}
	authentication log = plain
	user alice { password pap = clear pw }
	ruleset {
		rule { script { permit } }
	}
""")
        with d.connect() as c:
            self.assertTrue(c.pap("alice", "pw").ok)
        self.assertEqual(d.wait_log("plain", "PLAIN alice"), "PLAIN alice login\n")


if __name__ == "__main__":
    unittest.main()
