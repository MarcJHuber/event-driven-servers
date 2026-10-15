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


"""Authorization and accounting."""

import unittest

from tactest import DaemonTestCase

POLICY = """
	device edgecore {
		address = 127.0.0.4
		key = tactest
		bug compatibility = 256
	}
	profile shell {
		script {
			if (service == shell) {
				if (cmd == "") {
					set priv-lvl = 15
					permit
				}
				if (cmd =~ /^show /) permit
				deny
			}
		}
	}
	user alice {
		password login = clear alicepw
	}
	ruleset {
		rule { script { profile = shell permit } }
	}
"""


class Authorization(DaemonTestCase):
    CONFIG = POLICY

    def test_shell_start(self):
        r = self.connect().author("alice", ["service=shell", "cmd="])
        self.assertEqual(r.status_name, "PASS_ADD", r)
        self.assertEqual(r.args, ["priv-lvl=15"])
        self.wait_log("authorization", "permit")

    def test_command_permitted(self):
        r = self.connect().author("alice", ["service=shell", "cmd=show", "cmd-arg=version", "cmd-arg=<cr>"])
        self.assertEqual(r.status_name, "PASS_ADD", r)

    def test_command_denied(self):
        r = self.connect().author("alice", ["service=shell", "cmd=configure", "cmd-arg=terminal", "cmd-arg=<cr>"])
        self.assertEqual(r.status_name, "FAIL", r)
        self.wait_log("authorization", "deny")

    def test_unknown_user_denied(self):
        r = self.connect().author("nobody", ["service=shell", "cmd="])
        self.assertEqual(r.status_name, "FAIL", r)

    def test_issue21_empty_argument(self):
        """#21: a zero-length AV pair (Cumulus) made every command fail with "Illegal arg from NAS"."""
        r = self.connect().author("alice", ["service=shell", "cmd=show", "cmd-arg=version", ""])
        self.assertEqual(r.status_name, "PASS_ADD", r)

    def test_argument_without_separator_is_refused(self):
        """Without bug compatibility 256, an AV pair without "=" or "*" fails the request (see #225)."""
        r = self.connect().author("alice", ["service=shell", "cmd=show", "cmd-arg=version", "<cr>"])
        self.assertEqual(r.status_name, "FAIL", r)

    def test_issue225_malformed_argument_ignored_with_bug_compatibility_256(self):
        """#225: Edgecore sends a bare "<cr>"; bit 256 drops it and (eb88f27) keeps the other pairs.

        The shell start matters: its profile sets priv-lvl, so the daemon
        merges the NAS pairs with its own, which crashed while the filter
        kept the dropped pairs instead of the others.
        """
        r = self.connect(source="127.0.0.4").author("alice", ["service=shell", "cmd=", "<cr>"])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]), r)
        r = self.connect(source="127.0.0.4").author("alice", ["service=shell", "cmd=show", "cmd-arg=version", "<cr>"])
        self.assertEqual(r.status_name, "PASS_ADD", r)
        r = self.connect(source="127.0.0.4").author("alice", ["service=shell", "cmd=configure", "<cr>"])
        self.assertEqual(r.status_name, "FAIL", r)


class Accounting(DaemonTestCase):
    CONFIG = POLICY

    def test_start_and_stop(self):
        from tactest.tacacs import ACCT_FLAG_START, ACCT_FLAG_STOP
        c = self.connect()
        r = c.acct("alice", ["task_id=42", "service=shell", "cmd=show version <cr>"], flags=ACCT_FLAG_START)
        self.assertEqual(r.status_name, "SUCCESS", r)
        r = self.connect().acct("alice", ["task_id=42", "service=shell", "elapsed_time=3"], flags=ACCT_FLAG_STOP)
        self.assertEqual(r.status_name, "SUCCESS", r)
        log = self.wait_log("accounting", "\tstop\t")
        self.assertIn("\tstart\tshell\tshow version <cr>", log)


if __name__ == "__main__":
    unittest.main()
