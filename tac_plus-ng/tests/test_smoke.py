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

"""Smoke: the daemon starts under spawnd and answers PAP logins."""

import unittest

from tactest import DaemonTestCase, ProtocolError, ipv6_available

USERS = """
	user alice {
		password pap = clear alicepw
	}
	ruleset {
		rule { script { permit } }
	}
"""


class PapLogin(DaemonTestCase):
    CONFIG = USERS

    def test_pap_pass(self):
        r = self.connect().pap("alice", "alicepw")
        self.assertEqual(r.status_name, "PASS", r)
        self.wait_log("authentication", "pap login succeeded")

    def test_pap_wrong_password_fails(self):
        r = self.connect().pap("alice", "wrong")
        self.assertEqual(r.status_name, "FAIL", r)

    def test_pap_unknown_user_fails(self):
        r = self.connect().pap("nobody", "alicepw")
        self.assertEqual(r.status_name, "FAIL", r)

    def test_wrong_key_is_not_a_fail(self):
        """A key mismatch must not look like a verdict: the reply doesn't decode."""
        with self.assertRaises(ProtocolError):
            self.connect(key="not-the-key").pap("alice", "alicepw")

    def test_single_connection_flag_two_sessions_in_a_row(self):
        c = self.connect(single_connect=True)
        self.assertTrue(c.pap("alice", "alicepw").ok)
        self.assertEqual(c.pap("alice", "wrong").status_name, "FAIL")


@unittest.skipUnless(ipv6_available(), "no ::1 on this host")
class PapLoginIPv6(DaemonTestCase):
    CONFIG = USERS
    ADDRESS = "::1"

    def test_pap_pass_over_ipv6(self):
        r = self.connect().pap("alice", "alicepw")
        self.assertEqual(r.status_name, "PASS", r)


if __name__ == "__main__":
    unittest.main()
