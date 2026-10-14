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


"""Authentication: ASCII login, PAP, CHAP, enable; transport corner cases (MS-CHAP: test_issue263.py)."""

import unittest

from tactest import DaemonTestCase, tacacs

USERS = """
	device single {
		address = 127.0.0.3
		key = tactest
		single-connection = yes
	}
	user alice {
		password login = clear alicepw
		password pap = clear alicepw
		password chap = clear alicepw
		enable 15 = clear enablepw
	}
	ruleset {
		rule { script { permit } }
	}
"""

BANNER = "User Access Verification\n\n"


class AsciiLogin(DaemonTestCase):
    CONFIG = USERS

    def test_ascii_login_user_in_start(self):
        r = self.connect().ascii_login("alice", "alicepw")
        self.assertEqual(r.statuses, ["GETPASS", "PASS"], r)
        self.assertEqual(r.prompts, [BANNER + "Password: "])
        self.assertTrue(r.replies[0].noecho, "the password prompt must ask for no echo")
        self.wait_log("authentication", "shell login succeeded")

    def test_ascii_login_asks_for_the_user(self):
        r = self.connect().ascii_login("alice", "alicepw", user_in_start=False)
        self.assertEqual(r.statuses, ["GETUSER", "GETPASS", "PASS"], r)
        self.assertEqual(r.prompts, [BANNER + "Username: ", "Password: "])

    def test_ascii_login_wrong_password_fails(self):
        r = self.connect().ascii_login("alice", "wrong")
        self.assertEqual(r.status_name, "FAIL", r)
        self.assertEqual(r.server_msg, "Password incorrect.\n")

    def test_ascii_login_unknown_user_fails(self):
        r = self.connect().ascii_login("nobody", "alicepw")
        self.assertEqual(r.status_name, "FAIL", r)

    def test_ascii_login_abort(self):
        """CONTINUE with the abort flag ends the session without a REPLY."""
        c = self.connect()
        s = c.session()
        r = s.start(user="alice")
        self.assertEqual(r.status_name, "GETPASS", r)
        s.cont(abort=True)
        self.assertTrue(c.silent(1.0), "the daemon answered an abort")
        self.assertTrue(self.connect().ascii_login("alice", "alicepw").ok)

    def test_enable(self):
        r = self.connect().enable("enablepw", user="alice")
        self.assertEqual(r.statuses, ["GETPASS", "PASS"], r)

    def test_enable_wrong_password_fails(self):
        r = self.connect().enable("wrong", user="alice")
        self.assertEqual(r.status_name, "FAIL", r)


class PapChap(DaemonTestCase):
    CONFIG = USERS

    def test_pap(self):
        """Also #162: reading the request with read() instead of recv(flags) broke every TCP reply."""
        self.assertTrue(self.connect().pap("alice", "alicepw").ok)

    def test_pap_needs_minor_version_one(self):
        """RFC 8907 5.4.2.2: PAP comes with version 0xc1; 0xc0 gets no PAP handling."""
        r = self.connect().pap("alice", "alicepw", version=tacacs.VERSION_DEFAULT)
        self.assertNotEqual(r.status_name, "PASS", r)

    def test_chap(self):
        self.assertEqual(self.connect().chap("alice", "alicepw").status_name, "PASS")

    def test_chap_wrong_password_fails(self):
        self.assertEqual(self.connect().chap("alice", "wrong").status_name, "FAIL")


class Transport(DaemonTestCase):
    CONFIG = USERS

    def test_issue132_header_and_body_in_separate_segments(self):
        """#132: a NAS (F5) sends the header and the body in two TCP segments; the daemon stayed silent."""
        c = self.connect()
        s = c.session()
        s.seq_no = 1
        pkt = tacacs.Packet.authen_start(user="alice", data="alicepw", authen_type=tacacs.AUTHEN_TYPE_PAP,
                                         version=tacacs.VERSION_ONE, session_id=s.session_id)
        c.send_split(pkt, gap=0.3)
        r = tacacs.AuthenReply(s.recv())
        self.assertEqual(r.status_name, "PASS", r)

    def test_body_split_in_the_middle(self):
        c = self.connect()
        s = c.session()
        s.seq_no = 1
        pkt = tacacs.Packet.authen_start(user="alice", data="alicepw", authen_type=tacacs.AUTHEN_TYPE_PAP,
                                         version=tacacs.VERSION_ONE, session_id=s.session_id)
        c.send_split(pkt, gap=0.3, at=tacacs.HEADER_LEN + 5)
        self.assertEqual(tacacs.AuthenReply(s.recv()).status_name, "PASS")


class SingleConnection(DaemonTestCase):
    """Several sessions on one connection (RFC 8907 4.3), here from the single-connection device."""

    CONFIG = USERS

    def connect_single(self):
        return self.connect(source="127.0.0.3", single_connect=True)

    def test_server_agrees_to_single_connection(self):
        c = self.connect_single()
        r = c.pap("alice", "alicepw")
        self.assertTrue(r.ok, r)
        self.assertTrue(r.final.packet.flags & tacacs.FLAG_SINGLE_CONNECT, "reply without the single-connect flag")

    def test_sessions_in_a_row(self):
        c = self.connect_single()
        self.assertTrue(c.pap("alice", "alicepw").ok)
        self.assertEqual(c.ascii_login("alice", "wrong").status_name, "FAIL")
        self.assertTrue(c.ascii_login("alice", "alicepw").ok)
        self.assertTrue(c.enable("enablepw", user="alice").ok)

    def test_two_concurrent_sessions(self):
        """An ASCII login waits for its password while a PAP login on the same socket completes."""
        c = self.connect_single()
        a, b = c.session(), c.session()
        first = a.start(user="alice")
        self.assertEqual(first.status_name, "GETPASS", first)
        # b's START goes out while a is still open; a's next REPLY is read after b's
        b.send(tacacs.Packet.authen_start(user="alice", data="alicepw", authen_type=tacacs.AUTHEN_TYPE_PAP,
                                          version=tacacs.VERSION_ONE))
        a.send(tacacs.Packet.authen_continue("alicepw"))
        rb = tacacs.AuthenReply(b.recv())
        ra = tacacs.AuthenReply(a.recv())
        self.assertEqual((ra.status_name, rb.status_name), ("PASS", "PASS"))
        self.assertEqual(ra.packet.session_id, a.session_id)
        self.assertEqual(rb.packet.session_id, b.session_id)

    def test_two_concurrent_sessions_different_users(self):
        """Two dialogs interleaved step by step; each gets its own verdict."""
        c = self.connect_single()
        a, b = c.session(), c.session()
        self.assertEqual(a.start(user="").status_name, "GETUSER")
        self.assertEqual(b.start(user="").status_name, "GETUSER")
        self.assertEqual(b.cont("alice").status_name, "GETPASS")
        self.assertEqual(a.cont("alice").status_name, "GETPASS")
        self.assertEqual(a.cont("wrong").status_name, "FAIL")
        self.assertEqual(b.cont("alicepw").status_name, "PASS")


if __name__ == "__main__":
    unittest.main()
