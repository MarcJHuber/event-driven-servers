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


"""Requests that used to crash a worker.

A crash is invisible to the client (spawnd starts a new worker), so these
tests rely on the crash detectors that run after every test
(tactest/detect.py); the assertions here only check the answer.
"""

import struct
import unittest

from tactest import DaemonTestCase, tacacs

POLICY = """
	user alice {
		alias = bob
		password login = clear alicepw
		password pap = login
	}
	user crypted {
		# crypt(3) of "secret" with the salt "aF"
		password login = crypt aFs8iA.REo/iA
	}
	user badhash {
		password login = crypt $$9$$not-a-valid-setting
	}
	ruleset {
		rule { script { permit } }
	}
"""


class MalformedPackets(DaemonTestCase):
    CONFIG = POLICY

    def bogus_start(self, **encode):
        """An authentication START whose length fields don't add up to the body length."""
        c = self.connect()
        pkt = tacacs.Packet.authen_start(user="alice", data="alicepw", authen_type=tacacs.AUTHEN_TYPE_PAP,
                                         version=tacacs.VERSION_ONE)
        pkt.body = pkt.body[:4] + bytes([200]) + pkt.body[5:]      # user_len 200
        c.send_raw(pkt.encode(c.key, **encode))
        return c

    def test_issue140_bogus_authentication_packet(self):
        """#140: "Illegal packet" -> send_authen_reply() read session->authen_data, still NULL -> SIGSEGV."""
        c = self.bogus_start()
        r = tacacs.AuthenReply(c.recv())
        self.assertEqual(r.status_name, "ERROR", r)
        self.assertIn("Illegal packet", r.server_msg)

    def test_issue140_unknown_minor_version(self):
        c = self.connect()
        pkt = tacacs.Packet.authen_start(user="alice", data="alicepw", authen_type=tacacs.AUTHEN_TYPE_PAP)
        c.send_raw(pkt.encode(c.key, version=0xC5))
        r = tacacs.AuthenReply(c.recv())
        self.assertEqual(r.status_name, "ERROR", r)

    def test_issue140_wrong_key(self):
        """With a wrong key the body decodes to garbage: the same error path."""
        c = self.connect(key="not-the-key")
        with self.assertRaises(tacacs.ProtocolError):
            c.pap("alice", "alicepw")

    def test_unknown_packet_type(self):
        """Only that the worker survives: the daemon doesn't answer at all.

        RFC 8907 3.6 asks for an answer, the request header with seq_no + 1
        and length 0; this test doesn't insist on it.
        """
        c = self.connect(timeout=1.0)
        pkt = tacacs.Packet(9, b"\x00" * 8)
        c.send_raw(pkt.encode(c.key))
        try:
            c.recv()
        except (tacacs.Closed, TimeoutError):
            pass

    def test_bogus_authorization_and_accounting(self):
        for build, reply in ((tacacs.Packet.author_request, tacacs.AuthorReply),
                             (tacacs.Packet.acct_request, tacacs.AcctReply)):
            with self.subTest(packet=reply.__name__):
                c = self.connect()
                pkt = build("alice", ["service=shell", "cmd="])
                pkt.body = pkt.body[:-1]            # the last argument is a byte short
                c.send_raw(pkt.encode(c.key))
                self.assertEqual(reply(c.recv()).status_name, "ERROR")

    def test_length_field_beyond_the_data(self):
        """The header announces more than is sent, then the client closes."""
        c = self.connect()
        pkt = tacacs.Packet.authen_start(user="alice")
        c.send_raw(pkt.encode(c.key, length=len(pkt.body) + 100))
        c.close()

    def test_huge_length_field(self):
        """Only that the worker survives a header announcing a 2 GB body."""
        c = self.connect(timeout=1.0)
        c.send_raw(struct.pack("!BBBBII", tacacs.VERSION_DEFAULT, tacacs.TYPE_AUTHEN, 1, 0, 1, 0x7FFFFFFF))
        try:
            c.recv()
        except (tacacs.Closed, TimeoutError):
            pass


class Users(DaemonTestCase):
    CONFIG = POLICY

    def test_issue128_login_by_alias(self):
        """#128: logging in with the alias of a local user crashed the worker."""
        self.assertTrue(self.connect().ascii_login("bob", "alicepw").ok)
        self.assertTrue(self.connect().pap("bob", "alicepw").ok)
        self.assertEqual(self.connect().ascii_login("bob", "wrong").status_name, "FAIL")

    def test_crypt_password(self):
        """The crypt(3) path is in use: a valid hash works (control for #173)."""
        self.assertTrue(self.connect().ascii_login("crypted", "secret").ok)
        self.assertEqual(self.connect().ascii_login("crypted", "wrong").status_name, "FAIL")

    def test_invalid_crypt_setting_fails(self):
        """#173: crypt(3) returns NULL for a setting it doesn't know, and strcmp(NULL) crashed.

        glibc's libxcrypt and musl return a failure token instead of NULL,
        so on Linux this can't fail the way #173 did; it pins the FAIL.
        """
        self.assertEqual(self.connect().ascii_login("badhash", "secret").status_name, "FAIL")


class Realm(DaemonTestCase):
    """#149: any configuration with a realm crashed (complete_realm(), TLS builds)."""

    CONFIG = POLICY + """
	realm lab {
		user carol {
			password login = clear carolpw
			password pap = login
		}
		ruleset {
			rule { script { permit } }
		}
	}
	device realmdev {
		address = 127.0.0.5
		key = tactest
		target-realm = lab
	}
"""

    def test_issue149_login_in_a_realm(self):
        self.assertTrue(self.connect(source="127.0.0.5").pap("carol", "carolpw").ok)
        self.assertEqual(self.connect(source="127.0.0.5").pap("carol", "wrong").status_name, "FAIL")

    def test_issue149_default_realm_still_works(self):
        self.assertTrue(self.connect().pap("alice", "alicepw").ok)
        self.assertEqual(self.connect().pap("carol", "carolpw").status_name, "FAIL")


if __name__ == "__main__":
    unittest.main()
