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

import re
import unittest

from tactest import DaemonError, DaemonTestCase, config, features, tacacs
from tactest.daemon import parse_only

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

    def test_unobfuscated_packet_is_refused(self):
        """A device with a key: a packet with TAC_PLUS_UNENCRYPTED_FLAG gets ERROR, then the close."""
        c = self.connect()
        s = c.session()
        s.send(tacacs.Packet.authen_start(user="alice", data="alicepw", authen_type=tacacs.AUTHEN_TYPE_PAP,
                                          version=tacacs.VERSION_ONE, flags=tacacs.FLAG_UNENCRYPTED))
        r = tacacs.AuthenReply(s.recv())
        self.assertEqual((r.status_name, r.server_msg), ("ERROR", "Peers MUST use Obfuscation."), r)
        self.assertTrue(c.closed(), "the connection stays open")


class MaxAttempts(DaemonTestCase):
    """"password max-attempts" at global and at realm level, with declarations after it.

    The realm value applies to the devices of that realm, so the realm has its own device.
    """

    CONFIG = None

    def assert_two_attempts(self, connect, user, password):
        r = connect().ascii_login(user, ["bad1", "bad2"])
        self.assertEqual(r.statuses, ["GETPASS", "GETPASS", "FAIL"], r)
        self.assertEqual(r.prompts, [BANNER + "Password: ", "Password incorrect.\nPassword: "], r)
        self.assertEqual(r.server_msg, "Password incorrect.\n", r)
        r = connect().ascii_login(user, ["bad1", password])
        self.assertEqual(r.statuses, ["GETPASS", "GETPASS", "PASS"], r)

    def test_global_max_attempts(self):
        d = self.start_daemon("""
	password max-attempts = 2
	user alice { password login = clear alicepw }
	ruleset { rule { script { permit } } }
""")
        self.assert_two_attempts(lambda: self.connect(daemon=d), "alice", "alicepw")

    def test_realm_max_attempts(self):
        d = self.start_daemon("""
	realm lab {
		password max-attempts = 2
		device labdev { address = 127.0.0.5 key = tactest }
		user carol { password login = clear carolpw }
		ruleset { rule { script { permit } } }
	}
	device realmdev {
		address = 127.0.0.5
		key = tactest
		target-realm = lab
	}
""")
        self.assert_two_attempts(lambda: self.connect(daemon=d, source="127.0.0.5"), "carol", "carolpw")


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


class MaxRounds(DaemonTestCase):
    """"max-rounds = 2": an ASCII login with GETUSER needs three rounds."""

    CONFIG = "\tmax-rounds = 2\n" + USERS

    def test_reply_at_the_limit(self):
        """The third packet gets ERROR "Too many rounds.", then the daemon closes the connection."""
        c = self.connect()
        s = c.session()
        self.assertEqual(s.start(user="").status_name, "GETUSER")
        self.assertEqual(s.cont("alice").status_name, "GETPASS")
        r = s.cont("alicepw")
        self.assertEqual((r.status_name, r.server_msg), ("ERROR", "Too many rounds."), r)
        self.assertTrue(c.closed(), "the connection stays open")


# "alicepw", "enablepw" and "naskey", encrypted with the type6-key "demo"
ALICEPW_6 = r"g^^PIBaDAZOHeG^fIU^eY_RUPZ`^]X"
ENABLEPW_6 = r"JGRZhS_TGAab^`ZXC]XKadGG]ihdiNAAB"
NASKEY_6 = r"KIXTPG^HRJ]FIdaO\IN]fRbFKaTAAB"


def type6_alice(login="6 '%s'" % ALICEPW_6, enable="6 '%s'" % ENABLEPW_6):
    return """
	user alice {
		password login = %s
		password pap = clear alicepw
		enable 15 = %s
	}
""" % (login, enable)


TYPE6_NAS = """
	device nas6 {
		address = 127.0.0.6
		key = 6 '%s'
	}
""" % NASKEY_6

PERMIT = """
	ruleset {
		rule { script { permit } }
	}
"""


@unittest.skipUnless("openssl" in features(), "type 6 needs a build with OpenSSL")
class Type6(DaemonTestCase):
    """Type 6 passwords and keys, decrypted with the type6-key of the realm or of a parent realm.

    The type6-key comes last: the daemon decrypts after it has read the whole configuration.
    """

    LISTEN = {"lab": "realm = lab"}
    CONFIG = type6_alice() + TYPE6_NAS + PERMIT + """
	realm lab {
		user bob {
			password login = 6 '%s'
		}
	}
	type6-key = demo
""" % ALICEPW_6

    def test_type6_login(self):
        self.assertEqual(self.connect().ascii_login("alice", "alicepw").status_name, "PASS")

    def test_type6_login_with_the_encrypted_text_fails(self):
        self.assertEqual(self.connect().ascii_login("alice", ALICEPW_6).status_name, "FAIL")

    def test_type6_enable(self):
        self.assertEqual(self.connect().enable("enablepw", user="alice").status_name, "PASS")

    def test_type6_enable_with_the_encrypted_text_fails(self):
        self.assertEqual(self.connect().enable(ENABLEPW_6, user="alice").status_name, "FAIL")

    def test_type6_device_key(self):
        self.assertTrue(self.connect(source="127.0.0.6", key="naskey").pap("alice", "alicepw").ok)

    def test_type6_key_of_the_parent_realm(self):
        self.assertEqual(self.connect(listener="lab").ascii_login("bob", "alicepw").status_name, "PASS")


@unittest.skipUnless("openssl" in features(), "type 6 needs a build with OpenSSL")
class Type6SiblingParentRealm(DaemonTestCase):
    """A realm with a sibling as its parent gets the type6-key that the sibling inherits.

    Realms complete in name order, so sibling-a completes before its parent sibling-z.
    nest-c, a child of nest-z with parent nest-a, completes while nest-a waits for nest-z.
    """

    LISTEN = {"a": "realm = sibling-a", "c": "realm = nest-c"}
    CONFIG = PERMIT + """
	realm sibling-z {
	}
	realm sibling-a {
		parent = sibling-z
		user bob {
			password login = 6 '%s'
		}
	}
	realm nest-z {
	}
	realm nest-a {
		parent = nest-z
	}
	realm nest-z {
		realm nest-c {
			parent = nest-a
			user carol {
				password login = 6 '%s'
			}
		}
	}
	type6-key = demo
""" % (ALICEPW_6, ALICEPW_6)

    def test_type6_key_of_the_parent_of_the_parent_realm(self):
        self.assertEqual(self.connect(listener="a").ascii_login("bob", "alicepw").status_name, "PASS")

    def test_type6_key_of_a_parent_realm_that_completes_from_a_child_of_its_parent(self):
        self.assertEqual(self.connect(listener="c").ascii_login("carol", "alicepw").status_name, "PASS")


@unittest.skipUnless("openssl" in features(), "type 6 needs a build with OpenSSL")
class Type6Undecryptable(DaemonTestCase):
    """A type 6 value that the type6-key does not decrypt, or that has no type6-key, is a configuration error.

    The daemon used the encrypted text as the clear text password or key before.
    """

    CONFIG = None
    WRONG_KEY = "type 6 value cannot be decrypted with the type6-key"
    NO_KEY = "type 6 value without a type6-key"

    def assert_rejected(self, body, error, attempt):
        try:
            d = self.start_daemon(body)
        except DaemonError as e:
            self.assertIn("exited with code 78 ", str(e))
        else:
            self.fail("the daemon started; the encrypted text as the secret: %s"
                      % (attempt(d).status_name if attempt else "not tried"))
        code, out = parse_only(self.scratch_file("type6.cfg", config.render(body=body)))
        self.assertEqual(code, 78, out)
        # the line of the type 6 value, as the parser counts lines: it reports an unknown keyword there
        bogus = re.sub(r"(= 6 '[^']*')", r"\1 bogus", body, count=1)
        line = re.search(r"type6\.cfg:(\d+): .* but got 'bogus'",
                         parse_only(self.scratch_file("type6.cfg", config.render(body=bogus)))[1])
        self.assertIsNotNone(line)
        self.assertIn("type6.cfg:%s: %s" % (line.group(1), error), out)

    def login_as_clear_text(self, d):
        return self.connect(daemon=d).ascii_login("alice", ALICEPW_6)

    def enable_as_clear_text(self, d):
        return self.connect(daemon=d).enable(ENABLEPW_6, user="alice")

    def nas_key_as_clear_text(self, d):
        return self.connect(daemon=d, source="127.0.0.6", key=NASKEY_6).pap("alice", "alicepw")

    def test_type6_password_with_a_wrong_type6_key(self):
        self.assert_rejected(type6_alice(enable="clear enablepw") + PERMIT + "type6-key = wrong\n",
                             self.WRONG_KEY, self.login_as_clear_text)

    def test_type6_password_without_a_type6_key(self):
        self.assert_rejected(type6_alice(enable="clear enablepw") + PERMIT, self.NO_KEY, self.login_as_clear_text)

    def test_type6_enable_with_a_wrong_type6_key(self):
        self.assert_rejected(type6_alice(login="clear alicepw") + PERMIT + "type6-key = wrong\n",
                             self.WRONG_KEY, self.enable_as_clear_text)

    def test_type6_device_key_with_a_wrong_type6_key(self):
        self.assert_rejected(TYPE6_NAS + USERS + "type6-key = wrong\n", self.WRONG_KEY, self.nas_key_as_clear_text)

    def test_type6_device_key_without_a_type6_key(self):
        self.assert_rejected(TYPE6_NAS + USERS, self.NO_KEY, self.nas_key_as_clear_text)

    def test_type6_key_of_the_device_wins_over_the_realm(self):
        nas = TYPE6_NAS.replace("key = 6", "type6-key = wrong\n\t\tkey = 6")
        self.assert_rejected(nas + USERS + "type6-key = demo\n", self.WRONG_KEY, self.nas_key_as_clear_text)

    def test_type6_tls_psk_key_with_a_wrong_type6_key(self):
        # test_tls.Psk has a TLS-PSK client and the working type 6 PSK
        nas = TYPE6_NAS.replace("key = 6", "tls psk id = nas6\n\t\ttls psk key = 6")
        self.assert_rejected(nas + USERS + "type6-key = wrong\n", self.WRONG_KEY, None)


if __name__ == "__main__":
    unittest.main()
