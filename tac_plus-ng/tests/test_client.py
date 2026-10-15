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


"""The clients themselves, against published test vectors; no daemon needed."""

import hashlib
import hmac
import unittest

from tactest import crypto, radius, tacacs

h = bytes.fromhex


class Crypto(unittest.TestCase):
    def test_md4(self):
        """RFC 1320 appendix A.5."""
        self.assertEqual(crypto.md4(b"").hex(), "31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertEqual(crypto.md4(b"abc").hex(), "a448017aaf21d8525fc10ae87aa6729d")
        self.assertEqual(crypto.md4(b"1234567890" * 8).hex(), "e33b4ddc9c38f2199c3e7b164fcc0536")

    def test_des(self):
        self.assertEqual(crypto.des_encrypt(h("133457799BBCDFF1"), h("0123456789ABCDEF")).hex(), "85e813540f0ab405")
        self.assertEqual(crypto.des_encrypt(h("0E329232EA6D0D73"), h("8787878787878787")).hex(), "0000000000000000")

    def test_mschapv2(self):
        """RFC 2759 section 9.2."""
        self.assertEqual(crypto.nt_hash("clientPass").hex(), "44ebba8d5312b8d611474411f56989ae")
        challenge = crypto.mschapv2_challenge_hash(h("21402324255E262A28295F2B3A337C7E"),
                                                   h("5B5D7C7D7B3F2F3E3C2C602132262628"), b"User")
        self.assertEqual(challenge.hex(), "d02e4386bce91226")
        self.assertEqual(crypto.challenge_response(challenge, crypto.nt_hash("clientPass")).hex(),
                         "82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df")


class Tacacs(unittest.TestCase):
    def test_obfuscation_is_its_own_inverse(self):
        body = bytes(range(100))
        once = tacacs.obfuscate(body, 0x12345678, b"key", 0xC1, 1)
        self.assertNotEqual(once, body)
        self.assertEqual(tacacs.obfuscate(once, 0x12345678, b"key", 0xC1, 1), body)

    def test_author_request_layout(self):
        """RFC 8907 6.1: fixed fields, the argument lengths, then user, port, rem_addr, arguments."""
        p = tacacs.Packet.author_request("u", ["a=1", "bb=2"], port="p", rem_addr="r")
        self.assertEqual(p.body, bytes([6, 1, 1, 1, 1, 1, 1, 2, 3, 4]) + b"upra=1bb=2")

    def test_author_reply_parse(self):
        body = bytes([1, 2, 0, 2, 0, 0, 3, 4]) + b"hia=1bb=2"
        r = tacacs.AuthorReply(tacacs.Packet(tacacs.TYPE_AUTHOR, body))
        self.assertEqual((r.status_name, r.server_msg, r.args), ("PASS_ADD", "hi", ["a=1", "bb=2"]))

    def test_malformed_reply_is_a_protocol_error(self):
        with self.assertRaises(tacacs.ProtocolError):
            tacacs.AuthenReply(tacacs.Packet(tacacs.TYPE_AUTHEN, bytes([1, 0, 0, 9, 0, 0])))

    def test_replies_sorted_by_session(self):
        """Connection.recv(session_id) keeps packets of other sessions for later."""
        conn = tacacs.Connection.__new__(tacacs.Connection)
        conn.pending = []
        wire = [tacacs.Packet(tacacs.TYPE_AUTHEN, b"", 2, 1), tacacs.Packet(tacacs.TYPE_AUTHEN, b"", 2, 2)]
        conn._read = lambda: wire.pop(0)
        self.assertEqual(conn.recv(2).session_id, 2)
        self.assertEqual(conn.recv(1).session_id, 1)

    def test_proxy_v1(self):
        """The example of proxy-protocol.txt section 2.1."""
        self.assertEqual(tacacs.proxy_v1("192.168.0.1", "192.168.0.11", 56324, 443),
                         b"PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n")

    def test_proxy_v2_as_an_aws_load_balancer_sends_it(self):
        """The header from the packet capture in #88: IPv4, a CRC32C TLV and 62 bytes of NOOP padding."""
        tlvs = (tacacs.proxy_tlv(tacacs.PP2_TYPE_CRC32C, h("a6b09ed3"))
                + tacacs.proxy_tlv(tacacs.PP2_TYPE_NOOP, bytes(62)))
        captured = h("0d0a0d0a000d0a515549540a" "21110054" "0a0a0014" "0a40d038" "c6890031"
                     "030004a6b09ed3" "04003e") + bytes(62)
        self.assertEqual(tacacs.proxy_v2("10.10.0.20", "10.64.208.56", 50825, 49, tlvs=tlvs), captured)

    def test_proxy_v2_local(self):
        self.assertEqual(tacacs.proxy_v2(command=tacacs.PROXY_LOCAL), tacacs.PROXY_V2_SIGNATURE + h("20000000"))


class Radius(unittest.TestCase):
    def test_user_password(self):
        """RFC 2865 section 7.1."""
        self.assertEqual(radius.encrypt_password("arctangent", "xyzzy5461", h("0f403f9473978057bd83d5cb98f4227a")),
                         h("0dbe708d93d413ce3196e43f782a0aee"))
        self.assertEqual(len(radius.encrypt_password(b"", "s", bytes(16))), 16)
        self.assertEqual(len(radius.encrypt_password(b"x" * 17, "s", bytes(16))), 32)

    def test_roundtrip(self):
        p = radius.Packet(radius.ACCESS_REQUEST, 7, bytes(16), [(radius.USER_NAME, "u")])
        q = radius.Packet.decode(p.encode())
        self.assertEqual((q.code, q.identifier, q.attributes), (1, 7, [(1, b"u")]))

    def test_message_authenticator(self):
        p = radius.Packet(radius.ACCESS_REQUEST, 1, bytes(16), [(radius.USER_NAME, "u")])
        data = p.encode("s", message_authenticator=True)
        q = radius.Packet.decode(data)
        mac = q.get(radius.MESSAGE_AUTHENTICATOR)[0]
        zeroed = data[:-16] + bytes(16)
        self.assertEqual(mac, hmac.new(b"s", zeroed, hashlib.md5).digest())

    def test_reply_message_authenticator(self):
        """RFC 3579 3.2: the HMAC of a reply covers it with the Request Authenticator in place."""
        request_auth = bytes(range(16))
        attrs = bytes([radius.REPLY_MESSAGE, 4]) + b"hi" + bytes([radius.MESSAGE_AUTHENTICATOR, 18]) + bytes(16)
        head = bytes([2, 7, 0, 20 + len(attrs)])
        mac = hmac.new(b"s", head + request_auth + attrs, hashlib.md5).digest()
        reply = head + bytes(16) + attrs[:-16] + mac   # the Response Authenticator doesn't matter here
        self.assertIs(radius.reply_message_authenticator(reply, request_auth, b"s"), True)
        self.assertIs(radius.reply_message_authenticator(reply, request_auth, b"other"), False)
        self.assertIsNone(radius.reply_message_authenticator(head + bytes(16) + attrs[:4], request_auth, b"s"))

    def test_wrong_message_authenticator_on_request(self):
        p = radius.Packet(radius.ACCESS_REQUEST, 1, bytes(16), [(radius.USER_NAME, "u")])
        q = radius.Packet.decode(p.encode("s", message_authenticator=bytes(range(16))))
        self.assertEqual(q.get(radius.MESSAGE_AUTHENTICATOR), [bytes(range(16))])


if __name__ == "__main__":
    unittest.main()
