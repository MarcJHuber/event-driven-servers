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


"""RADIUS: Access-Request with PAP over UDP and RADIUS/TCP."""

import hashlib
import os
import struct
import unittest

from tactest import SOURCE, DaemonTestCase, config, features, radius, tacacs

DICTIONARY = os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")
SECRET = "radsecret"
NAS = "127.0.0.6"
ACCOUNTING_REQUEST = 4
ACCT_STATUS_TYPE = 40
CLOSE_TIMEOUT = 10.0    # waiting for the daemon to close a connection: generous, it does come

POLICY = """
	include = "%s"
	device radius-nas {
		address = 127.0.0.6
		key = tactest
		radius.key = %s
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile admin {
		script {
			if (aaa.protocol == radius) {
				set radius[Reply-Message] = "welcome"
				permit
			}
			if (service == shell) permit
		}
	}
	ruleset {
		rule { script { profile = admin permit } }
	}
""" % (DICTIONARY, SECRET)


class Pap(DaemonTestCase):
    CONFIG = POLICY
    UDP = True

    def radius(self, secret, **kw):
        kw.setdefault("source", NAS)
        return super().radius(secret, **kw)

    def test_access_accept(self):
        r = self.radius(SECRET).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(r.get(radius.REPLY_MESSAGE), [b"welcome"])

    def test_access_reject(self):
        r = self.radius(SECRET).access_request("alice", "wrong", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Reject", r)

    def test_message_authenticator_accepted(self):
        r = self.radius(SECRET).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)

    def test_wrong_secret_gets_no_accept(self):
        """The User-Password decodes to garbage: a reject or no answer, never an accept.

        The reply is read without the check of the Response Authenticator,
        which a reply under the daemon's secret could not pass anyway. The
        Message-Authenticator is computed with the daemon's secret, so that
        the request gets past it to the password check.
        """
        c = self.radius(SECRET, timeout=2.0)
        req = radius.Packet(radius.ACCESS_REQUEST)
        password = radius.encrypt_password("alicepw", "not-the-secret", req.authenticator)
        req.attributes = [(radius.USER_NAME, b"alice"), (radius.USER_PASSWORD, password)]
        c.send_raw(req.encode(SECRET, message_authenticator=True))
        try:
            r = radius.Packet.decode(c.recv_raw())
        except TimeoutError:
            return
        self.assertNotEqual(r.code_name, "Access-Accept", r)

    def test_password_that_is_not_utf8(self):
        """#247 was first blamed on a password that doesn't decode as UTF-8: it is just a wrong password."""
        for password in (b"\xff\xfe\xfd", b"caf\xe9", bytes(range(1, 40))):
            with self.subTest(password=password):
                r = self.radius(SECRET).access_request("alice", password, message_authenticator=True)
                self.assertEqual(r.code_name, "Access-Reject", r)

    def test_radius_over_tcp(self):
        """RADIUS/TCP (RFC 6613) on the TACACS+ port: the daemon recognizes the protocol."""
        r = self.radius(SECRET, tcp=True).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)

    def test_radius_over_tcp_length_below_the_header(self):
        """f02d3bc: a RADIUS/TCP length field below 20 made the data length negative, read as unsigned.

        The daemon allocated about 4 GB for the packet and waited for the
        rest of it. It must drop the connection instead.
        """
        for length in (0, 4, 19):
            with self.subTest(length=length):
                c = self.radius(SECRET, tcp=True, timeout=CLOSE_TIMEOUT)
                req = radius.Packet(radius.ACCESS_REQUEST, attributes=[(radius.USER_NAME, b"alice")])
                c.send_raw(req.encode(SECRET, message_authenticator=True, length=length))
                with self.assertRaises(ConnectionError):
                    c.recv_raw()


@unittest.skipUnless("openssl" in features(), "the Message-Authenticator needs a build with OpenSSL")
class MessageAuthenticator(DaemonTestCase):
    """Message-Authenticator (RFC 3579 3.2): checked in requests, always set in replies."""

    CONFIG = POLICY
    UDP = True

    def radius(self, secret, **kw):
        kw.setdefault("source", NAS)
        return super().radius(secret, **kw)

    def request(self):
        req = radius.Packet(radius.ACCESS_REQUEST)
        req.attributes = [(radius.USER_NAME, b"alice"),
                          (radius.USER_PASSWORD, radius.encrypt_password("alicepw", SECRET, req.authenticator))]
        return req

    def test_wrong_message_authenticator_gets_no_answer(self):
        """RFC 3579 3.2: a request with a wrong Message-Authenticator is silently discarded."""
        c = self.radius(SECRET, timeout=2.0)
        c.send_raw(self.request().encode(SECRET, message_authenticator=bytes(range(16))))
        with self.assertRaises(TimeoutError):
            c.recv_raw()
        # the same request with the right one is answered
        r = self.radius(SECRET).exchange(self.request(), message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept")

    def test_issue200_reply_has_a_message_authenticator(self):
        """#200: clients with "Require Message-Authenticator" need it in the reply (RFC 3579 3.2, BLAST)."""
        for password, code in (("alicepw", "Access-Accept"), ("wrong", "Access-Reject")):
            with self.subTest(reply=code):
                r = self.radius(SECRET).access_request("alice", password, message_authenticator=True)
                self.assertEqual(r.code_name, code, r)
                self.assertIs(r.message_authenticator, True, "Message-Authenticator missing or wrong")

    def test_radius_over_tcp_wrong_message_authenticator_closes(self):
        c = self.radius(SECRET, tcp=True, timeout=CLOSE_TIMEOUT)
        c.send_raw(self.request().encode(SECRET, message_authenticator=bytes(16)))
        with self.assertRaises(ConnectionError):
            c.recv_raw()

    def test_issue200_reply_over_tcp_has_a_message_authenticator(self):
        r = self.radius(SECRET, tcp=True).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertIs(r.message_authenticator, True)


@unittest.skipUnless("openssl" in features(), "the Message-Authenticator needs a build with OpenSSL")
class MessageAuthenticatorRequired(DaemonTestCase):
    """#281 (3): an Access-Request without Message-Authenticator is dropped, unless bug compatibility 32.

    BLAST mitigation as documented for bug compatibility bit 5 (32). The
    check in rad_check_failed() listed only reply codes (Access-Accept,
    -Reject, -Challenge), which the daemon never receives, so every
    request was answered. Over TLS/DTLS the attribute stays optional (see
    test_tls.RadiusOverTls).
    """

    CONFIG = """
	include = "%s"
	device strict {
		address = 127.0.0.6
		radius.key = %s
	}
	device lenient {
		address = 127.0.0.7
		radius.key = %s
		bug compatibility = 32
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	ruleset {
		rule { script { permit } }
	}
""" % (DICTIONARY, SECRET, SECRET)
    UDP = True

    def test_issue281_access_request_without_it_is_dropped(self):
        c = self.radius(SECRET, source="127.0.0.6", timeout=2.0)
        with self.assertRaises(TimeoutError, msg="answered an Access-Request without Message-Authenticator"):
            c.access_request("alice", "alicepw")

    def test_issue281_access_request_without_it_over_tcp_closes(self):
        c = self.radius(SECRET, tcp=True, source="127.0.0.6", timeout=CLOSE_TIMEOUT)
        with self.assertRaises(ConnectionError):
            c.access_request("alice", "alicepw")

    def test_issue281_access_request_with_it(self):
        for tcp in (False, True):
            with self.subTest(tcp=tcp):
                r = self.radius(SECRET, tcp=tcp, source="127.0.0.6").access_request("alice", "alicepw",
                                                                                    message_authenticator=True)
                self.assertEqual(r.code_name, "Access-Accept", r)

    def test_issue281_bug_compatibility_32_accepts_it_without(self):
        for tcp in (False, True):
            with self.subTest(tcp=tcp):
                r = self.radius(SECRET, tcp=tcp, source="127.0.0.7").access_request("alice", "alicepw")
                self.assertEqual(r.code_name, "Access-Accept", r)

    def test_issue281_accounting_request_needs_none(self):
        """RFC 2866 has no Message-Authenticator in accounting; not required there."""
        attrs = bytes([radius.USER_NAME, 7]) + b"alice" + bytes([ACCT_STATUS_TYPE, 6]) + struct.pack("!I", 1)
        head = struct.pack("!BBH", ACCOUNTING_REQUEST, 9, radius.HEADER_LEN + len(attrs))
        # RFC 2866 3: the Request Authenticator is MD5(packet with 16 zero bytes + secret)
        auth = hashlib.md5(head + bytes(16) + attrs + SECRET.encode()).digest()
        c = self.radius(SECRET, source="127.0.0.6")
        c.send_raw(head + auth + attrs)
        self.assertEqual(radius.Packet.decode(c.recv_raw()).code_name, "Accounting-Response")


class RealmOnUdpListener(DaemonTestCase):
    """#232: "realm =" on a UDP listener was ignored, every RADIUS request went to the default realm.

    struct scm_data_accept and scm_data_udp had their members in a different
    order (mavis/scm.h), so the worker read the realm name from the wrong
    place. The device and the user exist in realm "radius" only.
    """

    LISTEN = {"udp": "protocol = UDP realm = radius", "tcp": "realm = radius"}
    CONFIG = """
	include = "%s"
	realm radius {
		device radius-nas {
			address = 127.0.0.6
			radius.key = %s
		}
		user bob {
			password login = clear bobpw
			password pap = login
		}
		ruleset {
			rule { script { permit } }
		}
	}
""" % (DICTIONARY, SECRET)

    def test_issue232_realm_of_a_udp_listener(self):
        r = self.radius(SECRET, listener="udp", source=NAS).access_request("bob", "bobpw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)

    def test_issue232_realm_of_a_tcp_listener(self):
        r = self.radius(SECRET, listener="tcp", tcp=True, source=NAS).access_request("bob", "bobpw",
                                                                                     message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)


# no device for 127.0.0.2: the base configuration covers all of 127/8, NAS is 127.0.0.6
UNKNOWN_HOSTS = config.BASE.replace("address = 127.0.0.0/8", "address = 127.0.0.1/32")


class UnknownHost(DaemonTestCase):
    """#247: a request from an address without a device crashed the worker (builds without OpenSSL)."""

    CONFIG = None

    def start(self):
        self.assertNotEqual(UNKNOWN_HOSTS, config.BASE, "config.BASE no longer has address = 127.0.0.0/8")
        return self.start_daemon(POLICY, template=UNKNOWN_HOSTS, udp=True)

    def test_issue247_radius_from_unknown_host(self):
        d = self.start()
        with d.radius(SECRET, source="127.0.0.2", timeout=2.0) as c:
            with self.assertRaises(TimeoutError):
                c.access_request("alice", "alicepw")

    def test_issue247_tacacs_from_unknown_host(self):
        d = self.start()
        with d.connect(source="127.0.0.2", timeout=2.0) as c:
            c.send(tacacs.Packet.authen_start(user="alice"))
            self.assertTrue(c.closed(), "the daemon answered a device it doesn't know")


if __name__ == "__main__":
    unittest.main()
