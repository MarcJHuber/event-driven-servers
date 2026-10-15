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

import os
import unittest

from tactest import SOURCE, DaemonTestCase, config, radius, tacacs

DICTIONARY = os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")
SECRET = "radsecret"
NAS = "127.0.0.6"

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
        r = self.radius(SECRET).access_request("alice", "alicepw")
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(r.get(radius.REPLY_MESSAGE), [b"welcome"])

    def test_access_reject(self):
        r = self.radius(SECRET).access_request("alice", "wrong")
        self.assertEqual(r.code_name, "Access-Reject", r)

    def test_message_authenticator_accepted(self):
        """Only that a valid Message-Authenticator is accepted; that a wrong one is rejected is not tested yet."""
        r = self.radius(SECRET).access_request("alice", "alicepw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)

    def test_wrong_secret_gets_no_accept(self):
        """The User-Password decodes to garbage: a reject or no answer, never an accept.

        The reply is read without the check of the Response Authenticator,
        which a reply under the daemon's secret could not pass anyway.
        """
        c = self.radius(SECRET, timeout=2.0)
        req = radius.Packet(radius.ACCESS_REQUEST)
        password = radius.encrypt_password("alicepw", "not-the-secret", req.authenticator)
        req.attributes = [(radius.USER_NAME, b"alice"), (radius.USER_PASSWORD, password)]
        c.send_raw(req.encode())
        try:
            r = radius.Packet.decode(c.recv_raw())
        except TimeoutError:
            return
        self.assertNotEqual(r.code_name, "Access-Accept", r)

    def test_password_that_is_not_utf8(self):
        """#247 was first blamed on a password that doesn't decode as UTF-8: it is just a wrong password."""
        for password in (b"\xff\xfe\xfd", b"caf\xe9", bytes(range(1, 40))):
            with self.subTest(password=password):
                r = self.radius(SECRET).access_request("alice", password)
                self.assertEqual(r.code_name, "Access-Reject", r)

    def test_radius_over_tcp(self):
        """RADIUS/TCP (RFC 6613) on the TACACS+ port: the daemon recognizes the protocol."""
        r = self.radius(SECRET, tcp=True).access_request("alice", "alicepw", message_authenticator=True)
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
