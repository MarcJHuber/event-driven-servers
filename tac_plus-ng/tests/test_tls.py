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


"""TACACS+ over TLS (RFC 9887), TLS 1.3 PSK and RADIUS over TLS.

The certificates come from a CA made for the test class (tactest.tls.CA,
the openssl command); nothing is kept in the tree. Skipped without the
openssl command or in a build without OpenSSL.
"""

import os
import socket
import ssl
import time
import unittest

from tactest import LINUX, SOURCE, DaemonTestCase, cpu_seconds, features, radius, tacacs, tls

TLS_REALM = """
	tls cert-file = "%(server_crt)s"
	tls key-file = "%(server_key)s"
	tls ca-file = "%(ca)s"
"""

DEVICES = """
	device certnas.tactest {
		welcome banner = "certnas\\n"
	}
	device ipnas {
		address = 127.0.0.9
		key = ipkey
		tls.peer.cert.validation = none
	}
"""


def policy(devices=("certnas.tactest", "ipnas", "localhost")):
    """alice; shell authorization answers which device and transport the daemon saw, as tactest-* AV pairs."""
    lines = "".join("\t\t\t\tif (device.name == %s) set tactest-device = %s\n" % (d, d.split(".")[0])
                    for d in devices)
    return """
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile shell {
		script {
			if (service == shell) {
%s				if (conn.transport == tls) set tactest-transport = tls
				if (conn.transport == tcp) set tactest-transport = tcp
				permit
			}
		}
	}
	ruleset {
		rule { script { profile = shell permit } }
	}
""" % lines


POLICY = DEVICES + policy()


def need_tls():
    if not tls.openssl_available():
        raise unittest.SkipTest("no openssl command to make certificates")
    if "openssl" not in features():
        raise unittest.SkipTest("tac_plus-ng built without OpenSSL")


class TlsTestCase(DaemonTestCase):
    """A daemon with a CA of its own; CONFIG is formatted with the paths of its certificates.

    CLIENTS maps a name to the subject of its client certificate, or to
    (subject, subjectAltName).
    """

    BODY = ""
    CLIENTS = {"certnas": "/CN=certnas.tactest", "nobody": "/CN=nobody.tactest"}

    @classmethod
    def setUpClass(cls):
        need_tls()
        cls.ca = tls.CA(cls.__name__ + "-ca")
        cls.certs = {}
        for name, subject in cls.CLIENTS.items():
            subject, san = (subject, None) if isinstance(subject, str) else subject
            cls.certs[name] = cls.ca.issue(name, subject, san=san)
        paths = dict(ca=cls.ca.cert, server_crt=cls.ca.server[0], server_key=cls.ca.server[1])
        cls.CONFIG = cls.BODY % paths
        try:
            super().setUpClass()
        except Exception:
            cls.ca.remove()
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            super().tearDownClass()
        finally:
            if not cls._failed:
                cls.ca.remove()

    def context(self, client=None, **kw):
        return self.ca.context(self.certs[client] if client else None, **kw)

    def connect_tls(self, client="certnas", listener="tls", **kw):
        kw.setdefault("server_hostname", "localhost")
        kw.setdefault("timeout", 10.0)
        return self.connect(listener=listener, tls=self.context(client), **kw)

    def assertRefused(self, connect, login=lambda c: c.pap("alice", "alicepw")):
        """The handshake or the first request fails; how depends on when the daemon gives up.

        A TLS 1.3 server checks the client certificate after the client's
        handshake already finished, so the refusal may show up only when
        the first request is sent or its reply read.
        """
        with self.assertRaises((tacacs.Closed, ssl.SSLError, ConnectionError)):
            login(connect())

    def device_and_transport(self, conn):
        r = conn.author("alice", ["service=shell", "cmd="])
        self.assertTrue(r.ok, r)
        return dict(a.split("=", 1) for a in r.args if a.startswith("tactest-"))


class TacacsOverTls(TlsTestCase):
    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + POLICY

    def test_pap_over_tls(self):
        c = self.connect_tls()
        self.assertEqual(c.sock.version(), "TLSv1.3")
        self.assertTrue(c.pap("alice", "alicepw").ok)
        self.assertEqual(c.pap("alice", "wrong").status_name, "FAIL")

    def test_ascii_login_over_tls(self):
        self.assertEqual(self.connect_tls().ascii_login("alice", "alicepw").statuses, ["GETPASS", "PASS"])

    def test_device_by_certificate_name(self):
        """The common name of the client certificate selects the device, not the address."""
        self.assertEqual(self.device_and_transport(self.connect_tls()),
                         {"tactest-device": "certnas", "tactest-transport": "tls"})

    def test_device_by_address_without_client_certificate(self):
        """Only where the device of the address doesn't ask for one (tls.peer.cert.validation = none)."""
        self.assertEqual(self.device_and_transport(self.connect_tls(client=None, source="127.0.0.9")),
                         {"tactest-device": "ipnas", "tactest-transport": "tls"})

    def test_no_client_certificate_is_refused_by_default(self):
        self.assertRefused(lambda: self.connect_tls(client=None))

    def test_unknown_certificate_name_falls_back_to_the_address(self):
        self.assertEqual(self.device_and_transport(self.connect_tls(client="nobody", source="127.0.0.9")),
                         {"tactest-device": "ipnas", "tactest-transport": "tls"})

    def test_untrusted_client_certificate_is_refused(self):
        other = tls.CA("other-ca")
        self.addCleanup(other.remove)
        ctx = self.ca.context(other.issue("certnas", "/CN=certnas.tactest"))
        self.assertRefused(lambda: self.connect(listener="tls", tls=ctx, server_hostname="localhost", timeout=10.0))

    def test_tls12_is_refused(self):
        """RFC 9887 requires TLS 1.3; without bug compatibility 128 a TLS 1.2 session gets no answer."""
        c = self.connect(listener="tls", tls=self.context("certnas", minimum=ssl.TLSVersion.TLSv1_2,
                                                          maximum=ssl.TLSVersion.TLSv1_2),
                         server_hostname="localhost", timeout=10.0)
        self.assertEqual(c.sock.version(), "TLSv1.2")
        self.assertRefused(lambda: c)

    def test_obfuscated_packet_over_tls_is_refused(self):
        """RFC 9887: no obfuscation over TLS; a packet without TAC_PLUS_UNENCRYPTED_FLAG is refused."""
        c = self.connect_tls()
        pkt = tacacs.Packet.authen_start(user="alice", data="alicepw", authen_type=tacacs.AUTHEN_TYPE_PAP,
                                         version=tacacs.VERSION_ONE)
        c.send_raw(pkt.encode("tactest"))
        try:
            reply = c.recv()
        except tacacs.Closed:
            return
        self.assertNotEqual(tacacs.AuthenReply(reply).status_name, "PASS")

    def test_plain_tacacs_on_a_tls_listener_is_refused(self):
        c = self.connect(listener="tls", timeout=2.0)
        with self.assertRaises((tacacs.Closed, TimeoutError)):
            c.pap("alice", "alicepw")

    def test_plain_listener_still_plain(self):
        self.assertEqual(self.device_and_transport(self.connect()),
                         {"tactest-device": "localhost", "tactest-transport": "tcp"})


class PeerCertSan(TlsTestCase):
    """The subjectAltNames of a client certificate select the device; a DNS name in there crashed the worker.

    accept_control_tls() keeps the DNS names of the certificate in an
    array of pointers, but allocated it with one byte per name: the first
    DNS name looked at wrote 8 bytes into a 2-byte block. On musl (Alpine)
    the worker died with SIGSEGV when that memory was freed, on glibc the
    heap was quietly damaged; AddressSanitizer reports it at once. Found
    with Cisco IOS-XR and a certificate from an EST server: DNS name
    first, then the IP address of the device. An IP address SAN that
    comes first selects the device before any DNS name is looked at, so
    the order matters.
    """

    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + """
	device xr {
		address = 127.0.0.65
		key = xrkey
	}
	device dnsnas.tactest {
	}
""" + policy(("xr", "dnsnas.tactest", "localhost"))
    CLIENTS = {
        # the shape from the field: CN first, then serialNumber; DNS name, then the address
        "dns_then_ip": ("/CN=xr.tactest.invalid/serialNumber=e3d752c5",
                        "DNS:xr.tactest.invalid, IP:127.0.0.65"),
        "dns_names": ("/CN=other.tactest.invalid", "DNS:a.tactest.invalid, DNS:b.tactest.invalid, "
                      "DNS:c.tactest.invalid, DNS:d.tactest.invalid, DNS:dnsnas.tactest"),
        "ip_then_dns": ("/CN=xr.tactest.invalid", "IP:127.0.0.65, DNS:xr.tactest.invalid"),
        "ip_twice": ("/serialNumber=e3d752c5/CN=xr.tactest.invalid", "IP:127.0.0.65, IP:127.0.0.65"),
    }

    def device(self, client, source="127.0.0.65", single_connect=False):
        c = self.connect_tls(client, source=source, single_connect=single_connect)
        self.assertTrue(c.pap("alice", "alicepw").ok)
        return self.device_and_transport(c)["tactest-device"]

    def test_dns_san_before_ip_san(self):
        self.assertEqual(self.device("dns_then_ip"), "xr")

    def test_dns_san_before_ip_san_single_connection(self):
        self.assertEqual(self.device("dns_then_ip", single_connect=True), "xr")

    def test_dns_san_before_ip_san_from_another_address(self):
        """The address SAN selects the device, wherever the connection comes from."""
        self.assertEqual(self.device("dns_then_ip", source="127.0.0.9"), "xr")

    def test_several_dns_sans(self):
        self.assertEqual(self.device("dns_names", source="127.0.0.9"), "dnsnas")

    def test_ip_san_before_dns_san(self):
        self.assertEqual(self.device("ip_then_dns"), "xr")

    def test_ip_san_twice(self):
        self.assertEqual(self.device("ip_twice"), "xr")


class AutoDetect(TlsTestCase):
    """#236: "tls auto-detect = yes" in the realm made the daemon expect TLS only where spawnd said "tls = yes".

    With auto-detection, TLS and plain TACACS+ share a port: the first
    bytes of a connection decide. Before 238653a a TLS session on a plain
    listener was dropped after the handshake ("rejected [tac_read]"); with
    238653a alone plain sessions broke instead (fixed in 0a1e650).
    """

    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + "\ttls auto-detect = yes\n" + POLICY

    def test_issue236_tls_on_a_listener_without_tls(self):
        self.assertEqual(self.device_and_transport(self.connect_tls(listener=None)),
                         {"tactest-device": "certnas", "tactest-transport": "tls"})

    def test_issue236_plain_on_a_listener_without_tls(self):
        self.assertEqual(self.device_and_transport(self.connect()),
                         {"tactest-device": "localhost", "tactest-transport": "tcp"})

    def test_issue236_both_on_a_tls_listener(self):
        """With "tls = yes" on the listener, auto-detection is the fallback to plain TACACS+."""
        self.assertEqual(self.device_and_transport(self.connect_tls()),
                         {"tactest-device": "certnas", "tactest-transport": "tls"})
        self.assertEqual(self.device_and_transport(self.connect(listener="tls")),
                         {"tactest-device": "localhost", "tactest-transport": "tcp"})


class ListenerTlsAuto(TlsTestCase):
    """#236, second part: "tls = auto" on a spawnd listener (0a1e650) auto-detects on that listener only."""

    LISTEN = {"auto": "tls = auto"}
    BODY = TLS_REALM + POLICY

    def test_issue236_tls_auto_listener_takes_tls(self):
        self.assertEqual(self.device_and_transport(self.connect_tls(listener="auto")),
                         {"tactest-device": "certnas", "tactest-transport": "tls"})

    def test_issue236_tls_auto_listener_takes_plain(self):
        self.assertEqual(self.device_and_transport(self.connect(listener="auto")),
                         {"tactest-device": "localhost", "tactest-transport": "tcp"})

    def test_plain_listener_does_not_auto_detect(self):
        self.assertRefused(lambda: self.connect_tls(listener=None))


PSK_KEY = "0123456789abcdef0123456789abcdef"

PSK = """
	tls psk = yes
	tls cipher-suites = TLS_AES_128_GCM_SHA256
	device psknas {
		tls psk id = psknas
		tls psk key = hex %s
	}
	device pskclear {
		tls psk id = pskclear
		tls psk key = clear demoDemo
	}
""" % PSK_KEY


class Psk(TlsTestCase):
    """TLS 1.3 with a pre-shared key, through "openssl s_client -psk".

    The PSK identity is the device name here. An identity that names no
    device ("tls psk id = nas1@lab" on a device of another name) makes the
    worker use an uninitialized pointer (by_address in accept_control_tls(),
    #278), so these tests don't go there.
    """

    LISTEN = {"psk": "tls = yes tls psk = yes"}
    BODY = PSK + policy(("psknas", "pskclear", "localhost"))
    CLIENTS = {}

    def connect_psk(self, identity="psknas", key=PSK_KEY, timeout=10.0):
        sock = tls.PskSocket((self.daemon.address, self.daemon.ports["psk"]), identity, key, timeout=timeout)
        return self.connect(sock=sock, timeout=timeout)

    def test_pap_over_psk(self):
        c = self.connect_psk()
        self.assertTrue(c.pap("alice", "alicepw").ok)
        r = c.author("alice", ["service=shell", "cmd="])
        self.assertIn("tactest-transport=tls", r.args)

    def test_psk_identity_selects_the_device(self):
        r = self.connect_psk().author("alice", ["service=shell", "cmd="])
        self.assertTrue(r.ok, r)
        self.assertIn("tactest-device=psknas", r.args)

    def test_clear_text_psk(self):
        self.assertTrue(self.connect_psk("pskclear", b"demoDemo".hex()).pap("alice", "alicepw").ok)

    def test_wrong_psk_is_refused(self):
        self.assertRefused(lambda: self.connect_psk(key="00" * 16))

    def test_unknown_identity_is_refused(self):
        self.assertRefused(lambda: self.connect_psk(identity="nosuchnas"))



RADSEC = """
	include = "%s"
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile radius {
		script {
			if (aaa.protocol == radius) {
				if (device.name == certnas.tactest) set radius[Reply-Message] = "certnas"
				permit
			}
		}
	}
	ruleset {
		rule { script { profile = radius permit } }
	}
""" % os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")


class RadiusOverTls(TlsTestCase):
    """RADIUS over TLS (RFC 6614) on a TLS listener: the daemon tells it from TACACS+ by the first bytes."""

    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + DEVICES + RADSEC

    def radsec(self, client="certnas"):
        return self.radius("radsec", listener="tls", tls=self.context(client))

    def test_access_accept(self):
        r = self.radsec().access_request("alice", "alicepw")
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(r.get(radius.REPLY_MESSAGE), [b"certnas"], "device not selected by the certificate")
        self.assertTrue(r.message_authenticator, "no valid Message-Authenticator in the reply")

    def test_access_reject(self):
        self.assertEqual(self.radsec().access_request("alice", "wrong").code_name, "Access-Reject")

    def test_wrong_shared_secret_gets_no_accept(self):
        """Over TLS the shared secret is "radsec"; a request under another one is not accepted."""
        c = self.radius("not-radsec", listener="tls", tls=self.context("certnas"), timeout=2.0)
        req = radius.Packet(radius.ACCESS_REQUEST)
        password = radius.encrypt_password("alicepw", "not-radsec", req.authenticator)
        req.attributes = [(radius.USER_NAME, b"alice"), (radius.USER_PASSWORD, password)]
        c.send_raw(req.encode("not-radsec", message_authenticator=True))
        try:
            r = radius.Packet.decode(c.recv_raw())
        except (TimeoutError, ConnectionError, ssl.SSLError):
            return
        self.assertNotEqual(r.code_name, "Access-Accept", r)


@unittest.skipUnless(LINUX, "CPU time from /proc")
class PeerCloses(TlsTestCase):
    """PR 201, 203, 204: a connection the peer closed in the middle of a packet kept the worker busy.

    recv_inject() took the 0 of recv() at EOF for data, so the worker read
    the closed socket again and again (CPU, CLOSE_WAIT). Rewritten in
    9f1167f/866f730 instead of the PRs. For every transport: send a part
    of a packet, close, and the worker must stay idle; the socket check
    after the test sees whether it closed its end.
    """

    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + DEVICES.replace("key = ipkey", "key = ipkey\n\t\tradius.key = radsecret") + RADSEC

    def idle_after(self, close):
        (worker,) = self.daemon.workers()
        close()
        time.sleep(0.2)
        before = cpu_seconds(worker)
        time.sleep(1.5)
        self.assertLess(cpu_seconds(worker) - before, 0.5, "the worker is busy after the peer closed")

    def half(self, data):
        return data[:len(data) // 2]

    def test_peer_closes_plain_tacacs(self):
        c = self.connect()
        c.send_raw(self.half(tacacs.Packet.authen_start(user="alice").encode("tactest")))
        self.idle_after(c.close)

    def test_peer_closes_during_the_tls_handshake(self):
        s = socket.create_connection((self.daemon.address, self.daemon.ports["tls"]), timeout=5)
        self.addCleanup(s.close)
        # the beginning of a TLS record with a ClientHello
        s.sendall(bytes([0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03]))
        self.idle_after(s.close)

    def test_peer_closes_tacacs_over_tls(self):
        c = self.connect_tls()
        c.send_raw(self.half(tacacs.Packet.authen_start(user="alice").encode("")))
        self.idle_after(c.close)

    def test_peer_closes_radius_over_tls(self):
        c = self.radius("radsec", listener="tls", tls=self.context("certnas"))
        req = radius.Packet(radius.ACCESS_REQUEST, attributes=[(radius.USER_NAME, b"alice")])
        c.send_raw(self.half(req.encode("radsec", message_authenticator=True)))
        self.idle_after(c.close)

    def test_peer_closes_radius_over_tcp(self):
        c = self.radius("radsecret", tcp=True, source="127.0.0.9")
        req = radius.Packet(radius.ACCESS_REQUEST, attributes=[(radius.USER_NAME, b"alice")])
        c.send_raw(self.half(req.encode("radsecret", message_authenticator=True)))
        self.idle_after(c.close)
