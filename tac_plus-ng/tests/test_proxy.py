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


"""PROXY protocol: the device address from a load balancer's header (haproxy.org proxy-protocol.txt).

tac_plus-ng reads version 2 (the binary header) only. With "haproxy = yes"
on a spawnd listener every connection must start with it; with "haproxy
auto-detect = yes" in a realm the header is optional. The devices here sit
on addresses no test connection really comes from (10.1.2.0/24,
2001:db8::/64), with keys of their own, so a reply proves the daemon took
the address from the header.
"""

import time
import unittest

from tactest import LINUX, DaemonTestCase, cpu_seconds, tacacs

POLICY = """
	device proxied {
		address = 10.1.2.0/24
		key = proxykey
	}
	device proxied6 {
		address = 2001:db8::/64
		key = proxykey6
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile shell {
		script {
			if (service == shell) {
				if (device.name == proxied) set tactest-device = proxied
				if (device.name == proxied6) set tactest-device = proxied6
				if (device.name == localhost) set tactest-device = localhost
				set tactest-address = "$${device.address}"
				permit
			}
		}
	}
	ruleset {
		rule { script { profile = shell permit } }
	}
"""

CLOSE_TIMEOUT = 10.0    # waiting for the daemon to close a connection: generous, it does come

# what an AWS network load balancer adds after the addresses (#88): a CRC32C and padding
AWS_TLVS = (tacacs.proxy_tlv(tacacs.PP2_TYPE_CRC32C, bytes.fromhex("a6b09ed3"))
            + tacacs.proxy_tlv(tacacs.PP2_TYPE_NOOP, bytes(62)))


class ProxyTestCase(DaemonTestCase):
    CONFIG = POLICY

    def proxied(self, header, key="proxykey", listener="proxy", **kw):
        return self.connect(listener=listener, key=key, proxy=header, **kw)

    def device(self, conn):
        r = conn.author("alice", ["service=shell", "cmd="])
        self.assertTrue(r.ok, r)
        return dict(a.split("=", 1) for a in r.args if a.startswith("tactest-"))


class HaproxyListener(ProxyTestCase):
    LISTEN = {"proxy": "haproxy = yes"}

    def test_proxy_v2_ipv4(self):
        c = self.proxied(tacacs.proxy_v2("10.1.2.3", "10.0.0.1", 40000, 49))
        self.assertTrue(c.pap("alice", "alicepw").ok)
        self.assertEqual(self.device(c), {"tactest-device": "proxied", "tactest-address": "10.1.2.3"})

    def test_proxy_v2_ipv6(self):
        c = self.proxied(tacacs.proxy_v2("2001:db8::5", "2001:db8::1", 40000, 49), key="proxykey6")
        self.assertTrue(c.pap("alice", "alicepw").ok)
        self.assertEqual(self.device(c), {"tactest-device": "proxied6", "tactest-address": "2001:db8::5"})

    def test_issue88_proxy_v2_with_tlvs(self):
        """#88: an AWS NLB pads the header with TLVs; a length other than exactly 12 was refused."""
        c = self.proxied(tacacs.proxy_v2("10.1.2.3", "10.0.0.1", 40000, 49, tlvs=AWS_TLVS))
        self.assertTrue(c.pap("alice", "alicepw").ok)
        self.assertEqual(self.device(c)["tactest-device"], "proxied")

    def test_issue88_proxy_v2_ipv6_with_tlvs(self):
        c = self.proxied(tacacs.proxy_v2("2001:db8::5", "2001:db8::1", 40000, 49, tlvs=AWS_TLVS),
                         key="proxykey6")
        self.assertTrue(c.pap("alice", "alicepw").ok)

    def test_proxy_v2_local_is_the_peer_itself(self):
        """A LOCAL header (health checks) carries no addresses: the connection's own address counts."""
        c = self.proxied(tacacs.proxy_v2(command=tacacs.PROXY_LOCAL), key="tactest")
        self.assertEqual(self.device(c)["tactest-device"], "localhost")

    def test_key_of_the_proxy_does_not_work_for_a_proxied_device(self):
        c = self.proxied(tacacs.proxy_v2("10.1.2.3", "10.0.0.1", 40000, 49), key="tactest", timeout=2.0)
        with self.assertRaises((tacacs.Closed, tacacs.ProtocolError, TimeoutError)):
            c.pap("alice", "alicepw")

    def test_no_header_is_refused(self):
        c = self.connect(listener="proxy", timeout=CLOSE_TIMEOUT)
        with self.assertRaises((tacacs.Closed, ConnectionError)):
            c.pap("alice", "alicepw")

    def test_proxy_v1_is_refused(self):
        """Only version 2 is implemented; the text header of version 1 ends the connection."""
        c = self.proxied(tacacs.proxy_v1("10.1.2.3", "10.0.0.1"), timeout=CLOSE_TIMEOUT)
        with self.assertRaises((tacacs.Closed, ConnectionError)):
            c.pap("alice", "alicepw")

    @unittest.skipUnless(LINUX, "CPU time from /proc")
    def test_peer_closes_after_the_header(self):
        """PR 201-204 (see test_tls.PeerCloses), behind a PROXY header."""
        (worker,) = self.daemon.workers()
        c = self.proxied(tacacs.proxy_v2("10.1.2.3", "10.0.0.1", 40000, 49))
        c.send_raw(tacacs.Packet.authen_start(user="alice").encode("proxykey")[:20])
        c.close()
        time.sleep(0.2)
        before = cpu_seconds(worker)
        time.sleep(1.5)
        self.assertLess(cpu_seconds(worker) - before, 0.5, "the worker is busy after the peer closed")


class AutoDetect(ProxyTestCase):
    """"haproxy auto-detect = yes" in the realm: the header is optional on every listener."""

    CONFIG = "\thaproxy auto-detect = yes\n" + POLICY

    def test_with_header(self):
        c = self.proxied(tacacs.proxy_v2("10.1.2.3", "10.0.0.1", 40000, 49), listener=None)
        self.assertEqual(self.device(c)["tactest-device"], "proxied")

    def test_issue88_with_tlvs(self):
        c = self.proxied(tacacs.proxy_v2("10.1.2.3", "10.0.0.1", 40000, 49, tlvs=AWS_TLVS), listener=None)
        self.assertEqual(self.device(c)["tactest-device"], "proxied")

    def test_without_header(self):
        self.assertEqual(self.device(self.connect())["tactest-device"], "localhost")


if __name__ == "__main__":
    unittest.main()
