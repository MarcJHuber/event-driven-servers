"""tactester: the RADIUS client prints the attributes of the reply, and nothing else.

rad_attr_val_dump1() did not compare the length of an attribute with the
bytes left in the reply. An attribute that claims more bytes than the
packet has made it dump bytes after the packet, and the unsigned rest
length wrapped, so the walk went on through the uninitialized reply
buffer.
"""

import hashlib
import hmac
import os
import re
import socket
import struct
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from tactest import SOURCE, DaemonTestCase, radius, tactester
from tactest.daemon import sanitizer_env

DICTIONARY = os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")
SECRET = "radsecret"
NAS = "127.0.0.6"
ACCESS_ACCEPT = 2

POLICY = """
	include = "@DICTIONARY@"
	device radius-nas {
		address = @NAS@
		key = tactest
		radius.key = @SECRET@
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile admin {
		script {
			if (aaa.protocol == radius) {
				set radius[Reply-Message] = "first"
				set radius[Reply-Message] = "second"
				set radius[Login-TCP-Port] = 2323
				permit
			}
		}
	}
	ruleset {
		rule { script { profile = admin permit } }
	}
""".replace("@DICTIONARY@", DICTIONARY).replace("@NAS@", NAS).replace("@SECRET@", SECRET)

CLIENT = """
id = tactester {
	include = "@DICTIONARY@"
	server radius.udp {
		protocol = radius.udp
		destination address = @ADDRESS@
		destination port = @PORT@
		source address = @NAS@
		key = @SECRET@
		timeout = 5
		retry = 0
	}
}
"""


def run_tactester(test, tmp, address, port, *args):
    """tactester as RADIUS/UDP client of address:port: its output lines."""
    cfg = os.path.join(tmp, "tactester.cfg")
    text = CLIENT
    for key, value in (("@DICTIONARY@", DICTIONARY), ("@ADDRESS@", address), ("@PORT@", str(port)),
                       ("@NAS@", NAS), ("@SECRET@", SECRET)):
        text = text.replace(key, value)
    with open(cfg, "w") as f:
        f.write(text)
    p = subprocess.run([tactester.binary(), "-C", cfg, "-s", "radius.udp", *args], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=30, env=sanitizer_env(),
                       check=False)
    out = p.stdout.decode("utf-8", "replace")
    test.assertEqual(p.returncode, 0, out)
    # the Message-Authenticator differs for each reply
    return [re.sub(r"^Message-Authenticator=.*", "Message-Authenticator=...", line) for line in out.splitlines()]


class TactesterOfTheBuild(unittest.TestCase):
    """The tests use tactester only when the tac_plus-ng of the same installation has OpenSSL."""

    def binary(self, version):
        """tactester.binary() for an installation whose tac_plus-ng -v prints version."""
        with tempfile.TemporaryDirectory() as tmp:
            os.mkdir(os.path.join(tmp, "sbin"))
            for name, text in (("tac_plus-ng", "#!/bin/sh\necho '%s' >&2\n" % version), ("tactester", "#!/bin/sh\n")):
                path = os.path.join(tmp, "sbin", name)
                with open(path, "w") as f:
                    f.write(text)
                os.chmod(path, 0o755)
            with mock.patch.dict(os.environ, {"TACTEST_PREFIX": tmp}):
                return tactester.binary() and os.path.basename(tactester.binary())

    def test_tactester_of_an_earlier_build_with_openssl(self):
        self.assertIsNone(self.binary("tac_plus-ng version 1/PCRE2"))

    def test_tactester_of_a_build_with_openssl(self):
        self.assertEqual(self.binary("tac_plus-ng version 1/PCRE2/OpenSSL 3"), "tactester")


@unittest.skipUnless(tactester.binary(), "no tactester; run-tests builds it only with OpenSSL")
class RadiusUdp(DaemonTestCase):
    CONFIG = POLICY
    UDP = True

    def client(self, *args):
        return run_tactester(self, self.daemon.tmp, self.daemon.address, self.daemon.udp_port, *args)

    def test_access_accept_lists_the_reply_attributes(self):
        self.assertEqual(self.client("-m", "authc", "-u", "alice", "-p", "alicepw"),
                         ["authc ack", "Reply-Message=first", "Reply-Message=second", "Login-TCP-Port=2323",
                          "Message-Authenticator=..."])

    def test_accounting_response_lists_no_attributes(self):
        self.assertEqual(self.client("-m", "acct", "-u", "alice", "Acct-Status-Type=Start"),
                         ["acct ack", "Message-Authenticator=..."])


@unittest.skipUnless(tactester.binary(), "no tactester; run-tests builds it only with OpenSSL")
class MalformedReply(unittest.TestCase):
    """A server that answers with an attribute longer than the rest of the Access-Accept."""

    ADDRESS = "127.0.0.1"

    def serve(self, attributes, trailer):
        """Answer one Access-Request with an Access-Accept: attributes, Message-Authenticator, trailer.

        tactester looks for the Message-Authenticator before it dumps the
        reply, so a malformed attribute must come after it.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.bind((self.ADDRESS, 0))
        port = sock.getsockname()[1]
        sock.settimeout(30)

        def answer():
            req, peer = sock.recvfrom(4096)
            identifier, request_authenticator = req[1], req[4:20]
            ma = len(attributes) + 2
            attrs = attributes + bytes([radius.MESSAGE_AUTHENTICATOR, 18]) + bytes(16) + trailer
            head = struct.pack("!BBH", ACCESS_ACCEPT, identifier, radius.HEADER_LEN + len(attrs))
            mac = hmac.new(SECRET.encode(), head + request_authenticator + attrs, hashlib.md5).digest()
            attrs = attrs[:ma] + mac + attrs[ma + 16:]
            # RFC 2865 3: MD5(Code + Identifier + Length + Request Authenticator + Attributes + secret)
            auth = hashlib.md5(head + request_authenticator + attrs + SECRET.encode()).digest()
            sock.sendto(head + auth + attrs, peer)

        t = threading.Thread(target=answer, daemon=True)
        t.start()
        self.addCleanup(t.join, 30)
        return port

    def test_malformed_attribute_ends_the_dump(self):
        for name, trailer in (("longer than the rest of the packet", bytes([radius.REPLY_MESSAGE, 40]) + b"abc"),
                              ("length below 2", bytes([radius.REPLY_MESSAGE, 1]) + b"abc")):
            with self.subTest(name):
                port = self.serve(bytes([radius.REPLY_MESSAGE, 4]) + b"ok", trailer)
                with tempfile.TemporaryDirectory() as tmp:
                    lines = run_tactester(self, tmp, self.ADDRESS, port, "-m", "authc", "-u", "alice", "-p", "alicepw")
                self.assertEqual(lines, ["authc ack", "Reply-Message=ok", "Message-Authenticator=..."])

    def test_two_byte_attribute_at_the_end(self):
        """An attribute of only type and length is valid at the end of the packet too."""
        port = self.serve(b"", bytes([radius.REPLY_MESSAGE, 2]))
        with tempfile.TemporaryDirectory() as tmp:
            lines = run_tactester(self, tmp, self.ADDRESS, port, "-m", "authc", "-u", "alice", "-p", "alicepw")
        self.assertEqual(lines, ["authc ack", "Message-Authenticator=...", "Reply-Message="])


if __name__ == "__main__":
    unittest.main()
