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


"""#262: two parser bugs the TLS samples run into.

1. "tls.peer.cert.sha256 = <hex>" (and sha1), as documented, was rejected:
   the parser read the "=" as the fingerprint.
2. confdir_strdup() cut four characters off every "$CONFDIR/..." path,
   crashed on one with fewer than three characters after the slash, and
   built the path from the file name when the configuration was given
   without a directory.
"""

import os
import tempfile
import unittest

from tactest import features
from tactest.daemon import parse_only

PUBLIC_KEY = """\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAj7oFR4/OJaCJbjcv5lrOYZ9qYNzKPzYLQHWikDVhcOQ=
-----END PUBLIC KEY-----
"""

CONFIG = """\
id = spawnd { listen { port = 4949 } }
id = tac_plus-ng {
	device peer {
		address = 10.0.0.0/8
		%s
	}
}
"""


def fingerprint(n):
    return ":".join("%02x" % i for i in range(n))


@unittest.skipUnless("openssl" in features(), "TLS settings need a build with OpenSSL")
class ParserBugs(unittest.TestCase):
    def parse(self, line, files=None, relative=False):
        """tac_plus-ng -P on CONFIG with line in the device; files go next to it.

        parse_only() returns a negative code when the parser is killed by a
        signal (since #264 "-P" reports that as 128 + signal).
        """
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in (files or {}).items():
                with open(os.path.join(tmp, name), "w") as f:
                    f.write(text)
            path = os.path.join(tmp, "tac_plus-ng.cfg")
            with open(path, "w") as f:
                f.write(CONFIG % line.replace("$tmp", tmp))
            return parse_only("tac_plus-ng.cfg" if relative else path, cwd=tmp)

    def test_issue262_cert_sha256_with_equals_sign(self):
        self.assertEqual(self.parse("tls.peer.cert.sha256 = %s" % fingerprint(32)), (0, ""))

    def test_issue262_cert_sha1_with_equals_sign(self):
        self.assertEqual(self.parse("tls.peer.cert.sha1 = %s" % fingerprint(20)), (0, ""))

    def test_issue262_cert_sha256_without_equals_sign(self):
        """The form the parser has accepted all along still works."""
        self.assertEqual(self.parse("tls.peer.cert.sha256 %s" % fingerprint(32)), (0, ""))

    def test_issue262_cert_sha256_wrong_length(self):
        code, out = self.parse("tls.peer.cert.sha256 = %s" % fingerprint(31))
        self.assertGreater(code, 0, out)
        self.assertIn("Expected a 32 byte cert fingerprint", out)

    def test_issue262_confdir_path_complete(self):
        """$CONFDIR/peer.pem was opened as .../peer."""
        self.assertEqual(self.parse("tls.peer.cert.rpk file = $CONFDIR/peer.pem", {"peer.pem": PUBLIC_KEY}), (0, ""))

    def test_issue262_confdir_path_not_cut(self):
        """The file named like the cut path must not be what is found."""
        code, out = self.parse("tls.peer.cert.rpk file = $CONFDIR/peer.pem", {"peer": PUBLIC_KEY})
        self.assertGreater(code, 0, out)
        self.assertIn("$CONFDIR/peer.pem: No such file", out)

    def test_issue262_confdir_short_path(self):
        """Fewer than three characters after "$CONFDIR/": the length wrapped around, SIGSEGV."""
        self.assertEqual(self.parse("tls.peer.cert.rpk file = $CONFDIR/ab", {"ab": PUBLIC_KEY}), (0, ""))

    def test_issue262_confdir_of_a_config_without_directory(self):
        """-P tac_plus-ng.cfg: $CONFDIR is ".", not "tac_plus-ng.cfg."."""
        self.assertEqual(self.parse("tls.peer.cert.rpk file = $CONFDIR/peer.pem", {"peer.pem": PUBLIC_KEY},
                                    relative=True), (0, ""))

    def test_issue262_absolute_path(self):
        self.assertEqual(self.parse("tls.peer.cert.rpk file = $tmp/peer.pem", {"peer.pem": PUBLIC_KEY}), (0, ""))


if __name__ == "__main__":
    unittest.main()
