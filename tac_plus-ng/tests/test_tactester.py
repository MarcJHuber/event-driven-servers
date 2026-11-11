"""tactester: the RADIUS client prints the attributes of the reply, and nothing else."""

import os
import re
import subprocess
import tempfile
import unittest
from unittest import mock

from tactest import SOURCE, DaemonTestCase, tactester
from tactest.daemon import sanitizer_env

DICTIONARY = os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")
SECRET = "radsecret"
NAS = "127.0.0.6"

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


if __name__ == "__main__":
    unittest.main()
