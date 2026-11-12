"""Linux VRFs: a spawnd listener bound to a VRF ("vrf = name"), the VRF name as realm and as ${vrf}.

A VRF device needs CAP_NET_ADMIN, so these tests run in a user and network
namespace of their own: Namespace runs this module again under "unshare
--user --net --map-root-user" with TACTEST_NETNS set, and only there the
VRF tests load (load_tests). In the namespace, 10.10.10.1 is on blue0 in
VRF vrf-blue and also on plain0 in the default VRF: the same address and
port reach other sockets, depending on the VRF of the client.

TACTEST_REQUIRE_VRF=1 turns the skip into a failure when the namespace or
the VRF device cannot be made (CI sets it, so that a skip cannot pass).
"""

import os
import shutil
import subprocess
import sys
import unittest

from tactest import LINUX, DaemonTestCase, tacacs

NETNS = "TACTEST_NETNS"
REQUIRE = "TACTEST_REQUIRE_VRF"
UNSHARE = ["unshare", "--user", "--net", "--map-root-user"]
ADDRESS = "10.10.10.1"
VRF = "vrf-blue"
INNER_TIMEOUT = 300
# __name__ is __main__ when the file runs directly
MODULE = os.path.splitext(os.path.basename(__file__))[0]

# the local table after the l3mdev rule (pref 1000), so that the VRF finds its own local address first
NETWORK = f"""\
rule add pref 32765 table local
rule del pref 0
link set lo up
link add {VRF} type vrf table 10
link set {VRF} up
link add blue0 type dummy
link set blue0 master {VRF}
addr add {ADDRESS}/24 dev blue0
link set blue0 up
link add plain0 type dummy
addr add {ADDRESS}/24 dev plain0
link set plain0 up
"""


def setUpModule():
    if os.environ.get(NETNS):
        subprocess.run(["ip", "-batch", "-"], input=NETWORK.encode(), check=True)


def namespace_problem():
    """Why no namespace with a VRF device can be made here, or None."""
    if not LINUX:
        return "Linux only"
    for tool in ("unshare", "ip"):
        if not shutil.which(tool):
            return f"no {tool} command"
    p = subprocess.run(UNSHARE + ["ip", "link", "add", VRF, "type", "vrf", "table", "10"],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=30,
                       check=False)
    if p.returncode:
        return "no VRF device in a user namespace: " + p.stdout.decode("utf-8", "replace").strip()
    return None


class Namespace(unittest.TestCase):
    patterns = ()

    def test_vrf_tests_in_a_network_namespace(self):
        problem = namespace_problem()
        if problem:
            if os.environ.get(REQUIRE):
                self.fail(f"{REQUIRE} is set, but {problem}")
            self.skipTest(problem)
        env = dict(os.environ, **{NETNS: "1"})
        selection = [arg for pattern in self.patterns for arg in ("-k", pattern)]
        p = subprocess.run(UNSHARE + [sys.executable, "-m", "unittest", "-v", *selection, MODULE],
                           cwd=os.path.dirname(os.path.abspath(__file__)), env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=INNER_TIMEOUT, check=False)
        out = p.stdout.decode("utf-8", "replace")
        self.assertEqual(p.returncode, 0, "VRF tests in the namespace failed:\n" + out)
        self.assertNotIn("skipped", out, out)
        self.assertRegex(out, r"\nRan [1-9]", out)


# each realm tells the realm and the VRF of the connection; "vrf == ..." is the condition on the VRF
POLICY = """
		profile shell {
			script {
				if (service == shell) {
					set tactest-realm = "$${realm}"
					set tactest-vrf = "$${vrf}"
					if (vrf == "vrf-blue") set tactest-in-vrf = yes
					permit
				}
			}
		}
		ruleset {
			rule { script { profile = shell permit } }
		}
"""

REALMS = """
	realm vrf-blue {
		device blue {
			address = 10.10.10.0/24
			key = bluekey
		}
		user alice {
			password pap = clear bluepw
		}
""" + POLICY + """
	}
	realm tenant {
		device tenant {
			address = 10.10.10.0/24
			key = tenantkey
		}
		user alice {
			password pap = clear tenantpw
		}
""" + POLICY + """
	}
"""


class VrfTestCase(DaemonTestCase):
    def connect_vrf(self, port, key, device=None):
        """A connection to ADDRESS:port from the VRF device, or from the default VRF."""
        c = tacacs.Connection((ADDRESS, port), key, timeout=5.0, device=device)
        self.addCleanup(c.close)
        return c

    def seen(self, c, user="alice"):
        r = c.author(user, ["service=shell", "cmd="])
        self.assertTrue(r.ok, r)
        return sorted(a for a in r.args if a.startswith("tactest-"))


class VrfListener(VrfTestCase):
    """A listener with "vrf = vrf-blue" binds to the VRF device: only clients in that VRF reach it."""

    SPAWND = """
	listen { address = 10.10.10.1 port = 49 vrf = vrf-blue }
	listen { address = 10.10.10.1 port = 50 vrf = vrf-blue realm = tenant }
"""
    CONFIG = REALMS

    def test_client_in_the_vrf_gets_the_realm_of_the_vrf_name(self):
        c = self.connect_vrf(49, "bluekey", device=VRF)
        self.assertEqual(c.pap("alice", "bluepw").status_name, "PASS")
        self.assertEqual(self.seen(c), ["tactest-in-vrf=yes", "tactest-realm=" + VRF, "tactest-vrf=" + VRF])

    def test_realm_of_the_listener_wins_over_the_vrf_name(self):
        c = self.connect_vrf(50, "tenantkey", device=VRF)
        self.assertEqual(c.pap("alice", "tenantpw").status_name, "PASS")
        self.assertEqual(self.seen(c), ["tactest-in-vrf=yes", "tactest-realm=tenant", "tactest-vrf=" + VRF])

    def test_client_in_the_default_vrf_does_not_reach_the_listener(self):
        # plain0 has the same address in the default VRF, with no listener on it
        with self.assertRaises(ConnectionRefusedError):
            self.connect_vrf(49, "bluekey")


class L3mdevAccept(VrfTestCase):
    """With net.ipv4.tcp_l3mdev_accept=1 a listener without "vrf" takes the clients of every VRF.

    The daemon then takes the VRF name of the client as realm.
    """

    SPAWND = "\tlisten { address = 10.10.10.1 port = 49 }\n"
    CONFIG = REALMS + """
	device plain {
		address = 10.10.10.0/24
		key = plainkey
	}
	user alice {
		password pap = clear plainpw
	}
""" + POLICY

    SYSCTL = "/proc/sys/net/ipv4/tcp_l3mdev_accept"

    @classmethod
    def setUpClass(cls):
        with open(cls.SYSCTL, "w") as f:
            f.write("1")
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        try:
            super().tearDownClass()
        finally:
            with open(cls.SYSCTL, "w") as f:
                f.write("0")

    def test_client_in_the_vrf_gets_the_realm_of_the_vrf_name(self):
        c = self.connect_vrf(49, "bluekey", device=VRF)
        self.assertEqual(c.pap("alice", "bluepw").status_name, "PASS")
        self.assertEqual(self.seen(c), ["tactest-in-vrf=yes", "tactest-realm=" + VRF, "tactest-vrf=" + VRF])

    def test_client_in_the_default_vrf_gets_the_default_realm(self):
        c = self.connect_vrf(49, "plainkey")
        self.assertEqual(c.pap("alice", "plainpw").status_name, "PASS")
        self.assertEqual(self.seen(c), ["tactest-realm=default", "tactest-vrf="])


def load_tests(loader, tests, pattern):
    """The VRF tests only in the namespace; outside it, the test that runs the selected ones there."""
    classes = [VrfListener, L3mdevAccept]
    if os.environ.get(NETNS):
        return unittest.TestSuite(loader.loadTestsFromTestCase(cls) for cls in classes)
    test = Namespace("test_vrf_tests_in_a_network_namespace")
    if loader.testNamePatterns and any(loader.getTestCaseNames(cls) for cls in classes):
        test.patterns = loader.testNamePatterns
    elif loader.testNamePatterns and not loader.getTestCaseNames(Namespace):
        return unittest.TestSuite()
    return unittest.TestSuite([test])


if __name__ == "__main__":
    unittest.main()
