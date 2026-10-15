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


"""Policy conditions on the device and client address: net objects, their nesting, device tags.

Two addresses without network setup: on Linux all of 127.0.0.0/8 is local,
so a client binds to 127.0.x.y (source=) and the daemon sees another
device address. The client address (rem_addr) is a field of the packet.
Each condition that holds adds an AV pair "tactest-<name>=yes" to the
shell authorization, so one request shows all of them.
"""

import unittest

from tactest import LINUX, DaemonTestCase

USER = """
	user alice {
		password login = clear alicepw
		password pap = login
	}
"""


def shell_profile(conditions):
    """A profile that sets tactest-<name>=yes for every condition that holds, then permits."""
    lines = "".join("\t\t\t\tif (%s) set tactest-%s = yes\n" % (cond, name) for name, cond in conditions)
    return """
	profile shell {
		script {
			if (service == shell) {
%s				permit
			}
		}
	}
	ruleset {
		rule { script { profile = shell permit } }
	}
""" % lines


class PolicyTestCase(DaemonTestCase):
    def holds(self, source=None, rem_addr="127.0.0.1"):
        """Names of the conditions that hold for a request from source with this rem_addr."""
        r = self.connect(source=source).author("alice", ["service=shell", "cmd="], rem_addr=rem_addr)
        self.assertTrue(r.ok, r)
        return sorted(a[len("tactest-"):-len("=yes")] for a in r.args if a.startswith("tactest-"))


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class NestedNets(PolicyTestCase):
    """#16 and #166: a net matches its own addresses and those of its children, never those of its parent.

    #16: "nas == access-switches" also held for an address only the parent
    net "switches" has. #166 asked for the opposite with "parent = ":
    ef14e36 let a net inherit its parent's addresses, 479e732 took that
    back -- addresses go bottom-up, from a child into its parent, both for
    nested nets and for "parent =".
    """

    CONFIG = USER + """
	net switches {
		address = 127.0.3.0/24
		net access-switches {
			address = 127.0.3.100
		}
	}
	net jump-hosts {
		address = 127.0.4.1
	}
	net automation-hosts {
		address = 127.0.4.3
		parent = jump-hosts
	}
""" + shell_profile([
        ("switches", "device == switches"),
        ("access", "device == access-switches"),
        ("nas-access", "nas == access-switches"),
        ("jump", "device == jump-hosts"),
        ("automation", "device == automation-hosts"),
        ("client-access", "client == access-switches"),
        ("client-automation", "client == automation-hosts"),
        ("client-jump", "client == jump-hosts"),
    ])

    def test_issue16_child_net_does_not_match_an_address_of_its_parent(self):
        self.assertEqual(self.holds("127.0.3.20"), ["switches"])

    def test_issue16_parent_net_matches_an_address_of_its_child(self):
        self.assertEqual(self.holds("127.0.3.100"), ["access", "nas-access", "switches"])

    def test_issue166_net_with_parent_does_not_match_an_address_of_the_parent(self):
        self.assertEqual(self.holds("127.0.4.1"), ["jump"])

    def test_issue166_parent_matches_an_address_of_a_net_naming_it(self):
        self.assertEqual(self.holds("127.0.4.3"), ["automation", "jump"])

    def test_issue16_client_address(self):
        """The same rules for the client address (rem_addr)."""
        self.assertEqual(self.holds(rem_addr="127.0.3.20"), [])
        self.assertEqual(self.holds(rem_addr="127.0.3.100"), ["client-access"])
        self.assertEqual(self.holds(rem_addr="127.0.4.1"), ["client-jump"])
        self.assertEqual(self.holds(rem_addr="127.0.4.3"), ["client-automation", "client-jump"])


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class DeviceAddress(PolicyTestCase):
    """#134: "nas == <net>" stopped matching: the device address kept for the rules was not the one looked up.

    Fixed in 7b112b5: accept_control_common() converted the address to IPv4
    but then copied the IPv6 member of it into the context.
    """

    CONFIG = USER + """
	net net_local {
		address = 127.0.5.7
	}
	device nas5 {
		address = 127.0.5.0/24
		key = tactest
	}
	device nas57 {
		address = 127.0.5.7
		key = tactest
	}
""" + shell_profile([
        ("nas", "nas == net_local"),
        ("device", "device == net_local"),
        ("address", "device.address == 127.0.5.7"),
        ("nas57", "device == nas57"),
        ("nas5", "device == nas5"),
    ])

    def test_issue134_nas_matches_a_net(self):
        self.assertEqual(self.holds("127.0.5.7"), ["address", "device", "nas", "nas57"])

    def test_issue134_other_address_does_not_match(self):
        self.assertEqual(self.holds("127.0.5.8"), ["nas5"])

    def test_most_specific_device_wins(self):
        holds = self.holds("127.0.5.7")
        self.assertIn("nas57", holds)
        self.assertNotIn("nas5", holds)
        self.assertEqual(self.holds("127.0.0.1"), [])


class DeviceTagWithoutTags(PolicyTestCase):
    """#104: "device.tag" in a script while no device has a tag broke authentication and authorization.

    The tree of tag names existed only once a "tag =" had been parsed; the
    condition looked its name up in a tree that wasn't there. No "tag =" in
    this whole configuration, on purpose.
    """

    CONFIG = USER + shell_profile([("bar", "device.tag == bar")])

    def test_issue104_device_tag_without_any_tag(self):
        self.assertTrue(self.connect().pap("alice", "alicepw").ok)
        self.assertEqual(self.holds(), [])


if __name__ == "__main__":
    unittest.main()
