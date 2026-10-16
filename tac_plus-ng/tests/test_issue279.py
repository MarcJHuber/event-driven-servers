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


"""Access-Request with a Cisco VSA that is not Cisco-AVPair.

rad_check_dacl() scans every Access-Request for the dACL download marker
before authentication. Inside a Cisco vendor-specific attribute it advances
only over Cisco-AVPair (sub-type 1); any other sub-type (Cisco-NAS-Port is
sub-type 2) leaves the pointer in place and the single worker loops forever.

Each request here is otherwise a normal, valid PAP login (right secret, right
password), so the fixed daemon answers Access-Accept. On master the worker
never answers the non-AVPair requests: the reply times out and the harness
reports "worker hung" after the test. The Cisco-AVPair case is the control --
it advances the pointer and was never affected.

That the scan runs before the secret is checked, so an attacker needs no
secret, is shown by dos/repro.sh, not here.
"""

import os
import struct
import unittest

from tactest import SOURCE, DaemonTestCase, radius

DICTIONARY = os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")

VENDOR_SPECIFIC = 26
VID_CISCO = 9
CISCO_AVPAIR = 1
CISCO_NAS_PORT = 2          # the example the ticket uses

SECRET = "radsecret"
NAS = "127.0.0.9"

POLICY = """
	include = "%s"
	device radius-nas {
		address = 127.0.0.9
		key = tactest
		radius.key = radsecret
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile admin { script { if (aaa.protocol == radius) permit } }
	ruleset { rule { script { profile = admin permit } } }
""" % DICTIONARY


def cisco_vsa_value(sub_type, sub_value):
    """The value of a Vendor-Specific attribute (26): vendor 9 plus one sub-attribute.

    The RADIUS client wraps it in the type/length of attribute 26.
    """
    sub = bytes([sub_type, len(sub_value) + 2]) + sub_value
    return struct.pack("!I", VID_CISCO) + sub


class CiscoVsaHang(DaemonTestCase):
    """One daemon per test: a hung worker must not reach the next test."""

    CONFIG = None

    def login_with_vsa(self, sub_type, sub_value=b"\x00\x00\x00\x00", name="vsa"):
        d = self.start_daemon(POLICY, udp=True, name=name)
        c = self.radius(SECRET, daemon=d, timeout=3.0, source=NAS)
        return c.access_request("alice", "alicepw", message_authenticator=True,
                                attributes=[(VENDOR_SPECIFIC, cisco_vsa_value(sub_type, sub_value))])

    def test_issue279_cisco_nas_port_does_not_hang(self):
        self.assertEqual(self.login_with_vsa(CISCO_NAS_PORT, name="nas-port").code_name, "Access-Accept")

    def test_issue279_other_non_avpair_sub_types_do_not_hang(self):
        for sub_type in (5, 101, 250):
            with self.subTest(sub_type=sub_type):
                self.assertEqual(self.login_with_vsa(sub_type, name="vsa-%d" % sub_type).code_name, "Access-Accept")

    def test_issue279_cisco_avpair_is_still_handled(self):
        """Control: a real Cisco-AVPair advances the pointer and never hung."""
        self.assertEqual(self.login_with_vsa(CISCO_AVPAIR, b"shell:priv-lvl=15", name="avpair").code_name,
                         "Access-Accept")


if __name__ == "__main__":
    unittest.main()
