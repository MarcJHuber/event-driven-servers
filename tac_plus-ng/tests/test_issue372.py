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


"""#372 Fallback authorization for users not present in tac_plus-ng"""

import unittest

from tactest import DaemonTestCase

POLICY = """
	key = tactest
	device r4 {
		address = 127.0.0.4
		permit if-authenticated = yes
	}
	device r5 {
		address = 127.0.0.5
	}
	profile shell {
		script {
			if (service == shell) {
				if (cmd == "") {
					set priv-lvl = 15
					permit
				}
				deny
			}
		}
	}
	device r6 {
		address = 127.0.0.6
		permit if-authenticated = yes
		script { profile = shell }
	}
	ruleset {
		rule { script { profile = shell permit } }
	}
"""


class Authorization(DaemonTestCase):
    CONFIG = POLICY

    def test_shell_start(self):
        r = self.connect(source="127.0.0.4").author("alice", ["service=shell", "cmd="])
        self.assertEqual(r.status_name, "PASS_ADD", r)
        self.assertEqual(r.args, [])
        self.wait_log("authorization", "permit")
        r = self.connect(source="127.0.0.5").author("alice", ["service=shell", "cmd="])
        self.assertEqual(r.status_name, "FAIL", r)
        self.wait_log("authorization", "deny")
        r = self.connect(source="127.0.0.6").author("alice", ["service=shell", "cmd="])
        self.assertEqual(r.status_name, "PASS_ADD", r)
        self.assertEqual(r.args, ["priv-lvl=15"])
        self.wait_log("authorization", "permit")

if __name__ == "__main__":
    unittest.main()
