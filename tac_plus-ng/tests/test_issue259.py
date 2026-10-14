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


"""#259: "message PASSWORD = <string>" as a script action: a ruleset rule sets the password prompt.

The daemon is started inside each test: a tree without the feature
rejects the configuration, and that has to fail the test, not the class.
"""

import unittest

from tactest import DaemonTestCase

BANNER = "User Access Verification\n\n"

POLICY = """
	device lab {
		address = 127.0.0.11
		key = tactest
		single-connection = yes
		password max-attempts = 3
		enable = login
		%(device)s
	}
	group otp { }
	group netadmin { }
	user otpuser { password login = clear pw1123456 password pap = login member = otp }
	user netadmin { password login = clear pw2 password pap = login member = netadmin }
	profile admin { script { if (service == shell) { set priv-lvl = 15 permit } } }
	ruleset {
		rule otp_users {
			script {
				if (member == otp) {
					message PASSWORD = "Password+OTP: "
					profile = admin
					permit
				}
			}
		}
		rule netadmins {
			script { if (member == netadmin) { profile = admin permit } }
		}
	}
"""


class RulePasswordPrompt(DaemonTestCase):
    CONFIG = None

    def start(self, device=""):
        d = self.start_daemon(POLICY % dict(device=device))
        return lambda **kw: self.connect(source="127.0.0.11", daemon=d, **kw)

    def test_issue259_rule_sets_the_prompt(self):
        connect = self.start()
        r = connect().ascii_login("otpuser", "pw1123456")
        self.assertEqual((r.prompts, r.status_name), ([BANNER + "Password+OTP: "], "PASS"), r)

    def test_issue259_rule_without_action_keeps_the_default(self):
        connect = self.start()
        r = connect().ascii_login("netadmin", "pw2")
        self.assertEqual((r.prompts, r.status_name), ([BANNER + "Password: "], "PASS"), r)

    def test_issue259_retry_prompt(self):
        connect = self.start()
        r = connect().ascii_login("otpuser", ["bad", "pw1123456"])
        self.assertEqual(r.prompts, [BANNER + "Password+OTP: ", "Password incorrect.\nPassword+OTP: "], r)
        self.assertTrue(r.ok, r)

    def test_issue259_rule_before_device_prompt(self):
        connect = self.start(device='message PASSWORD = "Lab password: "')
        self.assertEqual(connect().ascii_login("otpuser", "pw1123456").prompts, [BANNER + "Password+OTP: "])
        self.assertEqual(connect().ascii_login("netadmin", "pw2").prompts, [BANNER + "Lab password: "])

    def test_issue259_enable_and_pap_unchanged(self):
        connect = self.start()
        r = connect().enable("pw1123456", user="otpuser")
        self.assertEqual((r.prompts, r.status_name), (["Password: "], "PASS"), r)
        self.assertTrue(connect().pap("otpuser", "pw1123456").ok)

    def test_issue259_single_connection(self):
        c = self.start()(single_connect=True)
        for user, password, prompt in (("otpuser", "pw1123456", "Password+OTP: "),
                                       ("otpuser", "pw1123456", "Password+OTP: "),
                                       ("netadmin", "pw2", "Password: "),
                                       ("otpuser", "pw1123456", "Password+OTP: ")):
            r = c.ascii_login(user, password)
            self.assertEqual((r.prompts, r.status_name), ([BANNER + prompt], "PASS"), user)


if __name__ == "__main__":
    unittest.main()
