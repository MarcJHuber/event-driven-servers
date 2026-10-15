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


"""#258: "motd banner = <format>" as a script action, so a ruleset rule can set the MOTD.

The daemon is started inside each test: a tree without the feature
rejects the configuration, and that has to fail the test, not the class.
"""

import unittest

from tactest import DaemonTestCase

DEVICE_MOTD = "Authorized access only.\n"
NETADMIN_MOTD = "Change freeze until Monday 06:00 UTC.\n"

POLICY = """
	device lab {
		address = 127.0.0.10
		key = tactest
		single-connection = yes
		motd banner = "Authorized access only.\\n"
	}
	group netadmin { }
	group contractor { }
	group auditor { }
	user netadmin { password login = clear pw1 member = netadmin }
	user contractor { password login = clear pw2 member = contractor }
	user auditor { password login = clear pw3 member = auditor }
	profile admin { script { if (service == shell) { set priv-lvl = 15 permit } } }
	profile limited {
		acl { %(profile_acl)s }
		script { if (service == shell) { set priv-lvl = 1 permit } }
	}
	ruleset {
		rule netadmins {
			script {
				if (member == netadmin) {
					motd banner = "Change freeze until Monday 06:00 UTC.\\n"
					profile = admin
					permit
				}
			}
		}
		rule contractors {
			script { if (member == contractor) { motd banner = "" profile = limited permit } }
		}
		rule auditors {
			script { if (member == auditor) { profile = limited permit } }
		}
	}
"""


class RuleMotd(DaemonTestCase):
    CONFIG = None

    def start(self, profile_acl="permit"):
        d = self.start_daemon(POLICY % dict(profile_acl=profile_acl))
        return lambda: self.connect(source="127.0.0.10", daemon=d)

    def motd(self, c, user, password):
        r = c.ascii_login(user, password)
        self.assertEqual(r.status_name, "PASS", r)
        return r.server_msg

    def test_issue258_rule_sets_the_motd(self):
        connect = self.start()
        self.assertEqual(self.motd(connect(), "netadmin", "pw1"), NETADMIN_MOTD)

    def test_issue258_rule_without_action_keeps_the_device_motd(self):
        connect = self.start()
        self.assertEqual(self.motd(connect(), "auditor", "pw3"), DEVICE_MOTD)

    def test_issue258_empty_motd_in_a_rule(self):
        connect = self.start()
        self.assertEqual(self.motd(connect(), "contractor", "pw2"), "")

    def test_issue258_failed_login_unchanged(self):
        connect = self.start()
        r = connect().ascii_login("netadmin", "wrong")
        self.assertEqual((r.status_name, r.server_msg), ("FAIL", "Password incorrect.\n"))

    def test_issue258_profile_acl_sets_the_motd(self):
        """The profile acl runs after the ruleset: the last one that sets the banner wins."""
        connect = self.start(profile_acl='motd banner = "Profile acl.\\n" permit')
        self.assertEqual(self.motd(connect(), "auditor", "pw3"), "Profile acl.\n")

    def test_issue258_single_connection_cached_verdict(self):
        """A repeated login on one connection takes the verdict from the profile cache, with its MOTD."""
        c = self.start()()
        c.single_connect = True
        for user, password, motd in (("netadmin", "pw1", NETADMIN_MOTD), ("netadmin", "pw1", NETADMIN_MOTD),
                                     ("auditor", "pw3", DEVICE_MOTD), ("netadmin", "pw1", NETADMIN_MOTD)):
            self.assertEqual(self.motd(c, user, password), motd, user)


if __name__ == "__main__":
    unittest.main()
