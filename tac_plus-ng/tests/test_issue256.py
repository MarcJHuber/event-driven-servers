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


"""#256: an empty banner on one device doubled the login prompt on others.

parse_log_format() returned one shared static item for every empty
format, and fixup_banner() appended the "${message}${umessage}" tail to
it once per empty banner in the whole configuration.
"""

import unittest

from tactest import DaemonTestCase

POLICY = """
	device a {
		address = 127.0.0.7
		key = tactest
		welcome banner = ""
	}
	device b {
		address = 127.0.0.8
		key = tactest
		motd banner = ""
		reject banner = ""
	}
	user alice {
		password login = clear alicepw
	}
	ruleset {
		rule { script { permit } }
	}
"""


class EmptyBanners(DaemonTestCase):
    CONFIG = POLICY

    def test_issue256_username_prompt_once(self):
        r = self.connect(source="127.0.0.7").ascii_login("alice", "alicepw", user_in_start=False)
        self.assertEqual(r.prompts, ["Username: ", "Password: "], r)
        self.assertTrue(r.ok, r)

    def test_issue256_password_prompt_once(self):
        """With the user in START, the doubled prompt was the password prompt."""
        r = self.connect(source="127.0.0.7").ascii_login("alice", "alicepw")
        self.assertEqual(r.prompts, ["Password: "], r)

    def test_issue256_empty_motd(self):
        r = self.connect(source="127.0.0.8").ascii_login("alice", "alicepw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", ""), r)

    def test_issue256_device_without_empty_banners(self):
        """The default banner of a device that sets none is untouched."""
        r = self.connect().ascii_login("alice", "alicepw", user_in_start=False)
        self.assertEqual(r.prompts, ["User Access Verification\n\nUsername: ", "Password: "], r)


if __name__ == "__main__":
    unittest.main()
