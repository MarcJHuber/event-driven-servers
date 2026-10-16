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


"""#293: enable request for a user the daemon doesn't know.

https://github.com/MarcJHuber/event-driven-servers/issues/293

do_enable() evaluates the ruleset through cfg_get_enable() before it
compares the enable password. For a user that is neither configured nor
found by MAVIS, session->user is NULL, and since 6cb55e5 (#257) the profile
cache code -- calc_user_profile_crc(), called from lookup_user_profile() --
reads session->user->name: the worker dies with SIGSEGV. The client sees the
connection close; spawnd restarts the worker, and the next enable request
from that user does the same.

A second NULL dereference sits in cfg_get_enable() itself: when the ruleset
assigns a profile that has an enable password, the type6 key is taken from
session->user->realm.

The fixed daemon answers these requests: the device's (or the profile's)
enable password decides, as it does for a known user.
"""

from tactest import DaemonTestCase, Stub

DEVICE_ENABLE = """
	device enable-nas {
		address = 127.0.0.20
		key = tactest
		enable 15 = clear devenablepw
	}
	user alice {
		password login = clear alicepw
	}
"""


class EnableUnknownUser(DaemonTestCase):
    """Local users only; the device has an enable password."""

    CONFIG = DEVICE_ENABLE + """
	ruleset { rule { script { permit } } }
"""

    def test_issue293_enable_unknown_user_device_password(self):
        r = self.connect(source="127.0.0.20").enable("devenablepw", user="nobody")
        self.assertEqual(r.status_name, "PASS")

    def test_issue293_enable_unknown_user_wrong_password(self):
        r = self.connect(source="127.0.0.20").enable("wrong", user="nobody")
        self.assertEqual(r.status_name, "FAIL")

    def test_issue293_enable_no_username_device_password(self):
        # a plain "enable" without a user name in START
        r = self.connect(source="127.0.0.20").enable("devenablepw")
        self.assertEqual(r.status_name, "PASS")

    def test_issue293_enable_known_user_device_password(self):
        # control: a configured user was never affected
        r = self.connect(source="127.0.0.20").enable("devenablepw", user="alice")
        self.assertEqual(r.status_name, "PASS")


class EnableMavisNotFound(DaemonTestCase):
    """Users from MAVIS; the backend answers INFO for the user with NOTFOUND."""

    CONFIG = Stub.module(childs=(1, 1)) + DEVICE_ENABLE + """
	user backend = mavis
	login backend = mavis
	ruleset { rule { script { permit } } }
"""

    def test_issue293_enable_mavis_notfound_device_password(self):
        stub = Stub(self.daemon)
        stub.set(users={})
        r = self.connect(source="127.0.0.20").enable("devenablepw", user="nobody")
        self.assertEqual(r.status_name, "PASS")
        self.assertEqual([e["result"] for e in stub.requests(type="INFO", user="nobody")][-1:], ["NOTFOUND"])

    def test_issue293_enable_mavis_notfound_wrong_password(self):
        Stub(self.daemon).set(users={})
        r = self.connect(source="127.0.0.20").enable("wrong", user="nobody")
        self.assertEqual(r.status_name, "FAIL")


class EnableUnknownUserProfile(DaemonTestCase):
    """The ruleset gives every request a profile that has the enable password."""

    CONFIG = """
	device enable-nas {
		address = 127.0.0.20
		key = tactest
	}
	profile netadmin {
		enable 15 = clear profenablepw
		script { permit }
	}
	ruleset { rule { script { profile = netadmin permit } } }
"""

    def test_issue293_enable_unknown_user_profile_password(self):
        r = self.connect(source="127.0.0.20").enable("profenablepw", user="nobody")
        self.assertEqual(r.status_name, "PASS")

    def test_issue293_enable_unknown_user_profile_wrong_password(self):
        r = self.connect(source="127.0.0.20").enable("wrong", user="nobody")
        self.assertEqual(r.status_name, "FAIL")
