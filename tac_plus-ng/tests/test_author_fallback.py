"""Authorization results that a change to the do_author() fallback must keep.

A device script that sets a profile, a user that the back-end authorizes, 
and an unknown user on a device with "permit if-authenticated = yes". Each 
test uses a new connection, so that the profile cache of the connection cannot
hide a change.
"""

import unittest

from tactest import LINUX, DaemonTestCase, Stub, tacacs

AUTHEN_METH_LOCAL = 5

BACKEND = """
	user backend = mavis
	login backend = mavis
	pap backend = mavis
"""

# The back-end authorizes the user itself: VERDICT = TRUE, no cache.
VERDICT = r"""
		script out {
			if ($$TACTYPE == INFO) {
				set $$VERDICT = "TRUE"
				set $$RARGS = "priv-lvl=15"
			}
		}"""


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class DeviceProfileKnownUser(DaemonTestCase):
    """A known user gets the profile of the device script if the rule only permits."""

    CONFIG = """
	profile priv15 { script { set priv-lvl = 15 permit } }
	profile priv15denied {
		acl { deny }
		script { set priv-lvl = 15 permit }
	}
	device withprofile {
		address = 127.0.11.1
		key = tactest
		script { profile = priv15 permit }
	}
	device withdeniedprofile {
		address = 127.0.11.5
		key = tactest
		script { profile = priv15denied permit }
	}
	user alice { password login = clear alicepw }
	ruleset {
		rule { script { permit } }
	}
"""

    def test_shell_start_has_the_device_profile(self):
        r = self.connect(source="127.0.11.1").author("alice", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]), r)

    def test_device_profile_acl_deny(self):
        # the same profile as priv15, with "acl { deny }"
        r = self.connect(source="127.0.11.5").author("alice", ["service=shell", "cmd="])
        self.assertEqual(r.status_name, "FAIL", r)


class BackendVerdict(DaemonTestCase):
    """A user that the back-end authorizes is permitted, also if the ruleset denies."""

    CONFIG = Stub.module(childs=(1, 1), script=VERDICT) + BACKEND + """
	ruleset {
		rule { script { deny } }
	}
"""

    def setUp(self):
        super().setUp()
        Stub(self.daemon).set(users={"bob": {"password": "bobpw"}})

    def test_shell_start_has_the_backend_attributes(self):
        r = self.connect().author("bob", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]), r)

    def test_command_is_permitted(self):
        r = self.connect().author("bob", ["service=shell", "cmd=show", "cmd-arg=version"])
        self.assertEqual(r.status_name, "PASS_ADD", r)


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class UnknownUserOnTrustingDevice(DaemonTestCase):
    """permit if-authenticated = yes: the result for an unknown user depends on authen_method and authen_type."""

    CONFIG = """
	profile restricted {
		acl { deny }
		script { permit }
	}
	device trusting {
		address = 127.0.11.2
		key = tactest
		permit if-authenticated = yes
	}
	device trustingwithprofile {
		address = 127.0.11.3
		key = tactest
		permit if-authenticated = yes
		script { profile = restricted permit }
	}
	ruleset {
		rule { script { permit } }
	}
"""

    def configure(self, method, authen_type):
        r = self.connect(source="127.0.11.2").author(
            "nobody", ["service=shell", "cmd=configure", "cmd-arg=terminal"],
            authen_method=method, authen_type=authen_type)
        return r.status_name

    def test_tacacs_ascii_is_denied(self):
        self.assertEqual(self.configure(tacacs.AUTHEN_METH_TACACSPLUS, tacacs.AUTHEN_TYPE_ASCII), "FAIL")

    def test_local_ascii_is_permitted(self):
        self.assertEqual(self.configure(AUTHEN_METH_LOCAL, tacacs.AUTHEN_TYPE_ASCII), "PASS_ADD")

    def test_local_pap_is_denied(self):
        self.assertEqual(self.configure(AUTHEN_METH_LOCAL, tacacs.AUTHEN_TYPE_PAP), "FAIL")

    def test_device_profile_acl_deny(self):
        r = self.connect(source="127.0.11.3").author("nobody", ["service=shell", "cmd="])
        self.assertEqual(r.status_name, "FAIL", r)


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class BackendNakOnTrustingDevice(DaemonTestCase):
    """A NAK to INFO (for example "User name not unique") is not an unknown user."""

    CONFIG = Stub.module(childs=(1, 1)) + BACKEND + """
	device trusting {
		address = 127.0.11.4
		key = tactest
		permit if-authenticated = yes
	}
	ruleset {
		rule { script { permit } }
	}
"""

    def test_nak_is_denied(self):
        stub = Stub(self.daemon)
        stub.set(users={"carl": {"password": "carlpw"}}, result={"carl:INFO": "NAK"})
        r = self.connect(source="127.0.11.4").author("carl", ["service=shell", "cmd="])
        self.assertEqual(r.status_name, "FAIL", r)
        self.assertEqual([e["result"] for e in stub.requests(type="INFO", user="carl")], ["NAK"])


if __name__ == "__main__":
    unittest.main()
