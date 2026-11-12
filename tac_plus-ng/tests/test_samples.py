"""The shipped samples as running daemons: the whole file parses, and its users get the answers it documents.

test_parse.py checks only that a sample parses, and most samples stop at
the first path of an installed system. Here each sample runs with the
fewest edits that make it start in a scratch directory (sample.template()):
the listener, the log files, and helper programs replaced by the MAVIS
stub. Everything else is the configuration a user copies.
"""

import unittest

from tactest import DaemonTestCase, Stub, sample

STUB_EXEC = Stub.module().split("\n")[1:-2]     # the exec and setenv lines, without the "mavis module" block


class MainSample(DaemonTestCase):
    """sample/tac_plus-ng.cfg: devices, enable levels, groups, profiles, ruleset, a realm, MAVIS modules."""

    KEY = "demo"
    LISTEN = {"heck": "realm = heck"}
    TEMPLATE = sample.template("sample/tac_plus-ng.cfg", [
        ("listen { port = 4949 realm = heck }", "listen { address = $address port = $port }\n$spawnd"),
        ("destination = /tmp/access.log", 'destination = "$tmp/access.log"'),
        ("destination = /tmp/author.log", 'destination = "$tmp/author.log"'),
        ('destination = ">/tmp/author2.log"', 'destination = ">$tmp/author2.log"'),
        ('"$CONFDIR/hosts.txt"', '"%s"' % sample.path("sample/hosts.txt")),
        ("exec = /usr/local/sbin/pammavis pammavis -s ssh", "\n".join(STUB_EXEC)),
    ])

    def test_login_with_the_banner_of_the_device(self):
        r = self.connect().ascii_login("demo", "demo")
        self.assertEqual(r.status_name, "PASS")
        self.assertEqual(r.prompts, ["Welcome home\nPassword: "])
        self.assertEqual(self.connect().pap("demo", "demo").status_name, "PASS")
        self.assertEqual(self.connect().pap("demo", "wrong").status_name, "FAIL")

    @unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
    def test_parent_device_banner_and_rules(self):
        """127.0.0.2 is the device "world": its banner, and no rule permits that device."""
        r = self.connect(source="127.0.0.2").ascii_login("demo", "demo")
        self.assertEqual(r.prompts, ["Welcome\nPassword: "])
        self.assertEqual(r.status_name, "FAIL")

    def test_user_without_a_group_is_denied_by_the_ruleset(self):
        self.assertEqual(self.connect().pap("readonly", "readonly").status_name, "FAIL")
        self.wait_log("access", "readonly\ttty0\t127.0.0.1\tpap login denied by ACL")

    def test_user_with_an_own_profile_skips_the_ruleset(self):
        self.assertEqual(self.connect().ascii_login("demo2", "demo2").status_name, "PASS")
        r = self.connect().author("demo2", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]))

    def test_engineering_profile(self):
        r = self.connect().author("demo", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]))
        r = self.connect().author("demo", ["service=shell", "cmd=show", "cmd-arg=version"])
        self.assertEqual((r.status_name, r.server_msg), ("PASS_ADD", "commandline=show version"))
        r = self.connect().author("demo", ["service=demo"])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["test=too"]))
        self.assertEqual(self.connect().author("demo", ["service=ppp", "protocol=ip"]).status_name, "FAIL")
        self.wait_log("author", "\tdemo\ttty0\t127.0.0.1\tengineering\tpermit\tshell\tshow version\n")
        self.wait_log("author", "\tdemo\ttty0\t127.0.0.1\tengineering\tdeny\tppp\tprotocol=ip\n")

    def test_enable_levels_of_the_profile(self):
        self.assertEqual(self.connect().enable("demodemo", user="demo", priv_lvl=14).status_name, "PASS")
        self.assertEqual(self.connect().enable("demo", user="demo", priv_lvl=15).status_name, "PASS")
        r = self.connect().enable("anything", user="demo", priv_lvl=2)
        self.assertEqual((r.status_name, r.prompts), ("PASS", []))
        # the profile's "enable 15 = login" replaces the device's "enable 15 = clear secret"
        self.assertEqual(self.connect().enable("secret", user="demo", priv_lvl=15).status_name, "FAIL")

    def test_password_policy_module_before_the_backend(self):
        """The "null" module with "script in" rejects a weak password; only a strong one reaches the backend."""
        stub = Stub(self.daemon)
        stub.set(users={"weak": {"password": "weakpw"}, "strong": {"password": "Str0ngPassw"}})
        r = self.connect().pap("weak", "weakpw")
        self.assertEqual((r.status_name, r.server_msg), ("FAIL", "Password is too weak.\n"))
        self.assertEqual(stub.count("AUTH", "weak"), 0)
        # the backend says yes, the ruleset no: the groups module keeps no group a rule names
        self.assertEqual(self.connect().pap("strong", "Str0ngPassw").status_name, "FAIL")
        self.assertEqual(stub.count("AUTH", "strong"), 1)

    def test_realm_uses_the_parent_ruleset_if_its_own_gives_no_verdict(self):
        self.assertEqual(self.connect(listener="heck").pap("demo", "demo").status_name, "PASS")
        self.assertEqual(self.connect(listener="heck").pap("readonly", "readonly").status_name, "FAIL")


if __name__ == "__main__":
    unittest.main()
