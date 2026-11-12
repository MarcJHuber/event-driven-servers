"""The older tac_plus daemon (directory tac_plus/), which users still run.

run-tests builds it next to tac_plus-ng. The daemon runs under spawnd
with config.TAC_PLUS around the policy, in tac_plus syntax.
"""

import os
import unittest

from tactest import DaemonTestCase, config, prefix
from tactest.daemon import parse_only

TAC_PLUS = os.access(os.path.join(prefix(), "sbin", "tac_plus"), os.X_OK)


@unittest.skipUnless(TAC_PLUS, "no tac_plus in the installation under test")
class TacPlusTestCase(DaemonTestCase):
    PROGRAM = "tac_plus"
    TEMPLATE = config.TAC_PLUS


class Smoke(TacPlusTestCase):
    """One request of each type gets a well-formed reply."""

    CONFIG = """
	user = alice {
		pap = clear alicepw
		service = shell { default command = permit }
	}
"""

    def test_pap(self):
        self.assertTrue(self.connect().pap("alice", "alicepw").ok)

    def test_author(self):
        r = self.connect().author("alice", ["service=shell", "cmd="])
        self.assertEqual(r.status_name, "PASS_ADD", r)

    def test_acct(self):
        self.assertTrue(self.connect().acct("alice", ["task_id=1", "service=shell"]).ok)


def users(conditions):
    """One user per condition; its shell authorization passes only if the condition holds."""
    return "".join("\tuser = %s { service = shell { script = { if (%s) permit deny } } }\n" % (name, cond)
                   for name, cond in conditions)


CONDITIONS = [
    ("acl-eq", "acl == trusted"),
    ("acl-ne", "acl != trusted"),
    ("acl-not-eq", "!(acl == trusted)"),
    ("time-always-eq", "time == always"),
    ("time-always-ne", "time != always"),
    ("time-never-eq", "time == never"),
    ("time-never-ne", "time != never"),
    # the ACLs below use the ACL syntax, not a script
    ("std-acl-eq", "acl == std-acl-eq"),
    ("std-acl-ne", "acl == std-acl-ne"),
    ("std-acl-not", "acl == std-acl-not"),
    ("std-time-eq", "acl == std-time-eq"),
    ("std-time-ne", "acl == std-time-ne"),
    ("std-time-not", "acl == std-time-not"),
]


class AclAndTimeNegation(TacPlusTestCase):
    """"acl != NAME" and "time != NAME" are the negation of "==", in scripts and in ACLs.

    The tac_plus-ng counterpart is AclAndTimeNegation in test_policy.py.
    """

    CONFIG = """
	acl = trusted { nac = 127.0.7.1 }
	timespec = always { "* * * * *" }
	timespec = never { "* * 30 2 *" }
	acl = std-acl-eq { acl == trusted }
	acl = std-acl-ne { acl != trusted }
	acl = std-acl-not { acl = not trusted }
	acl = std-time-eq { time == never }
	acl = std-time-ne { time != never }
	acl = std-time-not { time = not never }
""" + users(CONDITIONS)

    def holds(self, kind, rem_addr):
        """Names of the conditions of this kind that hold for a request with this rem_addr."""
        c = self.connect()
        return [name for name, _ in CONDITIONS if name.startswith(kind + "-")
                and c.author(name, ["service=shell", "cmd="], rem_addr=rem_addr).ok]

    def test_acl_ne_is_the_negation_of_acl_eq(self):
        self.assertEqual(self.holds("acl", "127.0.7.1"), ["acl-eq"])
        self.assertEqual(self.holds("acl", "127.0.7.2"), ["acl-ne", "acl-not-eq"])

    def test_time_ne_is_the_negation_of_time_eq(self):
        self.assertEqual(self.holds("time", "127.0.0.1"), ["time-always-eq", "time-never-ne"])

    def test_acl_ne_in_an_acl(self):
        self.assertEqual(self.holds("std-acl", "127.0.7.1"), ["std-acl-eq"])
        self.assertEqual(self.holds("std-acl", "127.0.7.2"), ["std-acl-ne", "std-acl-not"])

    def test_time_ne_in_an_acl(self):
        self.assertEqual(self.holds("std-time", "127.0.0.1"), ["std-time-ne", "std-time-not"])


class BareExclmark(TacPlusTestCase):
    """A script "acl ! NAME" or "time ! NAME" is a syntax error, as in an ACL; "!=" negates.

    tac_plus -P, because a parse error in a user script does not stop a daemon under spawnd.
    """

    CONFIG = None

    def test_bare_exclmark_is_rejected(self):
        for cond, name in (("acl ! trusted", "trusted"), ("time ! always", "always")):
            with self.subTest(cond=cond):
                body = ('\tacl = trusted { nac = 127.0.7.1 }\n\ttimespec = always { "* * * * *" }\n'
                        + users([("u", cond)]))
                path = self.scratch_file("tac_plus.cfg", config.render(config.TAC_PLUS, body=body))
                code, out = parse_only(path, program="tac_plus")
                self.assertEqual(code, 78, out)
                self.assertIn("Expected '=', but got '%s'" % name, out)


if __name__ == "__main__":
    unittest.main()
