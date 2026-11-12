"""The older tac_plus daemon (directory tac_plus/), which users still run.

run-tests builds it next to tac_plus-ng. The daemon runs under spawnd
with config.TAC_PLUS around the policy, in tac_plus syntax.
"""

import os
import unittest

from tactest import DaemonTestCase, config, prefix

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


if __name__ == "__main__":
    unittest.main()
