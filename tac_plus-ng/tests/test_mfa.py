"""MFA: "mavis mfa", "mfa" in a user and in a script; the second factor is a MAVIS request of type MFA.

There is no prompt for the second factor. After the first factor passed,
the daemon sends the backend a request with TACTYPE MFA for the user and
waits for the answer: a push to a phone, as with radmavis-mt in front of
a RADIUS MFA proxy, or mavis_tacplus-ng-demo-mfa.pl. ACK lets the user
in, NAK or ERROR does not. The stub answers MFA requests only with a
forced result.
"""

import os
import unittest

from tactest import SOURCE, DaemonTestCase, Stub

DICTIONARY = os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")
SECRET = "radsecret"
NAS = "127.0.0.6"
MFA_DEVICE = "127.0.0.82"

POLICY = Stub.module(childs=(1, 1)) + f"""
	include = "{DICTIONARY}"
	device radius-nas {{
		address = {NAS}
		key = tactest
		radius.key = {SECRET}
	}}
	device mfa-dev {{
		address = {MFA_DEVICE}
		key = tactest
	}}
	acl on-mfa-dev {{ if (device == mfa-dev) permit }}
	mavis mfa acl = on-mfa-dev
	user alice {{
		password login = clear alicepw
		password pap = clear alicepw
		mfa = yes
	}}
	user bob {{
		password login = clear bobpw
		password pap = clear bobpw
	}}
	user carol {{
		password login = clear carolpw
		mfa = no
	}}
	user dave {{
		password login = clear davepw
	}}
	profile admin {{
		script {{
			if (aaa.protocol == radius) permit
			if (service == shell) {{
				if (user == dave) {{ mfa = yes }}
				set priv-lvl = 15
				permit
			}}
		}}
	}}
	ruleset {{
		rule {{ script {{ profile = admin permit }} }}
	}}
"""


class Mfa(DaemonTestCase):
    CONFIG = POLICY
    UDP = True

    def setUp(self):
        super().setUp()
        self.stub = Stub(self.daemon)
        self.stub.set()

    def mfa(self, result):
        """The answer of the backend to every MFA request."""
        self.stub.set(result={"MFA": result})

    def mfa_users(self, before):
        return [e["user"] for e in self.stub.requests(type="MFA")[before:]]

    def test_ascii_login_with_the_second_factor(self):
        for result, status in (("ACK", "PASS"), ("NAK", "FAIL"), ("ERROR", "FAIL")):
            with self.subTest(result=result):
                self.mfa(result)
                before = self.stub.count(type="MFA")
                r = self.connect().ascii_login("alice", "alicepw")
                self.assertEqual(r.statuses, ["GETPASS", status], r)
                self.assertEqual(self.mfa_users(before), ["alice"])

    def test_pap_with_the_second_factor(self):
        for result, status in (("ACK", "PASS"), ("NAK", "FAIL")):
            with self.subTest(result=result):
                self.mfa(result)
                before = self.stub.count(type="MFA")
                self.assertEqual(self.connect().pap("alice", "alicepw").status_name, status)
                self.assertEqual(self.mfa_users(before), ["alice"])

    def test_no_second_factor_after_a_wrong_password(self):
        self.mfa("ACK")
        before = self.stub.count(type="MFA")
        self.assertEqual(self.connect().ascii_login("alice", "wrong").status_name, "FAIL")
        self.assertEqual(self.connect().pap("alice", "wrong").status_name, "FAIL")
        self.assertEqual(self.mfa_users(before), [])

    def test_user_without_mfa_is_not_asked(self):
        self.mfa("NAK")
        before = self.stub.count(type="MFA")
        self.assertEqual(self.connect().ascii_login("bob", "bobpw").status_name, "PASS")
        self.assertEqual(self.connect().pap("bob", "bobpw").status_name, "PASS")
        self.assertEqual(self.mfa_users(before), [])

    def test_realm_acl_asks_users_on_the_device(self):
        """"mavis mfa acl" applies to users without an "mfa" line of their own."""
        self.mfa("NAK")
        before = self.stub.count(type="MFA")
        self.assertEqual(self.connect(source=MFA_DEVICE).ascii_login("bob", "bobpw").status_name, "FAIL")
        self.assertEqual(self.mfa_users(before), ["bob"])
        self.mfa("ACK")
        self.assertEqual(self.connect(source=MFA_DEVICE).ascii_login("bob", "bobpw").status_name, "PASS")
        self.assertEqual(self.mfa_users(before), ["bob", "bob"])

    def test_user_mfa_no_wins_over_the_realm_acl(self):
        self.mfa("NAK")
        before = self.stub.count(type="MFA")
        self.assertEqual(self.connect(source=MFA_DEVICE).ascii_login("carol", "carolpw").status_name, "PASS")
        self.assertEqual(self.mfa_users(before), [])

    def test_authorization_with_mfa_in_the_script(self):
        """"mfa = yes" in a script asks for the second factor before the authorization reply."""
        for result, status in (("ACK", "PASS_ADD"), ("NAK", "FAIL")):
            with self.subTest(result=result):
                self.mfa(result)
                before = self.stub.count(type="MFA")
                r = self.connect().author("dave", ["service=shell", "cmd="])
                self.assertEqual(r.status_name, status, r)
                self.assertEqual(self.mfa_users(before), ["dave"])

    def test_authorization_without_mfa_in_the_script(self):
        """The "mfa" line of a user is for authentication only."""
        self.mfa("NAK")
        before = self.stub.count(type="MFA")
        r = self.connect().author("alice", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]), r)
        self.assertEqual(self.mfa_users(before), [])

    def test_radius_with_the_second_factor(self):
        for result, code in (("ACK", "Access-Accept"), ("NAK", "Access-Reject")):
            with self.subTest(result=result):
                self.mfa(result)
                before = self.stub.count(type="MFA")
                r = self.radius(SECRET, source=NAS).access_request("alice", "alicepw", message_authenticator=True)
                self.assertEqual(r.code_name, code, r)
                self.assertEqual(self.mfa_users(before), ["alice"])
        self.mfa("NAK")
        before = self.stub.count(type="MFA")
        r = self.radius(SECRET, source=NAS).access_request("bob", "bobpw", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(self.mfa_users(before), [])



class BackendUsers(DaemonTestCase):
    """"mavis mfa = yes" for users of the backend: the password goes to the backend first, then the MFA request."""

    CONFIG = Stub.module(childs=(1, 1)) + """
	user backend = mavis
	login backend = mavis
	pap backend = mavis
	mavis mfa = yes
	ruleset { rule { script { permit } } }
"""

    def test_backend_user_with_the_second_factor(self):
        stub = Stub(self.daemon)
        for password, result, status, types in (("pw", "ACK", "PASS", ["AUTH", "MFA"]),
                                                ("pw", "NAK", "FAIL", ["AUTH", "MFA"]),
                                                ("wrong", "ACK", "FAIL", ["AUTH"])):
            with self.subTest(password=password, result=result):
                stub.set(users={"erin": {"password": "pw"}}, result={"MFA": result})
                before = stub.count(user="erin")
                self.assertEqual(self.connect().pap("erin", password).status_name, status)
                self.assertEqual([e["type"] for e in stub.requests(user="erin")[before:]], types)


if __name__ == "__main__":
    unittest.main()
