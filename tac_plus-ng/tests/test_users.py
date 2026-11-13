"""Authentication settings of users and devices: password types, expiry, messages, enable, retries, password change.

Each class starts a daemon on a configuration that uses the settings, so
the parser must accept them; the tests then send real requests and check
the replies and log lines. The hashes of types 5, 7, 8 and 9 and the ASA
enable hash are those that IOS and ASA write for "cisco", so a hash copied
from a device must work (doc: "Password Hashes"). The daemon delays every
FAIL by a second or more, so tests send their failing requests in parallel.
"""

import os
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from tactest import LINUX, DaemonTestCase, Stub, features, prefix, tacacs

BANNER = "User Access Verification\n\n"
METH_LOCAL = 5      # authen_method "local" of RFC 8907 5.1


def parallel(fn, cases):
    """fn(*case) for all cases at the same time, the results in the order of cases."""
    with ThreadPoolExecutor(len(cases)) as pool:
        return list(pool.map(lambda case: fn(*case), cases))


HASHES = """
	user md5crypt { password login = crypt $$1$$mERr$$hx5rVt7rPNoS4wqbXKX7m0 password pap = login }
	user type5 { password login = 5 $$1$$mERr$$hx5rVt7rPNoS4wqbXKX7m0 }
	user sha256crypt {
		# openssl passwd -5 -salt saltsalt secret
		password login = crypt $$5$$saltsalt$$0IyaXrmV7.sGNS6tirgqHLqX/G.FBvgkYA.lpPdS5sA
	}
	user type7 { password login = 7 0822455D0A16 }
	user type8 { password login = 8 $$8$$dsYGNam3K1SIJO$$7nv/35M/qr6t.dVc7UY9zrJDWRVqncHub1PE9UlMQFs }
	user type9 { password login = 9 $$9$$nhEmQVczB7dqsO$$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM }
	user asauser {
		# ASA MD5: the password and the first 4 characters of the user name
		password login = asa v/oVCe9Tb.mf0xbN
		password pap = asa v/oVCe9Tb.mf0xbN
	}
	user asapbkdf2 {
		# ASA PBKDF2-SHA512, 5000 rounds, salt bytes 0..15, first 16 bytes of the hash; "=" needs quotes
		password login = pbkdf2 "$$sha512$$5000$$AAECAwQFBgcICQoLDA0ODw==$$Ty7PegTAbntoe4N5wpbEUg=="
	}
	user always { password login = permit password pap = permit }
	user never { password login = deny password pap = deny }
	user refused { password login = error }
	user hashedchap {
		password chap = crypt $$1$$mERr$$hx5rVt7rPNoS4wqbXKX7m0
		password pap = clear cisco
	}
	user enablehash {
		password login = clear loginpw
		enable 15 = 8 $$8$$dsYGNam3K1SIJO$$7nv/35M/qr6t.dVc7UY9zrJDWRVqncHub1PE9UlMQFs
	}
	device asaenable {
		address = 127.0.0.21
		key = tactest
		enable 15 = asa 2KFQnbNIdI.2KYOU
	}
	type6-key = demo
	user type6 {
		# the example of the documentation: "demo" with master key "demo"
		password login = 6 'SeIF^JbTBWUcRIhgP[FW\\`L\\AAB'
	}
	device type6 {
		# type 6 of "devkey6" and "enable6pw" with this master key, made with encrypt_type6() of type6.c
		address = 127.0.0.22
		type6-key = tactest-master
		key = 6 'AgCUffHhe[EgYQEJHSf]BXch[PfAS_'
		enable 15 = 6 'YfJeOHMiQMgh`SMOTRcFO_HHW`WIGCSeK'
	}
	ruleset { rule { script { permit } } }
"""


@unittest.skipUnless("openssl" in features(), "types 6, 8 and 9 and the ASA hashes need a build with OpenSSL")
class PasswordTypes(DaemonTestCase):
    """The password types of "password login", "pap" and "enable" (doc: "password login", "Password Hashes")."""

    CONFIG = HASHES

    # user, password; no type 4: the daemon does not accept the IOS hash of "cisco"
    LOGINS = (("md5crypt", "cisco"), ("type5", "cisco"), ("sha256crypt", "secret"), ("type7", "cisco"),
              ("type8", "cisco"), ("type9", "cisco"), ("asauser", "cisco"), ("asapbkdf2", "cisco"), ("type6", "demo"))

    def login(self, user, password):
        return self.connect().ascii_login(user, password).status_name

    def test_right_password_passes(self):
        for user, password in self.LOGINS:
            with self.subTest(user=user):
                self.assertEqual(self.login(user, password), "PASS")

    def test_wrong_password_fails(self):
        results = parallel(lambda user, password: self.login(user, password + "x"), self.LOGINS)
        self.assertEqual(dict(zip((u for u, _ in self.LOGINS), results)), {u: "FAIL" for u, _ in self.LOGINS})

    def test_pap_with_a_hash(self):
        self.assertTrue(self.connect().pap("md5crypt", "cisco").ok)
        self.assertTrue(self.connect().pap("asauser", "cisco").ok)

    def test_permit_asks_no_password(self):
        r = self.connect().ascii_login("always", [])
        self.assertEqual(r.statuses, ["PASS"], r)
        self.assertTrue(self.connect().pap("always", "anything").ok)

    def test_deny(self):
        results = parallel(lambda f: f("never", "anything").status_name,
                           [(self.connect().ascii_login,), (self.connect().pap,)])
        self.assertEqual(results, ["FAIL", "FAIL"])

    def test_error_answers_with_error(self):
        """Doc: "error" rejects the session with a TACACS+ error status, so the NAS falls back to local."""
        r = self.connect().ascii_login("refused", "anything")
        self.assertEqual((r.status_name, r.server_msg), ("ERROR", "Handling refused."), r)

    def test_chap_with_a_hash_fails(self):
        """CHAP needs the clear text; a hashed CHAP password denies (doc: "password chap")."""
        self.assertEqual(self.connect().chap("hashedchap", "cisco").status_name, "FAIL")
        self.assertTrue(self.connect().pap("hashedchap", "cisco").ok)

    def test_enable_type8(self):
        self.assertEqual(self.connect().enable("cisco", user="enablehash").status_name, "PASS")
        self.assertEqual(self.connect().enable("loginpw", user="enablehash").status_name, "FAIL")

    @unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
    def test_enable_asa_on_the_device(self):
        """The ASA enable hash has no user name in it, so this is the enable request without a user."""
        self.assertEqual(self.connect(source="127.0.0.21").enable("cisco").status_name, "PASS")
        self.assertEqual(self.connect(source="127.0.0.21").enable("wrong").status_name, "FAIL")

    @unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
    def test_type6_device_key_and_enable(self):
        """"type6-key" of the device decrypts its type 6 key and enable password."""
        c = self.connect(source="127.0.0.22", key="devkey6")
        self.assertEqual(c.enable("enable6pw").status_name, "PASS")


NOW = int(time.time())
DAY = 86400

EXPIRY = """
	user soon { password login = clear pw password pap = login valid until = %(soon)d }
	user later { password login = clear pw valid until = %(later)d }
	user expired { password login = clear pw password pap = login valid until = 2001-01-01 }
	user justexpired { password login = clear pw valid until = %(past)d }
	user notyet { password login = clear pw valid from = %(tomorrow)d }
	user current { password login = clear pw valid from = 2001-01-01 valid until = 2099-12-31 }
	ruleset { rule { script { permit } } }
	realm longwarn {
		warning period = 45
		user later { password login = clear pw valid until = %(later)d }
		ruleset { rule { script { permit } } }
	}
	device longwarn {
		address = 127.0.0.41
		key = tactest
		target-realm = longwarn
	}
""" % dict(soon=NOW + 3 * DAY, later=NOW + 30 * DAY, past=NOW - 60, tomorrow=NOW + DAY)

EXPIRES = "This account will expire soon.\n"


class Expiry(DaemonTestCase):
    """"valid until", "valid from" and the expiry warning of "warning period" (doc: "Configuring Expiry Dates")."""

    CONFIG = EXPIRY

    def login(self, user, source=None):
        r = self.connect(source=source).ascii_login(user, "pw")
        return r.status_name, r.server_msg

    def test_warning_within_14_days(self):
        self.assertEqual(self.login("soon"), ("PASS", EXPIRES))

    def test_no_warning_before(self):
        self.assertEqual(self.login("later"), ("PASS", ""))
        self.assertEqual(self.login("current"), ("PASS", ""))

    def test_user_out_of_its_validity_fails(self):
        results = parallel(lambda user: self.login(user)[0], [("expired",), ("justexpired",), ("notyet",)])
        self.assertEqual(results, ["FAIL", "FAIL", "FAIL"])
        self.wait_log("authentication", "expired\ttty0\t127.0.0.1\tshell login failed (expired)")

    def test_pap(self):
        self.assertTrue(self.connect().pap("soon", "pw").ok)
        self.assertEqual(self.connect().pap("expired", "pw").status_name, "FAIL")

    @unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
    def test_warning_period_of_the_realm(self):
        self.assertEqual(self.login("later", source="127.0.0.41"), ("PASS", EXPIRES))


MESSAGES = """
	realm strict {
		acl longpw { if (password =~ /^......../) permit deny }
		password acl = longpw
		user shortpw { password login = clear pw }
		ruleset { rule { script { permit } } }
	}
	realm lab {
		message USERNAME = "Lab login: "
		message PASSWORD = "Lab secret: "
		message PASSWORD_INCORRECT = "Lab secret wrong."
		device labdev {
			address = 127.0.0.0/8
			key = tactest
		}
		user labuser { password login = clear pw }
		ruleset { rule { script { permit } } }
	}
	device msgdev {
		address = 127.0.0.31
		key = tactest
		password max-attempts = 2
		anonymous-enable = deny
		message USER_ACCESS_VERIFICATION = "Authorized users only"
		message USERNAME = "Login: "
		message PASSWORD = "Secret: "
		message PASSWORD_INCORRECT = "Wrong secret."
		message ACCOUNT_EXPIRES = "Your account expires in 3 days."
		message PERMISSION_DENIED = "No enable for you."
		message ENABLE_PASSWORD = "Enable secret: "
		message DENIED_BY_ACL = "Blocked by policy."
		script { if (user == blocked) deny }
	}
	device strictdev {
		address = 127.0.0.33
		key = tactest
		target-realm = strict
		message PASSWORD_MINREQ = "Use eight characters or more."
	}
	user alice {
		password login = clear pw
		enable 15 = clear enablepw
	}
	user soon { password login = clear pw valid until = %(soon)d }
	user blocked { password login = clear pw }
	ruleset { rule { script { permit } } }
""" % dict(soon=NOW + 3 * DAY)

MSG_BANNER = "Authorized users only\n\n"


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class Messages(DaemonTestCase):
    """"message <ID> = ..." of a device or a realm replaces that text in the replies (doc: "User Messages")."""

    CONFIG = MESSAGES
    LISTEN = {"lab": "realm = lab"}

    def connect_msgdev(self):
        return self.connect(source="127.0.0.31")

    def test_banner_and_prompts(self):
        r = self.connect_msgdev().ascii_login("alice", "pw", user_in_start=False)
        self.assertEqual(r.prompts, [MSG_BANNER + "Login: ", "Secret: "], r)
        self.assertTrue(r.ok, r)

    def test_password_incorrect(self):
        r = self.connect_msgdev().ascii_login("alice", ["bad", "bad2"])
        self.assertEqual(r.prompts, [MSG_BANNER + "Secret: ", "Wrong secret.\nSecret: "], r)
        self.assertEqual((r.status_name, r.server_msg), ("FAIL", "Wrong secret.\n"), r)

    def test_account_expires(self):
        r = self.connect_msgdev().ascii_login("soon", "pw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "Your account expires in 3 days.\n"), r)

    def test_permission_denied(self):
        r = self.connect_msgdev().enable("wrong", user="alice")
        self.assertEqual(r.prompts, ["Secret: "], r)
        self.assertEqual((r.status_name, r.server_msg), ("FAIL", "No enable for you."), r)

    def test_enable_password(self):
        """With "anonymous-enable = deny" an enable without a user logs the user in first, then asks ENABLE_PASSWORD."""
        s = self.connect_msgdev().session()
        first = s.start(user="", service=tacacs.AUTHEN_SVC_ENABLE, priv_lvl=15)
        r = s.dialog(first, {"GETUSER": ["alice"], "GETPASS": ["pw", "enablepw"]})
        self.assertEqual(r.prompts, ["Login: ", MSG_BANNER + "Secret: ", "Enable secret: "], r)
        self.assertTrue(r.ok, r)

    def test_denied_by_acl(self):
        r = self.connect_msgdev().author("blocked", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.data), ("FAIL", b"Blocked by policy."), r)

    def test_password_minreq(self):
        r = self.connect(source="127.0.0.33").ascii_login("shortpw", "pw")
        self.assertEqual((r.status_name, r.server_msg), ("FAIL", "Use eight characters or more.\n"), r)

    def test_realm_messages(self):
        """The realm of the listener ("realm = lab") sets the messages of its devices."""
        r = self.connect(listener="lab").ascii_login("labuser", "bad", user_in_start=False)
        self.assertEqual(r.prompts, [BANNER + "Lab login: ", "Lab secret: "], r)
        self.assertEqual((r.status_name, r.server_msg), ("FAIL", "Lab secret wrong.\n"), r)
        self.assertTrue(self.connect(listener="lab").ascii_login("labuser", "pw").ok)

    def test_other_devices_keep_the_defaults(self):
        r = self.connect().ascii_login("alice", "bad", user_in_start=False)
        self.assertEqual(r.prompts, [BANNER + "Username: ", "Password: "], r)
        self.assertEqual(r.server_msg, "Password incorrect.\n")


ENABLE = """
	device anon {
		address = 127.0.0.51
		key = tactest
		anonymous-enable = deny
	}
	device augmented {
		address = 127.0.0.52
		key = tactest
		augmented-enable = permit
	}
	device devenable {
		address = 127.0.0.53
		key = tactest
		enable 15 = clear devicepw
	}
	user login { password login = clear loginpw enable = login }
	user permitted { password login = clear loginpw enable = permit }
	user plain { password login = clear loginpw }
	user denied { password login = clear loginpw enable = deny }
	user levels {
		password login = clear loginpw
		enable 7 = clear level7pw
		enable 15 = clear level15pw
	}
	ruleset { rule { script { permit } } }
"""


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class Enable(DaemonTestCase):
    """"enable" of a user and a device, "anonymous-enable", "augmented-enable" (doc: "enable", "Authentication")."""

    CONFIG = ENABLE

    def enable(self, password, user, source=None, priv_lvl=15):
        return self.connect(source=source).enable(password, user=user, priv_lvl=priv_lvl)

    def anonymous(self, source, user, passwords):
        """Enable START without a user; answer GETUSER with user."""
        s = self.connect(source=source).session()
        first = s.start(user="", service=tacacs.AUTHEN_SVC_ENABLE, priv_lvl=15)
        return s.dialog(first, {"GETUSER": [user], "GETPASS": passwords})

    def test_enable_with_the_login_password(self):
        self.assertEqual(self.enable("loginpw", "login").statuses, ["GETPASS", "PASS"])
        r = self.enable("wrong", "login")
        self.assertEqual((r.status_name, r.server_msg), ("FAIL", "Permission denied."), r)

    def test_enable_permit_asks_no_password(self):
        self.assertEqual(self.enable("unused", "permitted").statuses, ["PASS"])

    def test_enable_deny(self):
        self.assertEqual(self.enable("loginpw", "denied").status_name, "FAIL")

    def test_privilege_levels(self):
        """A level without a password of its own takes the next higher one."""
        cases = [("level7pw", 7), ("level7pw", 3), ("level15pw", 7), ("level7pw", 15)]
        results = parallel(lambda password, level: self.enable(password, "levels", priv_lvl=level).status_name, cases)
        self.assertEqual(results, ["PASS", "PASS", "FAIL", "FAIL"])

    def test_user_enable_before_device_enable(self):
        self.assertTrue(self.enable("level15pw", "levels", "127.0.0.53").ok)
        self.assertEqual(self.enable("devicepw", "levels", "127.0.0.53").status_name, "FAIL")
        self.assertTrue(self.enable("devicepw", "plain", "127.0.0.53").ok)

    def test_anonymous_enable_deny_asks_for_the_user(self):
        r = self.anonymous("127.0.0.51", "levels", ["loginpw", "level15pw"])
        self.assertEqual(r.statuses, ["GETUSER", "GETPASS", "GETPASS", "PASS"], r)
        self.assertEqual(r.prompts, ["Username: ", BANNER + "Password: ", "Enable Password: "], r)
        r = self.anonymous("127.0.0.51", "permitted", ["loginpw"])
        self.assertEqual(r.statuses, ["GETUSER", "GETPASS", "PASS"], r)

    def test_anonymous_enable_deny_wrong_login_password(self):
        r = self.anonymous("127.0.0.51", "levels", ["level15pw"])
        self.assertEqual((r.statuses, r.server_msg), (["GETUSER", "GETPASS", "FAIL"], "Password incorrect.\n"), r)

    def test_anonymous_enable_unset(self):
        """Without the setting the daemon asks for the enable password only."""
        r = self.anonymous("127.0.0.1", "levels", ["level15pw"])
        self.assertEqual(r.statuses, ["GETPASS", "FAIL"], r)

    def test_augmented_enable(self):
        """User "$enable$", then "<user> <login password>" at the prompt; the user needs "enable = login"."""
        cases = [("login loginpw", "127.0.0.52"), ("login wrong", "127.0.0.52"), ("levels loginpw", "127.0.0.52"),
                 ("login loginpw", "127.0.0.1")]
        results = parallel(lambda password, source: self.enable(password, "$enable$", source).status_name, cases)
        self.assertEqual(results, ["PASS", "FAIL", "FAIL", "FAIL"])


ATTRIBUTES = """
	device motd {
		address = 127.0.0.61
		key = tactest
		motd banner = "Authorized use only.\\n"
	}
	device tagged {
		address = 127.0.0.63
		key = tactest
	}
	device devtagged {
		address = 127.0.0.67
		key = tactest
		tag = dev
	}
	device trusting {
		address = 127.0.0.64
		key = tactest
		permit if-authenticated = yes
	}
	device rounds {
		address = 127.0.0.65
		key = tactest
		password max-attempts = 5
		max-rounds = 2
	}
	device retries {
		address = 127.0.0.66
		key = tactest
		password max-attempts = 2
	}
	profile quiet { hushlogin = yes script { permit } }
	user alice { password login = clear pw password pap = login }
	user hushed { password login = clear pw hushlogin = yes }
	user quietprofile { password login = clear pw profile = quiet }
	user opsuser { password pap = clear pw tag = ops }
	user devuser { password pap = clear pw tag = dev }
	ruleset {
		rule ops { script { if (device == tagged) { if (user.tag == ops) permit deny } } }
		rule same-tag { script { if (device == devtagged) { if (user.tag == device.tag) permit deny } } }
		rule others { script { permit } }
	}
"""


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class UserAttributes(DaemonTestCase):
    """"hushlogin", "user.tag", "permit if-authenticated", "password max-attempts", "max-rounds"."""

    CONFIG = ATTRIBUTES

    def test_motd_without_hushlogin(self):
        r = self.connect(source="127.0.0.61").ascii_login("alice", "pw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "Authorized use only.\n"), r)

    def test_hushlogin_hides_the_motd(self):
        for user in ("hushed", "quietprofile"):
            with self.subTest(user=user):
                r = self.connect(source="127.0.0.61").ascii_login(user, "pw")
                self.assertEqual((r.status_name, r.server_msg), ("PASS", ""), r)

    def test_user_tag(self):
        cases = [("opsuser", "127.0.0.63"), ("devuser", "127.0.0.63"), ("alice", "127.0.0.63"),
                 ("devuser", "127.0.0.67"), ("opsuser", "127.0.0.67")]
        results = parallel(lambda user, source: self.connect(source=source).pap(user, "pw").status_name, cases)
        self.assertEqual(results, ["PASS", "FAIL", "FAIL", "PASS", "FAIL"])

    def test_permit_if_authenticated(self):
        """An unknown user that the NAS authenticated itself (method "local") is authorized."""
        args = ["service=shell", "cmd="]
        trusting = self.connect(source="127.0.0.64")
        self.assertEqual(trusting.author("nobody", args, authen_method=METH_LOCAL).status_name, "PASS_ADD")
        self.assertEqual(trusting.author("nobody", args).status_name, "FAIL")
        self.assertEqual(self.connect().author("nobody", args, authen_method=METH_LOCAL).status_name, "FAIL")

    def test_max_attempts(self):
        r = self.connect(source="127.0.0.66").ascii_login("alice", ["bad", "pw"])
        self.assertEqual(r.statuses, ["GETPASS", "GETPASS", "PASS"], r)
        r = self.connect(source="127.0.0.66").ascii_login("alice", ["bad", "bad2"])
        self.assertEqual((r.statuses, r.server_msg), (["GETPASS", "GETPASS", "FAIL"], "Password incorrect.\n"), r)

    def test_retry_with_the_same_password(self):
        """The daemon does not check a repeated wrong password again (it protects backend lockout counters)."""
        r = self.connect(source="127.0.0.66").ascii_login("alice", ["bad", "bad"])
        self.assertEqual(r.status_name, "FAIL", r)
        self.wait_log("authentication", "shell login failed (retry with identical password)")

    def test_max_rounds(self):
        """"max-rounds = 2": a START and one CONTINUE; the daemon ends the session at the next packet."""
        self.assertTrue(self.connect(source="127.0.0.65").ascii_login("alice", "pw").ok)
        s = self.connect(source="127.0.0.65").session()
        self.assertEqual(s.start(user="alice").status_name, "GETPASS")
        self.assertEqual(s.cont("bad").status_name, "GETPASS")
        try:
            status = s.cont("pw").status_name
        except tacacs.Closed:
            status = "closed"
        self.assertIn(status, ("ERROR", "closed"))


REWRITE = """
	rewrite shared-account {
		rewrite /^(admin|root)$$/ shared
	}
	device rewriting {
		address = 127.0.0.62
		key = tactest
		script { rewrite user = shared-account }
	}
	user shared { password login = clear sharedpw password pap = login rewritten-only }
	user alice { password login = clear pw password pap = login }
	ruleset { rule { script { permit } } }
"""


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
@unittest.skipUnless("pcre2" in features(), "rewrite needs PCRE2")
class RewrittenOnly(DaemonTestCase):
    """"rewritten-only": the user exists only as the target of a rewrite (doc: "Rewriting User Names")."""

    CONFIG = REWRITE

    def test_rewritten_names_log_in(self):
        self.assertTrue(self.connect(source="127.0.0.62").ascii_login("admin", "sharedpw").ok)
        self.assertTrue(self.connect(source="127.0.0.62").pap("root", "sharedpw").ok)
        self.assertTrue(self.connect(source="127.0.0.62").pap("alice", "pw").ok)

    def test_own_name_fails(self):
        logins = [(self.connect(source="127.0.0.62").ascii_login,), (self.connect(source="127.0.0.62").pap,),
                  (self.connect().pap,)]
        self.assertEqual(parallel(lambda f: f("shared", "sharedpw").status_name, logins), ["FAIL", "FAIL", "FAIL"])


CHPASS = Stub.module(childs=(1, 1)) + """
	user backend = mavis
	login backend = mavis chpass
	device chmsg {
		address = 127.0.0.71
		key = tactest
		message PASSWORD_CHANGE_DIALOG = "Change your password now."
		message PASSWORD_OLD = "Current: "
		message PASSWORD_NEW = "Next: "
		message PASSWORD_AGAIN = "Next again: "
		message PASSWORD_NOMATCH = "No match."
		message PASSWORD_ABORT = "Stopped."
		message PASSWORD_CHANGED = "Changed."
		message CHANGE_PASSWORD = "Your password is too old."
	}
	ruleset { rule { script { permit } } }
"""


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class ChpassDialog(DaemonTestCase):
    """"login backend = mavis chpass": an empty password starts the password change dialog (doc: "chpass")."""

    CONFIG = CHPASS

    def setUp(self):
        super().setUp()
        self.stub = Stub(self.daemon)
        self.stub.set(users={"alice": {"password": "old", "new_password": "new"},
                             "bob": {"password": "old", "mustchange": True, "new_password": "new"}})

    def change(self, user, password, data, source="127.0.0.1"):
        return self.connect(source=source).ascii_login(user, password, data=data)

    def chpw(self, dialog):
        """Run dialog(); return (result, new password right) of each CHPW request it sent."""
        before = self.stub.count(type="CHPW")
        reply = dialog()
        return reply, [(e["result"], e.get("new_password")) for e in self.stub.requests(type="CHPW")[before:]]

    def test_empty_password_starts_the_dialog(self):
        r, chpw = self.chpw(lambda: self.change("alice", "", ["old", "new", "new"]))
        self.assertEqual(r.prompts, [BANNER + "Password: ", "Entering password change dialog\n\nOld password: ",
                                     "New password: ", "Retype new password: "], r)
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "Password change succeeded."), r)
        self.assertEqual(chpw, [("ACK", True)])

    def test_messages_of_the_dialog(self):
        r, chpw = self.chpw(lambda: self.change("alice", "", ["old", "new", "new"], source="127.0.0.71"))
        self.assertEqual(r.prompts, [BANNER + "Password: ", "Change your password now.\n\nCurrent: ", "Next: ",
                                     "Next again: "], r)
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "Changed."), r)
        self.assertEqual(chpw, [("ACK", True)])

    def test_new_passwords_differ(self):
        r, chpw = self.chpw(lambda: self.change("alice", "", ["old", "new", "other"], source="127.0.0.71"))
        self.assertEqual(r.status_name, "FAIL", r)
        self.assertTrue(r.server_msg.startswith("No match."), r)
        self.assertEqual(chpw, [])

    def test_empty_new_password_aborts(self):
        r, chpw = self.chpw(lambda: self.change("alice", "", ["old", ""], source="127.0.0.71"))
        self.assertEqual((r.status_name, r.server_msg), ("FAIL", "Stopped.\n"), r)
        self.assertEqual(chpw, [])

    def test_backend_asks_for_a_change(self):
        r, chpw = self.chpw(lambda: self.change("bob", "old", ["new", "new"], source="127.0.0.71"))
        self.assertEqual(r.prompts, [BANNER + "Password: ", "Your password is too old.\nNext: ", "Next again: "], r)
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "Changed."), r)
        self.assertEqual(chpw, [("ACK", True)])

    def test_change_password_request(self):
        """The TACACS+ CHPASS action of RFC 8907 5.4.4.3."""
        s = self.connect(source="127.0.0.71").session()

        def dialog():
            first = s.start(user="alice", action=2)
            return s.dialog(first, {"GETDATA": ["old"], "GETPASS": ["new", "new"]})
        r, chpw = self.chpw(dialog)
        self.assertEqual(r.prompts, ["Current: ", "Next: ", "Next again: "], r)
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "Changed."), r)
        self.assertEqual(chpw, [("ACK", True)])


# a MAVIS backend for what the stub does not answer: a challenge (CHAL) and a password expiry date
BACKEND = """
import sys
sys.path.insert(0, sys.argv[1])
import mavis as M

EXPIRY = {"expiring": %(soon)d, "notexpiring": %(later)d}
while True:
	d = M.Mavis()
	user, tactype = d.av_pairs.get(M.AV_A_USER), d.av_pairs.get(M.AV_A_TACTYPE)
	password = d.av_pairs.get(M.AV_A_PASSWORD)
	if user == "otpuser" and tactype == M.AV_V_TACTYPE_CHAL:
		d.av_pairs[M.AV_A_CHALLENGE] = "otp-md5 99 tactest"
		d.write(M.MAVIS_FINAL, M.AV_V_RESULT_OK, None)
	elif user == "otpuser" and tactype == M.AV_V_TACTYPE_AUTH:
		d.write(M.MAVIS_FINAL, M.AV_V_RESULT_OK if password == "response99" else M.AV_V_RESULT_FAIL, None)
	elif user in EXPIRY and tactype == M.AV_V_TACTYPE_AUTH:
		d.set_expiry(EXPIRY[user])
		d.write(M.MAVIS_FINAL, M.AV_V_RESULT_OK if password == "pw" else M.AV_V_RESULT_FAIL, None)
	elif user in EXPIRY or user == "otpuser":
		d.write(M.MAVIS_FINAL, M.AV_V_RESULT_OK, None)
	else:
		d.write(M.MAVIS_DOWN, M.AV_V_RESULT_NOTFOUND, None)
"""


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class ChallengeAndExpiry(DaemonTestCase):
    """"login backend = mavis chalresp [noecho]" and "password expiry warning", with BACKEND; a daemon per test."""

    CONFIG = None

    def start(self, login_backend):
        script = self.scratch_file("backend.py", BACKEND % dict(soon=NOW + 2 * DAY, later=NOW + 30 * DAY))
        return self.start_daemon("""
	mavis module = external {
		exec = "%s" "%s" "-u" "%s" "%s"
		childs min = 1
		childs max = 1
	}
	user backend = mavis
	login backend = %s
	password expiry warning = 7d
	device banner {
		address = 127.0.0.81
		key = tactest
		welcome banner = "Welcome.\\n"
		message RESPONSE = "OTP: "
	}
	ruleset { rule { script { permit } } }
""" % (sys.executable, sys.executable, script, os.path.join(prefix(), "lib", "mavis"), login_backend))

    def test_challenge_response(self):
        d = self.start("mavis chalresp")
        r = self.connect(daemon=d, source="127.0.0.81").ascii_login("otpuser", "response99")
        self.assertIn("otp-md5 99 tactest", r.prompts[0], r)
        self.assertIn("OTP: ", r.prompts[0], r)
        self.assertFalse(r.replies[0].noecho, r)
        self.assertTrue(r.ok, r)
        self.assertEqual(self.connect(daemon=d, source="127.0.0.81").ascii_login("otpuser", "bad").status_name, "FAIL")

    def test_challenge_response_noecho(self):
        d = self.start("mavis chalresp noecho")
        r = self.connect(daemon=d, source="127.0.0.81").ascii_login("otpuser", "response99")
        self.assertIn("otp-md5 99 tactest", r.prompts[0], r)
        self.assertTrue(r.replies[0].noecho, r)
        self.assertTrue(r.ok, r)

    def test_password_expiry_warning(self):
        """The backend sends the expiry date of the password; within "password expiry warning" the user gets told."""
        d = self.start("mavis")
        r = self.connect(daemon=d).ascii_login("expiring", "pw")
        expires = time.strftime("%c", time.localtime(NOW + 2 * DAY))
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "Password will expire on %s.\n" % expires), r)
        r = self.connect(daemon=d).ascii_login("notexpiring", "pw")
        self.assertEqual((r.status_name, r.server_msg), ("PASS", ""), r)


if __name__ == "__main__":
    unittest.main()
