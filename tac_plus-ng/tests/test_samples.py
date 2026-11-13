"""The shipped samples as running daemons: the whole file parses, and its users get the answers it documents.

test_parse.py checks only that a sample parses, and most samples stop at
the first path of an installed system. Here each sample runs with the
fewest edits that make it start in a scratch directory (sample.template()):
the listener, the log files, and helper programs replaced by the MAVIS
stub. Everything else is the configuration a user copies.

A real helper from the tree runs where it can: the Perl MAVIS scripts
with the installed Mavis.pm. Certificates come from tactest.tls. The
samples keep the MAVIS cache (120 s), so a test uses user names of its
own when a cached answer could hide what it checks.
"""

import hashlib
import os
import shutil
import ssl
import struct
import time
import unittest

from tactest import (LINUX, SOURCE, Closed, DaemonTestCase, ProtocolError, Stub, features, prefix, radius, sample,
                     tacacs, tls)

STUB_EXEC = Stub.module().split("\n")[1:-2]     # the exec and setenv lines, without the "mavis module" block
LISTENER = "listen { address = $address port = $port }\n$spawnd"
MAVIS_LIB = os.path.join(prefix(), "lib", "mavis")
PERL = shutil.which("perl")
HAVE_PERL = PERL is not None and os.path.exists(os.path.join(MAVIS_LIB, "Mavis.pm"))
HAVE_TLS = tls.openssl_available() and "openssl" in features()
DICTIONARY = '"%s"' % sample.path("sample/radius-dict.cfg")
DEMO_DATABASE = '"%s" "perl" "-I%s" "%s"' % (PERL, MAVIS_LIB, os.path.join(SOURCE, "mavis", "perl",
                                                                          "mavis_tacplus-ng-demo-database.pl"))

# RADIUS attributes (RFC 2865, 2866) and the Cisco vendor
SERVICE_TYPE = 6
VENDOR_SPECIFIC = 26
ACCOUNTING_REQUEST = 4
ACCT_STATUS_TYPE = 40
ACCT_SESSION_ID = 44
CISCO = 9
ADMINISTRATIVE_USER = (SERVICE_TYPE, struct.pack("!I", 6))


def log_edits(names):
    """{sample path: log name}: the log destinations of a sample into the scratch directory."""
    return [("destination = %s" % path, 'destination = "$tmp/%s.log"' % name) for path, name in names.items()]


RADIUS_LOGS = log_edits({"/tmp/tac/access.log": "access", "/tmp/tac/author.log": "author", "/tmp/tac/acct.log": "acct",
                         "/tmp/rad/access.log": "rad-access", "/tmp/rad/acct.log": "rad-acct", "/tmp/conn.log": "conn"})


def cisco_avpair(value):
    return (VENDOR_SPECIFIC, struct.pack("!IBB", CISCO, 1, len(value) + 2) + value.encode())


def cisco_avpairs(reply):
    """The Cisco-AVPair values of a RADIUS reply, in order."""
    out = []
    for v in reply.get(VENDOR_SPECIFIC):
        if struct.unpack("!I", v[:4])[0] == CISCO and v[4] == 1:
            out.append(v[6:4 + v[5]].decode())
    return out


def dacl_name(reply):
    """The ACL name of the ACS:CiscoSecure-Defined-ACL pair, e.g. "#ACSACL#demoacl-f35b979e"."""
    (pair,) = [p for p in cisco_avpairs(reply) if p.startswith("ACS:CiscoSecure-Defined-ACL=")]
    return pair.split("=", 1)[1]


def dacl_download(client, name):
    """The request of a Cisco device for the entries of a downloadable ACL."""
    return client.access_request(name, "", attributes=[cisco_avpair("aaa:event=acl-download")],
                                 message_authenticator=True)


def accounting_start(client, user, session_id):
    """Accounting-Request (RFC 2866): the Request Authenticator is MD5 over the packet with zeros, and the secret."""
    req = radius.Packet(ACCOUNTING_REQUEST, authenticator=bytes(16),
                        attributes=[(radius.USER_NAME, user), (ACCT_STATUS_TYPE, struct.pack("!I", 1)),
                                    (ACCT_SESSION_ID, session_id)])
    req.authenticator = hashlib.md5(req.encode() + client.secret).digest()
    return client.exchange(req)


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


def sunday():
    return time.localtime().tm_wday == 6


class SimpleSample(DaemonTestCase):
    """sample/tac_plus-ng-simple.cfg: a user profile, a profile in the user, a named ACL as script."""

    KEY = "demo"
    TEMPLATE = sample.template("sample/tac_plus-ng-simple.cfg", [("listen { port = 4949 }", LISTENER)])

    def test_admin_profile(self):
        self.assertEqual(self.connect().pap("demo", "demo").status_name, "PASS")
        self.assertEqual(self.connect().pap("demo", "wrong").status_name, "FAIL")
        r = self.connect().author("demo", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]))
        r = self.connect().author("demo", ["service=shell", "cmd=show", "cmd-arg=running-config"])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", []))
        self.assertEqual(self.connect().author("demo", ["service=ppp", "protocol=ip"]).status_name, "FAIL")

    def test_enable_15_with_the_login_password(self):
        self.assertEqual(self.connect().enable("demo", user="demo").status_name, "PASS")
        self.assertEqual(self.connect().enable("secret", user="demo").status_name, "FAIL")

    def test_profile_acl_of_the_user_checks_the_client_address(self):
        """demo2: "net localhost" is 127.0.0.1, the acl denies other clients and Sundays."""
        r = self.connect().author("demo2", ["service=shell", "cmd="], rem_addr="10.1.1.1")
        self.assertEqual(r.status_name, "FAIL")
        self.assertEqual(self.connect().pap("demo2", "demo", rem_addr="10.1.1.1").status_name, "FAIL")
        was_sunday = sunday()
        r = self.connect().author("demo2", ["service=shell", "cmd="], rem_addr="127.0.0.1")
        if sunday() != was_sunday:
            self.skipTest("the day changed during the test")
        if was_sunday:
            self.assertEqual(r.status_name, "FAIL")
        else:
            # "add" returns an optional AV pair the client did not ask for
            self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15", "demoattribute*ignore"]))

    def test_profile_with_a_named_acl_as_script(self):
        r = self.connect().author("demo3", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]))
        self.assertEqual(self.connect().author("demo3", ["service=ppp", "protocol=ip"]).status_name, "FAIL")


class RadiusSample(DaemonTestCase):
    """sample/tac_plus-ng-radius.cfg: one profile for TACACS+ and RADIUS, a DACL, RADIUS accounting."""

    KEY = "demo"
    UDP = True
    LISTEN = {"acct": "protocol = UDP flag = accounting"}
    TEMPLATE = sample.template("sample/tac_plus-ng-radius.cfg", [
        ("listen { port = 4949 } # TACACS+, non-standart port\n"
         "\tlisten { port = 1812 protocol = UDP } # RADIUS\n"
         "\tlisten { port = 1813 protocol = UDP flag = accounting } # RADIUS", LISTENER),
        ('"$CONFDIR/radius-dict.cfg"', DICTIONARY)] + RADIUS_LOGS)

    def access(self, user, password, attributes=()):
        return self.radius("demo").access_request(user, password, attributes=attributes, message_authenticator=True)

    def test_tacacs_shell(self):
        for user in ("demo", "demo2", "demo3"):
            r = self.connect().author(user, ["service=shell", "cmd="])
            self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]), user)
        self.wait_log("author", "\tdemo3\ttty0\t127.0.0.1\tadmin\tpermit\tshell\t")

    def test_radius_user_gets_priv_lvl_7_and_the_dacl(self):
        r = self.access("demo", "demo")
        self.assertEqual(r.code_name, "Access-Accept", r)
        pairs = cisco_avpairs(r)
        self.assertEqual(pairs[0], "shell:priv-lvl=7")
        self.assertRegex(dacl_name(r), r"^#ACSACL#demoacl-[0-9a-f]{8}$")
        self.assertEqual(len(pairs), 2, pairs)
        self.wait_log("rad-access", "\tradius pap login succeeded\tUser-Name=demo ")

    def test_administrative_user_gets_priv_lvl_15(self):
        r = self.access("demo", "demo", [ADMINISTRATIVE_USER])
        self.assertEqual((r.code_name, cisco_avpairs(r)), ("Access-Accept", ["shell:priv-lvl=15"]))

    def test_ruleset_gives_demo3_the_admin_profile(self):
        r = self.access("demo3", "demo")
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(cisco_avpairs(r)[0], "shell:priv-lvl=7")

    def test_profile_without_a_radius_rule_rejects(self):
        r = self.access("demo2", "demo")
        self.assertEqual((r.code_name, r.get(radius.REPLY_MESSAGE)), ("Access-Reject", [b"Denied by ACL"]))

    def test_wrong_password_rejects(self):
        self.assertEqual(self.access("demo", "wrong").code_name, "Access-Reject")

    @unittest.skipUnless("openssl" in features(), "the Message-Authenticator needs a build with OpenSSL")
    def test_reply_has_a_message_authenticator(self):
        self.assertTrue(self.access("demo", "demo").message_authenticator, "no valid Message-Authenticator in the reply")

    @unittest.skipUnless("openssl" in features(), "the Message-Authenticator needs a build with OpenSSL")
    def test_request_without_message_authenticator_gets_no_answer(self):
        """No "bug compatibility = 32" in the sample: the BLAST attack mitigation is on."""
        with self.assertRaises(TimeoutError):
            self.radius("demo", timeout=2.0).access_request("demo", "demo")

    def test_dacl_download(self):
        r = dacl_download(self.radius("demo"), dacl_name(self.access("demo", "demo")))
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(cisco_avpairs(r), ["ip:inacl#1=deny ip host 10.0.0.0 any", "ip:inacl#2=permit ip any any"])
        self.wait_log("rad-access", "\tdemoacl\t\t\t\tdacl request succeeded\t")

    def test_accounting_listener(self):
        r = accounting_start(self.radius("demo", listener="acct"), "demo", "acct-sample-1")
        self.assertEqual(r.code_name, "Accounting-Response", r)
        self.wait_log("rad-acct", "\tdemo\t\t\tstart\t\tUser-Name=demo Acct-Status-Type=Start "
                                  "Acct-Session-Id=acct-sample-1\n")


@unittest.skipUnless(HAVE_PERL, "needs perl and the installed Mavis.pm")
class RadiusMavisSample(DaemonTestCase):
    """sample/tac_plus-ng-radius-mavis.cfg: devices, users and DACLs from mavis_tacplus-ng-demo-database.pl.

    The script accepts every user with the password "demo"; it gives the
    device a key, a banner and tags, and the user a read-only profile.
    """

    KEY = "demo"
    UDP = True
    LISTEN = {"udp2": "protocol = UDP"}
    TEMPLATE = sample.template("sample/tac_plus-ng-radius-mavis.cfg", [
        ("listen { port = 4949 } # TACACS+, non-standart port\n"
         "\tlisten { port = 1812 protocol = UDP } # RADIUS\n"
         "\tlisten { port = 1813 protocol = UDP } # RADIUS", LISTENER),
        ('"$CONFDIR/radius-dict.cfg"', DICTIONARY),
        ("exec = mavis/perl/mavis_tacplus-ng-demo-database.pl", "exec = " + DEMO_DATABASE)] + RADIUS_LOGS)

    def test_device_banner_from_the_backend(self):
        r = self.connect().ascii_login("alice", "demo")
        self.assertEqual((r.status_name, r.prompts), ("PASS", ["Hi! :-)Password: "]))
        r = self.connect().ascii_login("alice", "wrong")
        self.assertEqual((r.status_name, r.server_msg), ("FAIL", "Password incorrect.\n"))

    def test_read_only_profile_from_the_backend(self):
        r = self.connect().author("bob", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]))
        for cmd in ("show", "ping", "traceroute"):
            r = self.connect().author("bob", ["service=shell", "cmd=%s" % cmd, "cmd-arg=x"])
            self.assertEqual(r.status_name, "PASS_ADD", cmd)
        r = self.connect().author("bob", ["service=shell", "cmd=configure", "cmd-arg=terminal"])
        self.assertEqual(r.status_name, "FAIL")
        self.assertEqual(self.connect().author("bob", ["service=ppp", "protocol=ip"]).status_name, "FAIL")
        self.wait_log("author", "\tbob\ttty0\t127.0.0.1\tbob\tdeny\tshell\tconfigure terminal\n")

    def test_radius_profile_from_the_backend(self):
        r = self.radius("demo").access_request("carol", "demo", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(cisco_avpairs(r)[0], "shell:priv-lvl=15")
        # the backend DACL has no version in the configuration, so the daemon uses the time
        self.assertRegex(dacl_name(r), r"^#ACSACL#demoacl-[0-9a-f]{8}$")
        r = self.radius("demo").access_request("carol", "wrong", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Reject")

    def test_dacl_from_the_backend(self):
        r = dacl_download(self.radius("demo"), "#ACSACL#demoacl-00000000")
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(cisco_avpairs(r), ["ip:inacl#1=permit ip host 1.2.3.4 host 4.5.6.7",
                                            "ip:inacl#2=permit tcp any any eq 443", "ip:inacl#3=deny ip any any"])

    def test_second_udp_listener_takes_accounting(self):
        r = accounting_start(self.radius("demo", listener="udp2"), "dave", "acct-mavis-1")
        self.assertEqual(r.code_name, "Accounting-Response", r)
        self.wait_log("rad-acct", "\tdave\t\t\tstart\t\t")

    def test_password_change_dialog(self):
        """"login backend = mavis chpass": an empty password starts the dialog; the script wants the old "demo"."""
        r = self.connect().ascii_login("erin", "", data=["demo", "Newpass1", "Newpass1"])
        self.assertEqual(r.prompts, ["Hi! :-)Password: ", "Entering password change dialog\n\nOld password: ",
                                     "New password: ", "Retype new password: "])
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "Password change succeeded."))
        r = self.connect().ascii_login("frank", "", data=["wrong", "Newpass1", "Newpass1"])
        self.assertEqual(r.status_name, "FAIL")
        r = self.connect().ascii_login("grace", "", data=["demo", "Newpass1", "Newpass2"])
        self.assertEqual(r.status_name, "FAIL")
        self.assertTrue(r.server_msg.startswith("Passwords do not match."), r)


@unittest.skipUnless(HAVE_PERL, "needs perl and the installed Mavis.pm")
class DemoDatabaseSample(DaemonTestCase):
    """sample/tac_plus-ng-demo-database.cfg: the device has no key; the backend gives it one."""

    KEY = "demo"
    UDP = True
    TEMPLATE = sample.template("sample/tac_plus-ng-demo-database.cfg", [
        ("listen { port = 4949 }\n\tlisten { port = 1812 protocol = udp }", LISTENER),
        ('include "$CONFDIR/radius-dict.cfg"', "include " + DICTIONARY),
        ('exec = "$CONFDIR/../../mavis/perl/mavis_tacplus-ng-demo-database.pl"', "exec = " + DEMO_DATABASE)])

    def test_key_and_banner_from_the_backend(self):
        r = self.connect().ascii_login("alice", "demo")
        self.assertEqual((r.status_name, r.prompts), ("PASS", ["Hi! :-)Password: "]))
        with self.assertRaises(ProtocolError):
            self.connect(key="other").ascii_login("alice", "demo")

    def test_pap_password_is_the_login_password(self):
        self.assertEqual(self.connect().pap("bob", "demo").status_name, "PASS")
        self.assertEqual(self.connect().pap("bob", "wrong").status_name, "FAIL")

    def test_read_only_profile_from_the_backend(self):
        r = self.connect().author("carol", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]))
        r = self.connect().author("carol", ["service=shell", "cmd=ping", "cmd-arg=192.0.2.1"])
        self.assertEqual(r.status_name, "PASS_ADD")
        self.assertEqual(self.connect().author("carol", ["service=shell", "cmd=reload"]).status_name, "FAIL")

    def test_radius_key_from_the_backend(self):
        r = self.radius("demo").access_request("dave", "demo", message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(cisco_avpairs(r)[0], "shell:priv-lvl=15")
        r = self.radius("demo").access_request("dave", "wrong", message_authenticator=True)
        self.assertEqual((r.code_name, r.get(radius.REPLY_MESSAGE)), ("Access-Reject", [b"Permission denied.\n"]))


class DemoPamSample(DaemonTestCase):
    """sample/tac_plus-ng-demo-pam.cfg: users from the backend (pammavis, here the stub), one rule for all.

    "single process = yes" goes: the harness needs spawnd and a worker.
    """

    KEY = "demo-key"
    TEMPLATE = sample.template("sample/tac_plus-ng-demo-pam.cfg", [
        ("single process = yes   # not suitable for production\n"
         "\tlisten { port = 4949 } # standard port would be 49", LISTENER),
        ("exec = /usr/local/sbin/pammavis pammavis -s sshd", "\n".join(STUB_EXEC))])

    def setUp(self):
        super().setUp()
        self.stub = Stub(self.daemon)
        self.stub.set(users={name: {"password": "pw-" + name} for name in ("alice", "bob", "carol")})

    def test_login_against_the_backend(self):
        r = self.connect().ascii_login("alice", "pw-alice")
        self.assertEqual((r.status_name, r.prompts), ("PASS", ["User Access Verification\n\nPassword: "]))
        self.assertEqual(self.connect().ascii_login("alice", "wrong").status_name, "FAIL")
        self.assertEqual([e["result"] for e in self.stub.requests("AUTH", "alice")], ["ACK", "NAK"])

    def test_pap_password_is_the_login_password(self):
        self.assertEqual(self.connect().pap("bob", "pw-bob").status_name, "PASS")
        self.assertEqual(self.stub.count("AUTH", "bob"), 1)

    def test_rule_gives_the_demo_profile(self):
        r = self.connect().author("carol", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]))
        self.assertEqual(self.connect().author("carol", ["service=ppp", "protocol=ip"]).status_name, "FAIL")

    def test_unknown_user(self):
        self.assertEqual(self.connect().ascii_login("nobody", "pw").status_name, "FAIL")
        self.assertEqual(self.stub.requests("AUTH", "nobody")[0]["result"], "NOTFOUND")


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
@unittest.skipUnless("pcre2" in features(), "the groups filter is a PCRE")
class MultivendorSample(DaemonTestCase):
    """sample/tac_plus-ng-multivendor.cfg: two realms, tagged devices, groups from UNIX group IDs.

    The device addresses move from 10.0.254.0/24 to 127.0.0.0/24. The
    "groups" module sets TACMEMBER from the UNIX groups (GIDS) of the user
    only. The stub sends no GIDS, and a test can't add the host groups
    "engineering" or "helpdesk", so here every user is denied.
    """

    KEY = "demo"
    LISTEN = {"vendor2": "realm = vendor2"}
    TEMPLATE = sample.template("sample/tac_plus-ng-multivendor.cfg", [
        ("listen { port = 4949 realm = vendor1 }\n\tlisten { port = 4950 realm = vendor2 }",
         LISTENER.replace("port = $port", "port = $port realm = vendor1")),
        ("exec = /usr/local/sbin/pammavis pammavis -s ssh", "\n".join(STUB_EXEC)),
        ("address = 10.0.254.0/24", "address = 127.0.0.0/24"),
        ("address = 10.0.254.123", "address = 127.0.0.123"),
        ("address = 10.0.254.125", "address = 127.0.0.125")])

    def test_banner_of_the_parent_device(self):
        Stub(self.daemon).set(users={"alice": {"password": "pw"}})
        for source in ("127.0.0.1", "127.0.0.123", "127.0.0.125"):
            r = self.connect(source=source).ascii_login("alice", "pw")
            self.assertEqual(r.prompts, ["Welcome\nPassword: "], source)

    def test_tacmember_of_the_backend_is_replaced_by_the_unix_groups(self):
        stub = Stub(self.daemon)
        stub.set(users={"eng": {"password": "pw", "member": ["engineering"]}})
        for listener in (None, "vendor2"):
            self.assertEqual(self.connect(listener=listener).ascii_login("eng", "pw").status_name, "FAIL", listener)
        self.assertEqual([e["result"] for e in stub.requests("AUTH", "eng")], ["ACK", "ACK"])


@unittest.skipUnless(HAVE_PERL, "needs perl and the installed Mavis.pm")
class ShadowSample(DaemonTestCase):
    """extra/tac_plus-ng.cfg-shadow: login passwords from mavis_tacplus_shadow.pl and a shadow file.

    The shadow line is the one of the comment in the sample: demo, "demopass", salt "demosalt".
    """

    KEY = "demo"
    TEMPLATE = sample.template("extra/tac_plus-ng.cfg-shadow", [
        ("listen = { port = 49 }", LISTENER.replace("listen {", "listen = {")),
        ('setenv SHADOWFILE = "/whereever/shadow"', 'setenv SHADOWFILE = "$tmp/shadow"'),
        ("exec = /usr/local/lib/mavis/mavis_tacplus_shadow.pl",
         'exec = "%s"' % os.path.join(MAVIS_LIB, "mavis_tacplus_shadow.pl"))])
    HASH = "$1$demosalt$utu9PObWiZWGFDLz4hWJe0"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.write_shadow(int(time.time() // 86400))

    @classmethod
    def write_shadow(cls, lastchange):
        """lastchange 0: the user must change the password at the next login."""
        with open(os.path.join(cls.daemon.tmp, "shadow"), "w") as f:
            f.write("demo:%s:%d:0:99999:7:::\n" % (cls.HASH, lastchange))

    def test_login_with_the_shadow_password(self):
        r = self.connect().ascii_login("demo", "demopass")
        self.assertEqual((r.status_name, r.prompts), ("PASS", ["Welcome\n\nPassword: "]))
        r = self.connect().ascii_login("demo", "wrong")
        self.assertEqual((r.status_name, r.server_msg), ("FAIL", "Password incorrect.\n"))
        self.assertEqual(self.connect().ascii_login("nobody", "demopass").status_name, "FAIL")

    def test_admins_rule(self):
        r = self.connect().author("demo", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]))
        self.assertEqual(self.connect().author("demo", ["service=ppp", "protocol=ip"]).status_name, "FAIL")

    def test_enable_of_the_device(self):
        self.assertEqual(self.connect().enable("secret", user="demo").status_name, "PASS")
        self.assertEqual(self.connect().enable("demopass", user="demo").status_name, "FAIL")

    def test_password_change_at_the_first_login(self):
        self.addCleanup(self.write_shadow, int(time.time() // 86400))
        self.write_shadow(0)
        r = self.connect().ascii_login("demo", "demopass", data=["Newpass1", "Newpass1"])
        self.assertEqual(r.prompts, ["Welcome\n\nPassword: ", "Please change your password.\nNew password: ",
                                     "Retype new password: "])
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "Password change was successful.\n"))
        self.assertEqual(self.connect().ascii_login("demo", "Newpass1").status_name, "PASS")
        self.assertEqual(self.connect().ascii_login("demo", "demopass").status_name, "FAIL")

    def test_password_change_dialog(self):
        self.addCleanup(self.write_shadow, int(time.time() // 86400))
        r = self.connect().ascii_login("demo", "", data=["demopass", "Newpass2", "Newpass2"])
        self.assertEqual(r.prompts[1:], ["Entering password change dialog\n\nOld password: ", "New password: ",
                                         "Retype new password: "])
        self.assertEqual((r.status_name, r.server_msg), ("PASS", "Password change was successful.\n"))
        with open(os.path.join(self.daemon.tmp, "shadow")) as f:
            self.assertNotIn(self.HASH, f.read())
        self.assertEqual(self.connect().ascii_login("demo", "Newpass2").status_name, "PASS")


class TlsSampleCase(DaemonTestCase):
    """A sample with certificates: they come from a CA of the class, so template() runs in setUpClass."""

    @classmethod
    def template(cls):
        raise NotImplementedError

    @classmethod
    def setUpClass(cls):
        cls.ca = tls.CA(cls.__name__ + "-ca")
        try:
            cls.TEMPLATE = cls.template()
            super().setUpClass()
        except Exception:
            cls.ca.remove()
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            super().tearDownClass()
        finally:
            if not cls._failed:
                cls.ca.remove()

    def connect_tls(self, cert, listener="tls"):
        return self.connect(listener=listener, tls=self.ca.context(cert), server_hostname="localhost", timeout=10.0)

    def radsec(self, cert):
        return self.radius("radsec", listener="radsec", tls=self.ca.context(cert))


# the listeners of tac_plus-ng-tls.cfg and tac_plus-ng-radsec.cfg, without the plain TACACS+ one
TLS_LISTENERS = ("\tlisten { port = 2083 tls = yes } \t\t\t# radsec\n"
                 "\tlisten { port = 2083 protocol = UDP tls = yes }\t\t# radius-dtls\n"
                 "\tlisten { port = 1812 protocol = UDP }\t\t\t# radius-udp authc\n"
                 "\tlisten { port = 1813 protocol = UDP flag = accounting } # radius-udp acct\n"
                 "\tlisten { port = 4949 } # TACACS -- should be 49, but binding to a high port\n"
                 "\t\t\t       # doesn't require root privileges\n"
                 "\tlisten { port = 4950 tls = yes }\t# TACACSS -- IANA standard is 300")
TLS_LISTEN = {"radsec": "tls = yes", "dtls": "protocol = UDP tls = yes", "udp": "protocol = UDP",
              "acct": "protocol = UDP flag = accounting", "tls": "tls = yes"}


def democa_edits(ca, chain):
    """The democa files of the sample (sample/democa/Makefile) from the CA of the test."""
    return [("tls cert-file = $CONFDIR/democa/server-chain.pem", 'tls cert-file = "%s"' % chain),
            ("tls key-file = $CONFDIR/democa/server.key", 'tls key-file = "%s"' % ca.server[1]),
            ("tls ca-file = $CONFDIR/democa/root.crt", 'tls ca-file = "%s"' % ca.cert)]


@unittest.skipUnless(HAVE_TLS, "needs the openssl command and a build with OpenSSL")
class TlsSample(TlsSampleCase):
    """sample/tac_plus-ng-tls.cfg: TACACS+ over TLS and TLS-PSK, RADIUS over UDP and TLS, a device by certificate.

    The DTLS listener stays in the configuration; the tests have no DTLS client.
    """

    KEY = "demo"
    LISTEN = dict(TLS_LISTEN, psk="tls = yes tls psk = yes")

    @classmethod
    def template(cls):
        cls.client = cls.ca.issue("client", "/CN=client.demo.local", san="DNS:client.demo.local")
        cls.other = cls.ca.issue("other", "/CN=other.demo.local", san="DNS:other.demo.local")
        chain = cls.ca.path("server-chain.pem")
        with open(chain, "w") as out:
            for name in (cls.ca.server[0], cls.ca.cert):
                with open(name) as f:
                    out.write(f.read())
        return sample.template("sample/tac_plus-ng-tls.cfg", [
            (TLS_LISTENERS + "\n\tlisten { port = 6049 tls = yes tls psk = yes }\t# TACACSS PSK", LISTENER),
            ("include = $CONFDIR/radius-dict.cfg", "include = " + DICTIONARY)] + democa_edits(cls.ca, chain))

    def test_plain_tacacs(self):
        r = self.connect().ascii_login("demo", "demo")
        self.assertEqual((r.status_name, r.prompts), ("PASS", ["Welcome\nPassword: "]))
        r = self.connect().author("demo", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]))
        # the profile ends with "permit": other services too
        self.assertEqual(self.connect().author("demo", ["service=ppp", "protocol=ip"]).status_name, "PASS_ADD")

    def test_certificate_selects_the_device(self):
        r = self.connect_tls(self.client).ascii_login("demo", "demo")
        self.assertEqual((r.status_name, r.prompts), ("PASS", ["Welcome to TLS.\nPassword: "]))
        r = self.connect_tls(self.other).ascii_login("demo", "demo")
        self.assertEqual((r.status_name, r.prompts), ("PASS", ["Welcome\nPassword: "]))

    def test_psk(self):
        sock = tls.PskSocket((self.daemon.address, self.daemon.ports["psk"]), "psk-demo", "0123456789ab", timeout=10.0)
        self.assertEqual(self.connect(sock=sock, timeout=10.0).pap("demo", "demo").status_name, "PASS")
        sock = tls.PskSocket((self.daemon.address, self.daemon.ports["psk"]), "psk-demo", "0123456789ac", timeout=10.0)
        with self.assertRaises(Closed):
            self.connect(sock=sock, timeout=10.0).pap("demo", "demo")

    def test_single_connection(self):
        c = self.connect(single_connect=True)
        for _ in range(2):
            r = c.author("demo", ["service=shell", "cmd="])
            self.assertEqual(r.args, ["priv-lvl=15"])
            self.assertTrue(r.packet.flags & tacacs.FLAG_SINGLE_CONNECT, "no single-connect flag in the reply")

    def test_radius_without_message_authenticator(self):
        """"bug compatibility = 32" accepts a request without Message-Authenticator."""
        r = self.radius("demo", listener="udp").access_request("demo", "demo")
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(self.radius("demo", listener="udp").access_request("demo", "wrong").code_name, "Access-Reject")

    def test_radsec(self):
        self.assertEqual(self.radsec(self.client).access_request("demo", "demo").code_name, "Access-Accept")
        self.assertEqual(self.radsec(self.client).access_request("demo", "wrong").code_name, "Access-Reject")

    def test_accounting_listener(self):
        r = accounting_start(self.radius("demo", listener="acct"), "demo", "acct-tls-1")
        self.assertEqual(r.code_name, "Accounting-Response", r)


@unittest.skipUnless(HAVE_TLS, "needs the openssl command and a build with OpenSSL")
class RadsecSample(TlsSampleCase):
    """sample/tac_plus-ng-radsec.cfg: RADIUS over TLS and UDP, TACACS+ over TLS, one profile for both.

    The DTLS listener stays in the configuration; the tests have no DTLS client.
    """

    KEY = "demo"
    LISTEN = TLS_LISTEN

    @classmethod
    def template(cls):
        cls.client = cls.ca.issue("client", "/CN=nas.demo.local")
        return sample.template("sample/tac_plus-ng-radsec.cfg", [
            (TLS_LISTENERS, LISTENER),
            ("include = $CONFDIR/radius-dict.cfg", "include = " + DICTIONARY)]
            + RADIUS_LOGS + democa_edits(cls.ca, cls.ca.server[0]))

    def test_radsec_admin_profile(self):
        r = self.radsec(self.client).access_request("demo", "demo")
        self.assertEqual((r.code_name, cisco_avpairs(r)), ("Access-Accept", ["shell:priv-lvl=7"]))
        self.assertTrue(r.message_authenticator, "no valid Message-Authenticator in the reply")
        r = self.radsec(self.client).access_request("demo", "demo", attributes=[ADMINISTRATIVE_USER])
        self.assertEqual((r.code_name, cisco_avpairs(r)), ("Access-Accept", ["shell:priv-lvl=15"]))
        self.wait_log("rad-access", "\tradius pap login succeeded\tUser-Name=demo Service-Type=Administrative-User\t"
                                    "Cisco:Cisco-AVPair=shell:priv-lvl=15\n")

    def test_radsec_rejects(self):
        self.assertEqual(self.radsec(self.client).access_request("demo", "wrong").code_name, "Access-Reject")
        r = self.radsec(self.client).access_request("demo2", "demo")
        self.assertEqual((r.code_name, r.get(radius.REPLY_MESSAGE)), ("Access-Reject", [b"Denied by ACL"]))

    def test_udp_needs_message_authenticator(self):
        r = self.radius("demo", listener="udp").access_request("demo", "demo", message_authenticator=True)
        self.assertEqual((r.code_name, cisco_avpairs(r)), ("Access-Accept", ["shell:priv-lvl=7"]))
        with self.assertRaises(TimeoutError):
            self.radius("demo", listener="udp", timeout=2.0).access_request("demo", "demo")

    def test_tacacs_over_tls(self):
        for user in ("demo", "demo2"):
            r = self.connect_tls(self.client).author(user, ["service=shell", "cmd="])
            self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]), user)
        self.assertEqual(self.connect_tls(self.client).author("demo2", ["service=ppp"]).status_name, "FAIL")
        self.wait_log("conn", "\tTLSv1.3\t/O=tactest/CN=tactest root\t/CN=nas.demo.local")

    def test_tacacs_on_the_radsec_port(self):
        """The daemon tells TACACS+ from RADIUS by the first bytes."""
        r = self.connect_tls(self.client, listener="radsec").author("demo", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]))

    def test_accounting_listener(self):
        r = accounting_start(self.radius("demo", listener="acct"), "demo", "acct-radsec-1")
        self.assertEqual(r.code_name, "Accounting-Response", r)
        self.wait_log("rad-acct", "\tdemo\t\t\tstart\t\tUser-Name=demo Acct-Status-Type=Start "
                                  "Acct-Session-Id=acct-radsec-1\n")


@unittest.skipUnless(HAVE_TLS, "needs the openssl command and a build with OpenSSL")
class FingerprintSample(TlsSampleCase):
    """sample/tls-fingerprint-demo/tac_plus-ng-fingerprint.cfg: a device by the SHA-256 fingerprint of a certificate.

    The certificates and the fingerprint file are what mkcert.sh makes.
    The TLS listener moves to LISTEN, after the plain one the harness
    probes; "single process = yes" goes. The device has no key, so the
    probe gets no PASS. A matching certificate is not tested: the
    handshake refuses every self-signed client certificate.
    """

    KEY = ""
    LISTEN = {"tls": "tls = yes"}

    @classmethod
    def template(cls):
        cls.server = tls.self_signed(cls.ca.dir, "server.selfsigned", "/CN=server.selfsigned")
        cls.client = tls.self_signed(cls.ca.dir, "client.selfsigned", "/CN=client.selfsigned")
        cls.other = tls.self_signed(cls.ca.dir, "other.selfsigned", "/CN=client.selfsigned")
        with open(cls.client[0]) as f:
            digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).digest()
        fingerprint = cls.ca.path("client.selfsigned.fingerprint")
        with open(fingerprint, "w") as f:
            f.write(":".join("%02X" % b for b in digest) + "\n")
        return sample.template("sample/tls-fingerprint-demo/tac_plus-ng-fingerprint.cfg", [
            ("single process = yes\n\tlisten { port = 4950 tls = yes }", LISTENER),
            ("tls cert-file = $CONFDIR/server.selfsigned.crt", 'tls cert-file = "%s"' % cls.server[0]),
            ("tls key-file = $CONFDIR/server.selfsigned.key", 'tls key-file = "%s"' % cls.server[1]),
            ("include $CONFDIR/client.selfsigned.fingerprint", 'include "%s"' % fingerprint)])

    def context(self, cert):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False
        ctx.load_verify_locations(self.server[0])
        if cert:
            ctx.load_cert_chain(*cert)
        return ctx

    def test_client_without_a_certificate_is_refused(self):
        with self.assertRaises((Closed, OSError)):
            self.connect(listener="tls", tls=self.context(None)).pap("demo", "demo")

    def test_certificate_with_another_fingerprint_is_refused(self):
        with self.assertRaises((Closed, OSError)):
            self.connect(listener="tls", tls=self.context(self.other)).pap("demo", "demo")


class AdsSample(DaemonTestCase):
    """extra/tac_plus-ng.cfg-ads: profiles by LDAP group (memberOf) and by local group; the LDAP script is the stub.

    "background = yes" goes: the harness runs the daemon in the foreground.
    """

    KEY = "demo"
    TEMPLATE = sample.template("extra/tac_plus-ng.cfg-ads", [
        ("listen = { port = 49 }", LISTENER.replace("listen {", "listen = {")),
        ("background = yes", "background = no"),
        ("exec = /usr/local/lib/mavis/mavis_tacplus-ng_ldap.pl", "\n".join(STUB_EXEC))])

    def setUp(self):
        super().setUp()
        self.stub = Stub(self.daemon)
        ldap = "CN=tacacs_%s,OU=Groups,DC=example,DC=local"
        self.stub.set(users={"adm": {"password": "pw", "memberof": [ldap % "admins"]},
                             "ro": {"password": "pw", "memberof": ["CN=other,DC=example,DC=local", ldap % "readonly"]},
                             "other": {"password": "pw", "memberof": [ldap % "other"]},
                             "guest": {"password": "pw", "member": ["guest"]}})

    def test_ldap_admins_group(self):
        self.assertEqual(self.connect().ascii_login("adm", "pw").prompts, ["Welcome\nPassword: "])
        r = self.connect().author("adm", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=15"]))
        self.assertEqual(self.connect().enable("secret", user="adm").status_name, "PASS")
        self.assertEqual(self.connect().ascii_login("adm", "wrong").status_name, "FAIL")

    def test_ldap_readonly_group(self):
        r = self.connect().author("ro", ["service=shell", "cmd="])
        self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=1"]))
        # the guest profile has "enable = deny"
        self.assertEqual(self.connect().enable("secret", user="ro").status_name, "FAIL")

    def test_other_ldap_group_is_denied(self):
        self.assertEqual(self.connect().ascii_login("other", "pw").status_name, "FAIL")
        self.assertEqual(self.stub.requests("AUTH", "other")[0]["result"], "ACK")

    def test_local_guest_group(self):
        """Local user readonly and backend user guest: the second rule, "member == guest"."""
        self.assertEqual(self.connect().ascii_login("readonly", "readonly").status_name, "PASS")
        for user in ("readonly", "guest"):
            r = self.connect().author(user, ["service=shell", "cmd="])
            self.assertEqual((r.status_name, r.args), ("PASS_ADD", ["priv-lvl=1"]), user)
        self.assertEqual(self.connect().enable("secret", user="readonly").status_name, "FAIL")


if __name__ == "__main__":
    unittest.main()
