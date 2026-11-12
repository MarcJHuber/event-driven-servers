"""Script conditions and actions, rewrite profiles, script order and time ranges, end to end.

A profile sets "tactest-<name>=yes" for each condition that holds (the
pattern of test_policy.py), so one authorization request shows all of
them. RADIUS tests put the names into Reply-Message attributes instead.
On Linux all of 127.0.0.0/8 is local: a client binds to 127.0.x.y and the
daemon sees another device address.
"""

import datetime
import os
import struct
import unittest

from tactest import LINUX, SOURCE, DaemonTestCase, Stub, features, radius, tacacs, tls

DICTIONARY = os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")
RADIUS_SECRET = "radsecret"
RADIUS_NAS = "127.0.0.1"

USER = """
	user alice {
		password login = clear alicepw
		password pap = login
	}
"""


def shell_profile(conditions):
    """A profile that sets tactest-<name> = yes for each condition that holds, then permits the shell."""
    lines = "".join("\t\t\t\tif (%s) set tactest-%s = yes\n" % (cond, name) for name, cond in conditions)
    return """
	profile shell {
		script {
			if (service == shell) {
%s				permit
			}
		}
	}
	ruleset {
		rule { script { profile = shell permit } }
	}
""" % lines


def names(reply):
    """The names of the tactest-<name>=yes pairs of an authorization reply."""
    return sorted(a[len("tactest-"):-len("=yes")] for a in reply.args
                  if a.startswith("tactest-") and a.endswith("=yes"))


class FlagTestCase(DaemonTestCase):
    def holds(self, **kw):
        """Names of the conditions that hold for a shell start; kw goes to the authorization request."""
        r = self.connect().author("alice", ["service=shell", "cmd="], **kw)
        self.assertTrue(r.ok, r)
        return names(r)


class SessionConditions(FlagTestCase):
    """Conditions on the connection, the server, the client address, the port and the authentication type."""

    CONFIG = USER + """
	net lab {
		address = 10.1.2.0/24
	}
""" + shell_profile([
        ("tcp", "conn.protocol == tcp"),
        ("udp", "conn.protocol == udp"),
        ("server-port", "server.port == $port"),
        ("server-address", "server.address == 127.0.0.1"),
        ("server-name", 'server.name == "%s"' % os.uname().nodename),
        ("client-address", "client.address == 10.1.2.0/24"),
        ("client-address-regex", "client.address =~ /^10[.]1[.]2[.]/"),
        ("client-name", "client.name == lab"),
        ("device-port", "device.port == tty7"),
        ("device-port-regex", "device.port =~ /^vty/"),
        ("port", "port == tty7"),
        ("ascii", "authen-type == ascii"),
        ("pap", "authen-type == pap"),
    ])

    def test_connection_and_server(self):
        self.assertEqual(self.holds(), ["ascii", "server-address", "server-name", "server-port", "tcp"])

    def test_client_address_and_net(self):
        client = {"client-address", "client-address-regex", "client-name"}
        self.assertEqual(set(self.holds(rem_addr="10.1.2.3")) & client, client)
        self.assertEqual(set(self.holds(rem_addr="10.9.2.3")) & client, set())

    def test_device_port(self):
        port = {"device-port", "device-port-regex", "port"}
        self.assertEqual(set(self.holds(port="tty7")) & port, {"device-port", "port"})
        self.assertEqual(set(self.holds(port="vty3")) & port, {"device-port-regex"})

    def test_authen_type_of_the_request(self):
        self.assertIn("ascii", self.holds(authen_type=tacacs.AUTHEN_TYPE_ASCII))
        holds = self.holds(authen_type=tacacs.AUTHEN_TYPE_PAP)
        self.assertIn("pap", holds)
        self.assertNotIn("ascii", holds)


VENDOR_SPECIFIC = 26


def vsa(vendor, attr_type, value):
    return (VENDOR_SPECIFIC, struct.pack("!I", vendor) + bytes([attr_type, 2 + len(value)]) + value)


class RadiusConditions(DaemonTestCase):
    """Conditions on a RADIUS request: transport, client address and port from attributes, an ipaddr VSA."""

    CALLING_STATION_ID = 31
    NAS_PORT_ID = 87
    CISCO_ASA = 3076
    ASA_PRIMARY_DNS = 5
    CONDITIONS = [
        ("udp", "conn.protocol == udp"),
        ("tcp", "conn.protocol == tcp"),
        ("radius-udp", "aaa.protocol == radius.udp"),
        ("radius-tcp", "aaa.protocol == radius.tcp"),
        ("client-address", "client.address == 10.9.8.7"),
        ("device-port", "device.port == port42"),
        ("dns", "radius[Cisco-ASA:ASA-Primary-DNS] == 10.0.0.53"),
        ("not-dns", "radius[Cisco-ASA:ASA-Primary-DNS] != 10.0.0.53"),
        ("dns-regex", "radius[Cisco-ASA:ASA-Primary-DNS] =~ /^10[.]0[.]0[.]/"),
    ]
    CONFIG = """
	include = "%s"
	device radius-nas {
		address = %s
		key = tactest
		radius.key = %s
	}
""" % (DICTIONARY, RADIUS_NAS, RADIUS_SECRET) + USER + """
	profile admin {
		script {
			if (aaa.protocol == radius) {
%s				permit
			}
		}
	}
	ruleset {
		rule { script { profile = admin permit } }
	}
""" % "".join('\t\t\t\tif (%s) set radius[Reply-Message] = "%s"\n' % (c, n) for n, c in CONDITIONS)
    UDP = True

    def holds(self, attributes=(), tcp=False):
        r = self.radius(RADIUS_SECRET, tcp=tcp, source=RADIUS_NAS).access_request(
            "alice", "alicepw", attributes=attributes, message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Accept", r)
        return sorted(v.decode() for v in r.get(radius.REPLY_MESSAGE))

    def test_udp(self):
        self.assertEqual(self.holds(), ["not-dns", "radius-udp", "udp"])

    def test_tcp(self):
        self.assertEqual(self.holds(tcp=True), ["not-dns", "radius-tcp", "tcp"])

    def test_client_address_and_port_from_attributes(self):
        holds = self.holds([(self.CALLING_STATION_ID, b"10.9.8.7"), (self.NAS_PORT_ID, b"port42")])
        self.assertEqual(set(holds) & {"client-address", "device-port"}, {"client-address", "device-port"})
        holds = self.holds([(self.CALLING_STATION_ID, b"10.9.8.8"), (self.NAS_PORT_ID, b"port43")])
        self.assertFalse(set(holds) & {"client-address", "device-port"})

    def test_ipaddr_vendor_attribute(self):
        """ASA-Primary-DNS has the dictionary type "ipaddr"; it compares as an IPv4 address."""
        dns = vsa(self.CISCO_ASA, self.ASA_PRIMARY_DNS, bytes([10, 0, 0, 53]))
        self.assertEqual(set(self.holds([dns])) & {"dns", "not-dns", "dns-regex"}, {"dns", "dns-regex"})
        dns = vsa(self.CISCO_ASA, self.ASA_PRIMARY_DNS, bytes([10, 0, 0, 54]))
        self.assertEqual(set(self.holds([dns])) & {"dns", "not-dns", "dns-regex"}, {"not-dns", "dns-regex"})


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
@unittest.skipUnless("pcre2" in features(), "rewrite profiles need PCRE2")
class Rewrite(DaemonTestCase):
    """The rewrite profile of a device script changes the user name before the daemon looks up the user to log in.

    The first rule that matches wins. "rewritten-only" lets a user log in
    only under a name that a rewrite changed. user.original is the name
    before the rewrite, in the device script and in the ruleset.
    """

    DEVICE = "127.0.8.1"
    CONFIG = r"""
	rewrite names {
		rewrite /^admin$$/ alice
		rewrite /^root$$/ alice
		rewrite /^toor$$/ alice
		rewrite /^ops-(.*)$$/ $$1
		rewrite /^.*$$/ \L$$0
	}
	device rewriting {
		address = 127.0.8.0/24
		key = tactest
		script {
			rewrite user = names
			if (user.original == root) deny
		}
	}
	user bob {
		password login = clear bobpw
		password pap = login
	}
	user shared {
		password login = clear sharedpw
		password pap = login
		rewritten-only
	}
	ruleset {
		rule {
			script {
				if (user.original == toor) deny
				permit
			}
		}
	}
""" + USER

    def pap(self, user, password, source=DEVICE):
        return self.connect(source=source).pap(user, password).status_name

    def test_rewritten_name_logs_in(self):
        self.assertEqual(self.pap("admin", "alicepw"), "PASS")
        self.assertEqual(self.connect(source=self.DEVICE).ascii_login("admin", "alicepw").status_name, "PASS")

    def test_replacement_with_a_capture_group(self):
        self.assertEqual(self.pap("ops-bob", "bobpw"), "PASS")

    def test_replacement_in_lower_case(self):
        self.assertEqual(self.pap("ALICE", "alicepw"), "PASS")
        self.assertEqual(self.pap("Bob", "bobpw"), "PASS")

    def test_device_without_the_rewrite(self):
        self.assertEqual(self.pap("admin", "alicepw", source="127.0.0.1"), "FAIL")
        self.assertEqual(self.pap("alice", "alicepw", source="127.0.0.1"), "PASS")

    def test_rewritten_only_user(self):
        self.assertEqual(self.pap("Shared", "sharedpw"), "PASS")
        self.assertEqual(self.pap("shared", "sharedpw"), "FAIL")

    def test_user_original_in_the_device_script(self):
        self.assertEqual(self.pap("root", "alicepw"), "FAIL")

    def test_user_original_in_the_ruleset(self):
        self.assertEqual(self.pap("toor", "alicepw"), "FAIL")


def users(*names):
    return "".join("\tuser %s {\n\t\tpassword login = clear pw\n\t}\n" % n for n in names)


REALM_RULESET = """
		ruleset {
			rule { script { if (user == realm) { profile = child-realm permit } } }
		}
"""


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class ScriptOrder(DaemonTestCase):
    """script-order (bottom-up by default, or top-down) and "skip parent-script" for profiles, devices, realms.

    Bottom-up runs the script of the child first and the parent only if the
    child gives no permit or deny; top-down runs the parent first. Each realm
    of a listener has its own script-order; the policy is in the parent realm.
    """

    CONFIG = users("inner", "inner-return", "inner-skip", "realm") + """
	profile outer {
		script { if (service == shell) { set tactest-profile = outer permit } }
		profile inner {
			script { if (service == shell) { set tactest-profile = inner permit } }
		}
		profile inner-return {
			script {
				if (service == shell) {
					set tactest-return = yes
					return
					set tactest-after-return = yes
					permit
				}
			}
		}
		profile inner-skip {
			skip parent-script = yes
			script { if (service == shell) set tactest-skip = yes }
		}
	}
	profile parent-realm {
		script { if (service == shell) { set tactest-realm = parent permit } }
	}
	profile child-realm {
		script { if (service == shell) { set tactest-realm = child permit } }
	}
	device order-parent {
		address = 127.0.9.0/24
		key = tactest
		script { if (service == shell) deny }
		device order-child {
			address = 127.0.9.1
			script { if (service == shell) permit }
		}
	}
	ruleset {
		rule profiles {
			script {
				if (user == inner) { profile = inner permit }
				if (user == inner-return) { profile = inner-return permit }
				if (user == inner-skip) { profile = inner-skip permit }
			}
		}
		rule parent-realm {
			script { if (user == realm) { profile = parent-realm permit } }
		}
		# the harness logs in as this user after each test; a failed login costs the failure delay
		rule probe {
			script { if (user =~ /^tactest-generation-/) permit }
		}
	}
	realm bottomup {
%s	}
	realm topdown {
		script-order profile = top-down
		script-order host = top-down
		script-order realm = top-down
%s	}
	realm skip {
		skip parent-script = yes
%s	}
""" % (REALM_RULESET, REALM_RULESET, REALM_RULESET)
    LISTEN = {"bottomup": "realm = bottomup", "topdown": "realm = topdown", "skip": "realm = skip"}

    def shell(self, user, listener=None, source=None):
        """(status, tactest-* pairs) of a shell start."""
        r = self.connect(listener=listener, source=source).author(user, ["service=shell", "cmd="])
        return r.status_name, sorted(a for a in r.args if a.startswith("tactest-"))

    def test_profile_bottom_up_by_default(self):
        self.assertEqual(self.shell("inner"), ("PASS_ADD", ["tactest-profile=inner"]))
        self.assertEqual(self.shell("inner", "bottomup"), ("PASS_ADD", ["tactest-profile=inner"]))

    def test_profile_top_down(self):
        self.assertEqual(self.shell("inner", "topdown"), ("PASS_ADD", ["tactest-profile=outer"]))

    def test_return_in_the_child_profile_lets_the_parent_decide(self):
        self.assertEqual(self.shell("inner-return"), ("PASS_ADD", ["tactest-profile=outer", "tactest-return=yes"]))

    def test_skip_parent_script_of_a_profile(self):
        """The child gives no verdict and its parent is skipped: nothing permits the service."""
        self.assertEqual(self.shell("inner-skip"), ("FAIL", []))

    def test_device_bottom_up_by_default(self):
        self.assertEqual(self.shell("inner", source="127.0.9.1")[0], "PASS_ADD")
        self.assertEqual(self.shell("inner", source="127.0.9.2")[0], "FAIL")

    def test_device_top_down(self):
        self.assertEqual(self.shell("inner", "topdown", source="127.0.9.1")[0], "FAIL")
        self.assertEqual(self.shell("inner", "topdown")[0], "PASS_ADD")

    def test_realm_bottom_up_by_default(self):
        self.assertEqual(self.shell("realm", "bottomup"), ("PASS_ADD", ["tactest-realm=child"]))

    def test_realm_top_down(self):
        self.assertEqual(self.shell("realm", "topdown"), ("PASS_ADD", ["tactest-realm=parent"]))

    def test_skip_parent_script_of_a_realm(self):
        self.assertEqual(self.shell("realm", "skip"), ("PASS_ADD", ["tactest-realm=child"]))
        self.assertEqual(self.shell("inner", "skip"), ("FAIL", []))
        self.assertEqual(self.shell("inner", "bottomup"), ("PASS_ADD", ["tactest-profile=inner"]))


DAYS = ("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def cron_day(t):
    return (t.weekday() + 1) % 7


def around(now, step, n):
    """now + k * step for k in -n .. n."""
    return [now + k * step for k in range(-n, n + 1)]


def joined(values):
    return ",".join(str(v) for v in sorted(set(values)))


def time_policy(now):
    """Time ranges around now (UTC): "near" ones hold for an hour or a day at least, "far" ones not."""
    hour, day = datetime.timedelta(hours=1), datetime.timedelta(days=1)
    near_hours = {t.hour for t in around(now, hour, 1)}
    far_hours = set(range(24)) - {t.hour for t in around(now, hour, 2)}
    near_days = {cron_day(t) for t in around(now, day, 1)}
    far_days = set(range(7)) - {cron_day(t) for t in around(now, day, 2)}
    near_mdays = {t.day for t in around(now, day, 1)}
    far_mdays = set(range(1, 32)) - {t.day for t in around(now, day, 2)}
    near_months = {t.month for t in around(now, day, 1)}
    far_month = (now.month + 5) % 12 + 1
    uucp = ("Su", "Mo", "Tu", "We", "Th", "Fr", "Sa")
    ranges = [
        ("time", "always", '"* * * * *"'),
        ("time", "never", '"* * 30 Feb *"'),
        ("timespec", "near-hours", '"* %s * * *"' % joined(near_hours)),
        ("timespec", "far-hours", '"* %s * * *"' % joined(far_hours)),
        ("time", "near-days", '"* * * * %s"' % ",".join(DAYS[d] for d in sorted(near_days))),
        ("time", "far-days", '"* * * * %s"' % ",".join(DAYS[d] for d in sorted(far_days))),
        ("time", "near-mdays", '"* * %s * *"' % joined(near_mdays)),
        ("time", "far-mdays", '"* * %s * *"' % joined(far_mdays)),
        ("time", "near-months", '"* * * %s *"' % ",".join(MONTHS[m - 1] for m in sorted(near_months))),
        ("time", "far-month", '"* * * %s *"' % MONTHS[far_month - 1]),
        ("time", "two-entries", '"* * * * %s" "* %s * * *"' % (DAYS[min(far_days)], joined(near_hours))),
        ("time", "uucp-any", "Any"),
        ("time", "uucp-near-days", " ".join(uucp[d] for d in sorted(near_days))),
        ("time", "uucp-far-days", " ".join(uucp[d] for d in sorted(far_days))),
        ("time", "uucp-near-hours", " ".join("Any%02d00-%02d59" % (h, h) for h in sorted(near_hours))),
        ("time", "uucp-far-hours", "Any%02d00-%02d59" % ((now.hour + 12) % 24, (now.hour + 12) % 24)),
        ("time", "uucp-weekdays", "Wk"),
        ("time", "uucp-weekend", "Wd"),
    ]
    decls = "".join("\t%s %s { %s }\n" % r for r in ranges)
    conditions = [(name, "time == %s" % name) for _, name, _ in ranges]
    conditions += [("not-never", "!(time == never)"), ("not-always", "!(time == always)")]
    return "\ttime zone = UTC\n" + decls + USER + shell_profile(conditions)


class TimeRanges(FlagTestCase):
    """time (and its other name timespec) in cron and Taylor UUCP syntax, and "time ==" in a script.

    "time zone = UTC" lets the test compute the ranges from the UTC clock.
    The ranges are built when the class starts, with a margin of an hour
    or a day, so a test that runs a few minutes later still sees them hold.
    Each line or word inside the braces is one entry; the range holds if
    one entry holds.
    """

    CONFIG = None

    @classmethod
    def setUpClass(cls):
        cls.CONFIG = time_policy(datetime.datetime.now(datetime.timezone.utc))
        super().setUpClass()

    def test_cron_syntax(self):
        holds = set(self.holds()) - {"not-never", "not-always"}
        holds = {n for n in holds if not n.startswith("uucp-")}
        self.assertEqual(holds, {"always", "near-hours", "near-days", "near-mdays", "near-months", "two-entries"})

    def test_uucp_syntax(self):
        holds = {n for n in self.holds() if n.startswith("uucp-")}
        weekday = cron_day(datetime.datetime.now(datetime.timezone.utc)) in range(1, 6)
        self.assertEqual(holds, {"uucp-any", "uucp-near-days", "uucp-near-hours",
                                 "uucp-weekdays" if weekday else "uucp-weekend"})

    def test_negated_time_condition(self):
        holds = self.holds()
        self.assertIn("not-never", holds)
        self.assertNotIn("not-always", holds)


class Attributes(DaemonTestCase):
    """set, add and optional against the AV pairs of the device ("The Authorization Algorithm" in the docs).

    set: a mandatory pair, always in the reply. add: an optional pair, in
    the reply also if the device did not ask for it. optional: only if the
    device offered that attribute as an optional pair.
    """

    CONFIG = USER + """
	profile shell {
		script {
			if (service == shell) {
				set priv-lvl = 15
				set timeout = 30
				add tactest-added = yes
				optional idletime = 10
				optional tactest-optional = yes
				permit
			}
		}
	}
	ruleset {
		rule { script { profile = shell permit } }
	}
"""

    def shell(self, *args):
        r = self.connect().author("alice", ["service=shell", "cmd="] + list(args))
        return r.status_name, r.args

    def test_shell_start(self):
        """Only the additions come back (PASS_ADD); an optional pair the device didn't offer is left out."""
        self.assertEqual(self.shell(), ("PASS_ADD", ["priv-lvl=15", "timeout=30", "tactest-added*yes"]))

    def test_optional_value_of_the_daemon_replaces_the_offer_of_the_device(self):
        status, args = self.shell("idletime*5")
        self.assertEqual(status, "PASS_REPL")
        self.assertIn("idletime*10", args)
        self.assertNotIn("idletime*5", args)

    def test_mandatory_value_of_the_daemon_replaces_an_optional_offer(self):
        status, args = self.shell("timeout*5")
        self.assertEqual(status, "PASS_REPL")
        self.assertIn("timeout=30", args)
        self.assertNotIn("timeout*5", args)

    def test_mandatory_pair_of_the_device_with_another_value_fails(self):
        self.assertEqual(self.shell("timeout=5"), ("FAIL", []))

    def test_mandatory_pair_of_the_device_with_an_optional_attribute_is_kept(self):
        """The device keeps idletime=3 (PASS_ADD returns only the additions)."""
        status, args = self.shell("idletime=3")
        self.assertEqual(status, "PASS_ADD")
        self.assertFalse([a for a in args if a.startswith("idletime")], args)

    def test_unknown_optional_pair_of_the_device_is_deleted(self):
        status, args = self.shell("foo*bar")
        self.assertEqual(status, "PASS_REPL")
        self.assertEqual(args, ["service=shell", "cmd=", "priv-lvl=15", "timeout=30", "tactest-added*yes"])

    def test_unknown_mandatory_pair_of_the_device_fails(self):
        self.assertEqual(self.shell("foo=bar"), ("FAIL", []))


class ScriptFlow(DaemonTestCase):
    """else, return, "acl ==" and the exec context ("context =" and "context ==")."""

    CONFIG = r"""
	user bob {
		password login = clear bobpw
	}
	acl lab {
		if (client == 10.1.0.0/16) permit
	}
	profile shell {
		script {
			if (service == shell) {
				if (cmd == "") {
					if (device.port == tty1) set tactest-branch = if
					else set tactest-branch = else
					if (acl == lab) set tactest-acl = yes
					set tactest-profile = shell
					permit
				}
				if (cmd =~ /^interface FastEthernet0\/1( |$$)/) {
					context = FE
					permit
				} else if (cmd =~ /^interface /) {
					context = ""
					permit
				}
				if (context == FE) {
					if (cmd =~ /^shutdown/) permit
				}
				deny
			}
		}
	}
	profile limited {
		script { if (service == shell) { set tactest-profile = limited permit } }
	}
	ruleset {
		rule early {
			script {
				if (user == bob) return
				profile = shell
				permit
			}
		}
		rule late {
			script { profile = limited permit }
		}
	}
""" + USER

    def shell(self, user="alice", **kw):
        r = self.connect().author(user, ["service=shell", "cmd="], **kw)
        self.assertTrue(r.ok, r)
        return sorted(a for a in r.args if a.startswith("tactest-"))

    def test_else(self):
        for port, branch in (("tty1", "if"), ("tty2", "else")):
            pairs = [a for a in self.shell(port=port) if a.startswith("tactest-branch=")]
            self.assertEqual(pairs, ["tactest-branch=" + branch], port)

    def test_return_ends_the_rule_without_a_verdict(self):
        self.assertIn("tactest-profile=shell", self.shell())
        self.assertEqual(self.shell("bob"), ["tactest-profile=limited"])

    def test_acl_condition(self):
        self.assertIn("tactest-acl=yes", self.shell(rem_addr="10.1.2.3"))
        self.assertNotIn("tactest-acl=yes", self.shell(rem_addr="10.2.2.3"))

    def test_context(self):
        """The example of the docs: "shutdown" only in the context of one interface, per user and port."""
        c = self.connect(single_connect=True)

        def command(line, port="tty1"):
            words = line.split()
            args = ["service=shell", "cmd=" + words[0]] + ["cmd-arg=" + w for w in words[1:]] + ["cmd-arg=<cr>"]
            return c.author("alice", args, port=port).status_name

        self.assertEqual(command("shutdown"), "FAIL")
        self.assertEqual(command("interface FastEthernet0/1"), "PASS_ADD")
        self.assertEqual(command("shutdown"), "PASS_ADD")
        self.assertEqual(command("shutdown", port="tty2"), "FAIL")
        r = self.connect().author("alice", ["service=shell", "cmd=shutdown", "cmd-arg=<cr>"], port="tty1")
        self.assertEqual(r.status_name, "FAIL", "context on another connection")
        self.assertEqual(command("interface GigabitEthernet0/2"), "PASS_ADD")
        self.assertEqual(command("shutdown"), "FAIL")


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class PermitIfAuthenticated(DaemonTestCase):
    """permit if-authenticated = yes: authorization of a user the daemon doesn't know, not authenticated by it."""

    CONFIG = USER + """
	device trusting {
		address = 127.0.10.1
		key = tactest
		permit if-authenticated = yes
	}
	ruleset {
		rule { script { permit } }
	}
"""

    AUTHEN_METH_LOCAL = 5

    def unknown_user(self, source, method):
        r = self.connect(source=source).author("nobody", ["service=shell", "cmd="], authen_method=method)
        return r.status_name

    def test_user_authenticated_on_the_device(self):
        self.assertEqual(self.unknown_user("127.0.10.1", self.AUTHEN_METH_LOCAL), "PASS_ADD")

    def test_user_authenticated_with_tacacs(self):
        self.assertEqual(self.unknown_user("127.0.10.1", tacacs.AUTHEN_METH_TACACSPLUS), "FAIL")

    def test_device_without_it(self):
        self.assertEqual(self.unknown_user("127.0.0.1", self.AUTHEN_METH_LOCAL), "FAIL")


@unittest.skipUnless("pcre2" in features(), "the script out uses a PCRE")
class MavisAttributes(FlagTestCase):
    """memberof and identity-source on the MAVIS answer of a user.

    The "script out" of the module adds MEMBEROF to the answer for alice,
    the way an LDAP backend sends it: quoted DNs, separated by commas.
    identity-source is the name of the module that answered.
    """

    MODULE = Stub.module(childs=(1, 1), script=r"""		script out {
			if ($$USER == alice) set $$MEMBEROF = "\"CN=netadmins,OU=groups,DC=example\",\"CN=staff,OU=groups,DC=example\""
		}""").replace("mavis module = external", "mavis module ldap1 = external")
    CONFIG = MODULE + """
	user backend = mavis
	login backend = mavis
	pap backend = mavis
	user carol {
		password login = clear carolpw
	}
""" + shell_profile([
        ("netadmins", 'memberof == "CN=netadmins,OU=groups,DC=example"'),
        ("staff", "memberof =~ /^CN=staff,/"),
        ("other", 'memberof == "CN=other,OU=groups,DC=example"'),
        ("ldap1", "identity-source == ldap1"),
        ("ldap", "identity-source =~ /^ldap/"),
    ])

    def setUp(self):
        super().setUp()
        Stub(self.daemon).set(users={"alice": {"password": "pw"}, "bob": {"password": "pw"}})

    def shell(self, user):
        r = self.connect().author(user, ["service=shell", "cmd="])
        self.assertTrue(r.ok, r)
        return names(r)

    def test_memberof(self):
        self.assertEqual(self.shell("alice"), ["ldap", "ldap1", "netadmins", "staff"])

    def test_identity_source_without_memberof(self):
        self.assertEqual(self.shell("bob"), ["ldap", "ldap1"])

    def test_local_user_has_neither(self):
        self.assertEqual(self.shell("carol"), [])


def need_tls():
    if not tls.openssl_available():
        raise unittest.SkipTest("no openssl command to make certificates")
    if "openssl" not in features():
        raise unittest.SkipTest("tac_plus-ng built without OpenSSL")


TLS_CONDITIONS = [
    ("aes256", "tls.conn.cipher == TLS_AES_256_GCM_SHA384"),
    ("aes128", "tls.conn.cipher == TLS_AES_128_GCM_SHA256"),
    ("chacha20", "tls.conn.cipher =~ /^TLS_CHACHA20_/"),
    ("bits256", "tls.conn.cipher.strength == 256"),
    ("bits128", "tls.conn.cipher.strength == 128"),
]
CIPHERS = {"TLS_AES_256_GCM_SHA384": "aes256", "TLS_AES_128_GCM_SHA256": "aes128",
           "TLS_CHACHA20_POLY1305_SHA256": "chacha20"}


class TlsCertificateConditions(FlagTestCase):
    """tls.conn.cipher, tls.conn.cipher.strength and the peer certificate conditions on a TLS listener."""

    LISTEN = {"tls": "tls = yes"}
    BODY = """
	tls cert-file = "%(server_crt)s"
	tls key-file = "%(server_key)s"
	tls ca-file = "%(ca)s"
	device certnas.tactest {
	}
""" + USER + shell_profile(TLS_CONDITIONS + [
        ("issuer", 'tls.peer.cert.issuer == "/O=tactest/CN=tactest root"'),
        ("issuer-regex", "tls.peer.cert.issuer =~ /CN=tactest root$$/"),
        ("subject", 'tls.peer.cert.subject == "/O=tactest/CN=certnas.tactest"'),
        ("subject-regex", "tls.peer.cert.subject =~ /O=tactest/"),
        ("cn", "tls.peer.cn == certnas.tactest"),
        ("psk", "tls.psk.identity =~ /./"),
    ])

    @classmethod
    def setUpClass(cls):
        need_tls()
        cls.ca = tls.CA(cls.__name__ + "-ca")
        cls.certs = {"certnas": cls.ca.issue("certnas", "/O=tactest/CN=certnas.tactest"),
                     "other": cls.ca.issue("other", "/O=tactest/CN=other.tactest")}
        cls.CONFIG = cls.BODY % dict(ca=cls.ca.cert, server_crt=cls.ca.server[0], server_key=cls.ca.server[1])
        try:
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

    def tls_holds(self, client):
        c = self.connect(listener="tls", tls=self.ca.context(self.certs[client]), server_hostname="localhost",
                         timeout=10.0)
        r = c.author("alice", ["service=shell", "cmd="])
        self.assertTrue(r.ok, r)
        name, _, bits = c.sock.cipher()
        return set(names(r)), {CIPHERS[name], "bits%d" % bits}

    def test_cipher_as_the_client_sees_it(self):
        holds, cipher = self.tls_holds("certnas")
        self.assertEqual(holds & {n for n, _ in TLS_CONDITIONS}, cipher)

    def test_peer_certificate(self):
        holds, cipher = self.tls_holds("certnas")
        self.assertEqual(holds - cipher, {"issuer", "issuer-regex", "subject", "subject-regex", "cn"})

    def test_other_peer_certificate(self):
        holds, cipher = self.tls_holds("other")
        self.assertEqual(holds - cipher, {"issuer", "issuer-regex", "subject-regex"})

    def test_plain_connection_has_no_tls_data(self):
        self.assertEqual(self.holds(), [])


PSK_KEY = "0123456789abcdef0123456789abcdef"


class TlsPskConditions(FlagTestCase):
    """tls.psk.identity and the cipher of a TLS 1.3 PSK connection ("openssl s_client -psk")."""

    LISTEN = {"psk": "tls = yes tls psk = yes"}
    CONFIG = """
	tls psk = yes
	tls cipher-suites = TLS_AES_128_GCM_SHA256
	device psknas {
		tls psk id = psknas
		tls psk key = hex %s
	}
	device pskother {
		tls psk id = pskother
		tls psk key = clear demoDemo
	}
""" % PSK_KEY + USER + shell_profile(TLS_CONDITIONS + [
        ("psknas", "tls.psk.identity == psknas"),
        ("psk-regex", "tls.psk.identity =~ /^psk/"),
        ("cn", "tls.peer.cn =~ /./"),
    ])

    @classmethod
    def setUpClass(cls):
        need_tls()
        super().setUpClass()

    def psk_holds(self, identity, key):
        sock = tls.PskSocket((self.daemon.address, self.daemon.ports["psk"]), identity, key, timeout=10.0)
        return self.connect(sock=sock, timeout=10.0).author("alice", ["service=shell", "cmd="])

    def test_identity(self):
        r = self.psk_holds("psknas", PSK_KEY)
        self.assertTrue(r.ok, r)
        self.assertEqual(names(r), ["aes128", "bits128", "psk-regex", "psknas"])

    def test_other_identity(self):
        r = self.psk_holds("pskother", b"demoDemo".hex())
        self.assertTrue(r.ok, r)
        self.assertEqual(names(r), ["aes128", "bits128", "psk-regex"])


if __name__ == "__main__":
    unittest.main()
