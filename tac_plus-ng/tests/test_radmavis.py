"""radmavis-mt: daemon A authenticates through external-mt against daemon B, a tac_plus-ng that answers RADIUS.

The backend sends an Access-Request with PAP to B and maps the Class
attribute of the Access-Accept to TACMEMBER ("group_attribute=Class").
"""

import os
import string
import unittest

from tactest import SOURCE, DaemonTestCase, prefix

RADMAVIS = os.path.join(prefix(), "sbin", "radmavis-mt")
DICTIONARY = os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")
SECRET = "radsecret"
NAS = "127.0.0.6"

# radcli 1.2 and 1.3 send no Message-Authenticator: B must not require it (bug compatibility 32)
# Reply-Message: radmavis-mt rejects an Access-Accept without attributes (a B without OpenSSL adds none)
SERVER = string.Template("""
	include = "$dictionary"
	device nas {
		address = $nas
		radius.key = $secret
		bug compatibility = 32
	}
	user alice { password login = clear alicepw }
	user bob { password login = clear bobpw }
	profile reply {
		script {
			if (user == alice) set radius[Class] = "netadmins"
			set radius[Reply-Message] = "welcome"
			permit
		}
	}
	ruleset {
		rule { script { profile = reply permit } }
	}
""").substitute(dictionary=DICTIONARY, nas=NAS, secret=SECRET)

RADIUSCLIENT_CONF = """\
nas-identifier tactest
authserver 127.0.0.1:{port}:{secret}
acctserver 127.0.0.1:{port}:{secret}
bindaddr {nas}
dictionary /etc/radcli/dictionary
seqfile {seqfile}
mapfile /dev/null
auth_order radius
login_tries 1
radius_timeout 1
radius_retries 1
serv-type udp
"""

NETADMINS_MOTD = "Member of netadmins.\n"

CLIENT = string.Template("""
	mavis module = external-mt {
		exec = "$radmavis" "radmavis-mt" "-c" "$conf" "group_attribute=Class"
	}
	user backend = mavis
	login backend = mavis
	pap backend = mavis
	group netadmins { }
	ruleset {
		rule netadmins {
			script { if (member == netadmins) { motd banner = "Member of netadmins.\\n" permit } }
		}
		rule everyone { script { permit } }
	}
""")


@unittest.skipUnless(os.path.exists(RADMAVIS), "the build has no radmavis-mt (radcli or pthreads missing)")
class RadiusServer(DaemonTestCase):
    """Each test starts B first, then A with a radcli configuration that points at the RADIUS port of B."""

    CONFIG = None

    def start_pair(self, check_server=True):
        server = self.start_daemon(SERVER, udp=True, name=self.id().split(".")[-1] + "-server", check=check_server)
        port = server.udp_port
        seqfile = self.scratch_file("radius.seq", "")
        conf = self.scratch_file("radiusclient.conf",
                                 RADIUSCLIENT_CONF.format(port=port, secret=SECRET, nas=NAS, seqfile=seqfile))
        client = self.start_daemon(CLIENT.substitute(radmavis=RADMAVIS, conf=conf))
        return server, client

    def test_pap(self):
        _, a = self.start_pair()
        for password, status in (("alicepw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), a.connect() as c:
                self.assertEqual(c.pap("alice", password).status_name, status)

    def test_ascii_login(self):
        _, a = self.start_pair()
        for password, status in (("bobpw", "PASS"), ("wrong", "FAIL")):
            with self.subTest(password=password), a.connect() as c:
                self.assertEqual(c.ascii_login("bob", password).status_name, status)

    def test_unknown_user(self):
        _, a = self.start_pair()
        with a.connect() as c:
            self.assertEqual(c.pap("mallory", "alicepw").status_name, "FAIL")

    def test_class_attribute_becomes_a_group(self):
        """The rule for members of netadmins sets the MOTD; bob gets no Class and so no MOTD."""
        _, a = self.start_pair()
        for user, password, motd in (("alice", "alicepw", NETADMINS_MOTD), ("bob", "bobpw", "")):
            with self.subTest(user=user), a.connect() as c:
                r = c.ascii_login(user, password)
                self.assertEqual((r.status_name, r.server_msg), ("PASS", motd), r)

    def test_server_stopped(self):
        """Without an answer of the RADIUS server the login fails after radius_timeout, it does not hang."""
        b, a = self.start_pair(check_server=False)
        with a.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")
        self.assertEqual(b.stop(remove=False), [])
        with a.connect(timeout=10.0) as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "FAIL")


if __name__ == "__main__":
    unittest.main()
