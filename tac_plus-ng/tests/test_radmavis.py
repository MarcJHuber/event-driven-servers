"""radmavis-mt: daemon A authenticates through external-mt against daemon B, a tac_plus-ng that answers RADIUS.

The backend sends an Access-Request with PAP to B and maps the Class
attribute of the Access-Accept to TACMEMBER ("group_attribute=Class").
For the answers B does not give -- none at all, an Access-Challenge --
a RADIUS responder of the test takes the place of B.

A backend error opens the fallback of the realm ("authentication
fallback period"): the fallback-only user rescue can log in. As
"authentication fallback = permit" turns an error into a deny for the
user under test, rescue is what tells a failed login from a backend
error.
"""

import hashlib
import os
import select
import socket
import string
import threading
import unittest

from tactest import SOURCE, DaemonTestCase, prefix, radius

RADMAVIS = os.path.join(prefix(), "sbin", "radmavis-mt")
DICTIONARY = os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")
SECRET = "radsecret"
NAS = "127.0.0.6"
RADCLI_DICTIONARY = "/etc/radcli/dictionary"
ACCESS_CHALLENGE = 11
STATE = 24

# radcli 1.2 and 1.3 send no Message-Authenticator: B must not require it (bug compatibility 32)
SERVER = string.Template("""
	include = "$dictionary"
	device nas {
		address = $nas
		radius.key = $secret
		bug compatibility = 32
	}
	user alice { password login = clear alicepw }
	user bob { password login = clear bobpw }
	user carol { password login = clear carolpw }
	profile reply {
		script {
			if (user == carol) permit
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
dictionary {dictionary}
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
	authentication fallback = permit
	user rescue {
		fallback-only
		password pap = clear rescuepw
	}
	group netadmins { }
	ruleset {
		rule netadmins {
			script { if (member == netadmins) { motd banner = "Member of netadmins.\\n" permit } }
		}
		rule everyone { script { permit } }
	}
""")

# the first factor is local, the second (TACTYPE MFA) goes to radmavis-mt
MFA_CLIENT = string.Template("""
	mavis module = external-mt {
		exec = "$radmavis" "radmavis-mt" "-c" "$conf"
	}
	authentication fallback = permit
	user alice {
		password login = clear alicepw
		mfa = yes
	}
	user rescue {
		fallback-only
		password pap = clear rescuepw
	}
	ruleset { rule { script { permit } } }
""")


class Responder:
    """A RADIUS server on a free UDP port that answers every request with reply = (code, attributes).

    reply None: it never answers. requests counts what it got.
    """

    def __init__(self, reply=None):
        self.reply, self.requests = reply, 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            if select.select([self.sock], [], [], 0.1)[0]:
                data, peer = self.sock.recvfrom(4096)
                request = radius.Packet.decode(data)
                self.requests += 1
                if self.reply:
                    code, attributes = self.reply
                    raw = radius.Packet(code, request.identifier, request.authenticator, attributes).encode()
                    # Response Authenticator, RFC 2865 3
                    raw = raw[:4] + hashlib.md5(raw + SECRET.encode()).digest() + raw[20:]
                    self.sock.sendto(raw, peer)

    def close(self):
        self.stop.set()
        self.thread.join()
        self.sock.close()


@unittest.skipUnless(os.path.exists(RADMAVIS), "the build has no radmavis-mt (radcli or pthreads missing)")
class RadiusServer(DaemonTestCase):
    """Each test starts B first, then A with a radcli configuration that points at the RADIUS port of B."""

    CONFIG = None

    def start_pair(self, check_server=True, dictionary=RADCLI_DICTIONARY):
        server = self.start_daemon(SERVER, udp=True, name=self.id().split(".")[-1] + "-server", check=check_server)
        return server, self.start_client(server.udp_port, dictionary=dictionary)

    def start_client(self, port, template=CLIENT, dictionary=RADCLI_DICTIONARY):
        """Daemon A, with radmavis-mt asking the RADIUS server on port."""
        seqfile = self.scratch_file("radius.seq", "")
        conf = self.scratch_file("radiusclient.conf",
                                 RADIUSCLIENT_CONF.format(port=port, secret=SECRET, nas=NAS, seqfile=seqfile,
                                                          dictionary=dictionary))
        return self.start_daemon(template.substitute(radmavis=RADMAVIS, conf=conf))

    def responder(self, reply=None):
        r = Responder(reply)
        self.addCleanup(r.close)
        return r

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

    def test_access_accept_without_attributes(self):
        """B adds no attribute for carol, and radcli keeps no Message-Authenticator: radmavis-mt gets no pairs.

        radcli drops the attributes that its dictionary does not have. A
        build of B without OpenSSL sends no Message-Authenticator at all.
        """
        with open(RADCLI_DICTIONARY) as f:
            lines = [line for line in f if "Message-Authenticator" not in line]
        _, a = self.start_pair(dictionary=self.scratch_file("dictionary", "".join(lines)))
        with a.connect() as c:
            self.assertEqual(c.pap("carol", "carolpw").status_name, "PASS")

    def test_server_stopped(self):
        """No answer from the RADIUS server is a backend error: the fallback-only user can log in."""
        b, a = self.start_pair(check_server=False)
        with a.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")
        with a.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")
        self.assertEqual(b.stop(remove=False), [])
        with a.connect(timeout=10.0) as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "FAIL")
        with a.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS")

    def test_password_timeout_is_a_backend_error(self):
        """The RADIUS server gets the Access-Request and never answers: the fallback opens."""
        r = self.responder()
        a = self.start_client(r.port)
        with a.connect(timeout=10.0) as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "FAIL")
        with a.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "PASS")
        self.assertGreater(r.requests, 0)

    def test_mfa_timeout_is_a_failed_login(self):
        """No answer to the second factor is a push nobody approved, not a backend error: no fallback."""
        r = self.responder()
        a = self.start_client(r.port, template=MFA_CLIENT)
        with a.connect(timeout=10.0) as c:
            self.assertEqual(c.ascii_login("alice", "alicepw").status_name, "FAIL")
        self.assertGreater(r.requests, 0)
        with a.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")

    def test_access_challenge_is_a_failed_login(self):
        """radmavis-mt can't pass a challenge on: an Access-Challenge is a failed login, not a backend error."""
        r = self.responder((ACCESS_CHALLENGE, [(STATE, "otp"), (radius.REPLY_MESSAGE, "Enter OTP")]))
        a = self.start_client(r.port)
        with a.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "FAIL")
        self.assertGreater(r.requests, 0)
        with a.connect() as c:
            self.assertEqual(c.pap("rescue", "rescuepw").status_name, "FAIL")


if __name__ == "__main__":
    unittest.main()
