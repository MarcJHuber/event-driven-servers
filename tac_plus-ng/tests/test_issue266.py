# Copyright (C) 2026 TaranacLabs
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL ITS AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


"""#266: two ways of the external MAVIS module to leave a client without a reply.

1. A NUL byte in an answer: the daemon reads the answer as a C string
   (av_char_to_array()), so everything after the NUL -- among it the request
   type -- was lost and no reply was sent. mavis.py strips NUL bytes now, as
   the Perl backends do since #58.
2. A backend that answers one request twice: the stale answer arrives while
   the child works on the next request; the daemon killed the child "out of
   sync" and lost that request. read_from_child() hands it to a new child now,
   as it does for a child that dies before answering (#228).
"""

import time
import unittest

from tactest import DaemonTestCase, Stub

POLICY = Stub.module(childs=(1, 1)) + """
	user backend = mavis
	login backend = mavis
	pap backend = mavis
	ruleset {
		rule { script { permit } }
	}
"""


class MessageWithNul(DaemonTestCase):
    CONFIG = POLICY

    def test_issue266_failure_with_a_nul_in_the_message(self):
        """The text of an AD error with a NUL in it, as in #58; the client waited for ever."""
        Stub(self.daemon).set(users={"alice": {"password": "pw"}},
                              message="AcceptSecurityContext error\x00, data 52e")
        for login in (self.connect(timeout=4).pap, self.connect(timeout=4).ascii_login):
            with self.subTest(login=login.__name__):
                self.assertEqual(login("alice", "wrong").status_name, "FAIL")


class DoubleAnswer(DaemonTestCase):
    CONFIG = None

    def test_issue266_request_after_a_double_answer(self):
        d = self.start_daemon(POLICY)
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw"}}, double_write=True)
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
        # the second answer goes out only now, so it can't be read together with the first
        stub.release(1)
        deadline = time.monotonic() + 10
        while stub.requests()[-1]["result"] != "again" and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(stub.requests()[-1]["result"], "again")
        stub.set(users={"alice": {"password": "pw"}})
        with d.connect(timeout=4) as c:
            self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
        # the child that answered twice is killed as "out of sync", on purpose
        d.baseline.forget(stub.requests()[0]["pid"])


if __name__ == "__main__":
    unittest.main()
