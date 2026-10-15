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


"""#261: four findings of ASan/UBSan.

1. spawnd_accepted() hashed the protocol byte for the sticky cache after
   its scope had ended. clang -O2 drops the store, so the sticky cache
   didn't keep the connections of one address on one worker.
2. io_poll(): "int unreg[cax]" with cax == 0 (UBSan vla-bound).
3. send_authen_reply(): memcpy(p, NULL, 0) (UBSan nonnull-attribute).
4. mavis_method_add() called Mavis_new() through another function type
   (UBSan function).

1 is visible in an optimized clang build (tested here); 2, 3 and 4 in
any UBSan run, whose reports fail the crash detectors.
"""

import os
import unittest

from tactest import LINUX, DaemonTestCase, config

STICKY = config.BASE.replace("spawn { instances min = 1 instances max = 1 }", """\
spawn { instances min = 2 instances max = 2 users min = 1 users max = 10 }
	sticky cache period = 300""")

POLICY = """
	mavis module = null { }
	user alice {
		password pap = clear alicepw
	}
	ruleset {
		rule { script { permit } }
	}
"""

CONNECTIONS = 4
ROUNDS = 3


def worker_of(daemon, client_port):
    """PID of the worker holding the daemon's end of the connection from client_port."""
    for pid in daemon.workers():
        inodes = set()
        for fd in os.listdir("/proc/%d/fd" % pid):
            try:
                target = os.readlink("/proc/%d/fd/%s" % (pid, fd))
            except OSError:
                continue
            if target.startswith("socket:["):
                inodes.add(target[8:-1])
        for name in ("tcp", "tcp6"):
            with open("/proc/%d/net/%s" % (pid, name)) as f:
                next(f)
                for line in f:
                    fields = line.split()
                    if int(fields[2].rsplit(":", 1)[1], 16) == client_port and fields[9] in inodes:
                        return pid
    return None


class Sanitizers(DaemonTestCase):
    CONFIG = None

    @unittest.skipUnless(LINUX, "needs /proc")
    def test_issue261_sticky_cache_one_worker_per_address(self):
        self.assertNotEqual(STICKY, config.BASE)
        d = self.start_daemon(POLICY, template=STICKY)
        workers = None
        for i in range(ROUNDS):
            conns = [self.connect(daemon=d) for _ in range(CONNECTIONS)]
            pids = []
            for c in conns:
                self.assertTrue(c.pap("alice", "alicepw").ok)
                pids.append(worker_of(d, c.sock.getsockname()[1]))
            with self.subTest(round=i):
                self.assertEqual(len(set(pids)), 1, "connections from 127.0.0.1 on workers %s" % pids)
            workers = workers or d.workers()
            for c in conns:
                c.close()
        self.assertEqual(len(workers), 2, "the test needs two workers")


if __name__ == "__main__":
    unittest.main()
