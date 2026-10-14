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

"""The harness checks itself: a green run must prove that crashes are seen.

Each test starts its own daemon, breaks it on purpose and asserts that the
detectors (tactest/detect.py) notice. Without these, a green run would not
show that a crash had been looked for.
"""

import os
import select
import shutil
import signal
import socket
import time
import unittest

from tactest import LINUX, DaemonTestCase, detect, sanitizers
from tactest.daemon import proc_stat

POLICY = """
	device single {
		address = 127.0.0.3
		key = tactest
		single-connection = yes
	}
	user alice {
		password login = clear alicepw
		password pap = clear alicepw
	}
	ruleset {
		rule { script { permit } }
	}
"""

def poll(fn, timeout):
    """Call fn() until it returns something true or the deadline passes."""
    deadline = time.monotonic() + timeout
    while True:
        value = fn()
        if value or time.monotonic() > deadline:
            return value
        select.select([], [], [], 0.05)


class Harness(DaemonTestCase):
    CONFIG = None       # every test starts and breaks its own daemon

    def start(self, body=POLICY, ports=(), **kw):
        """A daemon this test is about to break: no crash detectors at the end, but no leftovers either."""
        d = self.start_daemon(body, check=False, ports=ports, **kw)
        with d.connect() as c:          # make sure a worker serves this daemon
            self.assertTrue(c.pap("alice", "alicepw").ok)
        return d

    def only_worker(self, d):
        if not LINUX:
            self.skipTest("worker discovery needs /proc")
        # a worker on its way out may still be listed for a moment
        workers = poll(lambda: len(d.workers()) == 1 and d.workers(), 5)
        self.assertTrue(workers, "expected exactly one worker, got %s" % d.workers())
        return next(iter(workers))

    def test_harness_clean_daemon_has_no_problems(self):
        d = self.start()
        self.assertEqual(detect.Baseline(d).check(), [])

    def test_harness_detects_crash(self):
        """kill -SEGV of a worker: the debug-cmd marker sees it, or with ASan the sanitizer report."""
        d = self.start()
        base = detect.Baseline(d)
        os.kill(self.only_worker(d), signal.SIGSEGV)
        # ASan owns SIGSEGV (allow_user_segv_handler=0); otherwise the daemon's handler runs debug-cmd
        if "address" in sanitizers():
            detector, name = base.sanitizer, "sanitizer report"
        else:
            detector, name = base.marker, "debug-cmd marker"
        problems = poll(detector, 10)
        self.assertTrue(problems, "SIGSEGV of a worker went unnoticed by the %s" % name)
        print("\n  detected: %s" % problems[0].splitlines()[0], end=" ", flush=True)

    def test_harness_detects_abort(self):
        """SIGABRT is blocked in the worker and acted on in periodics: census, with polling."""
        d = self.start()
        base = detect.Baseline(d)
        os.kill(self.only_worker(d), signal.SIGABRT)
        self.assertTrue(poll(base.census, 15), "SIGABRT of a worker went unnoticed")

    def test_harness_detects_hang(self):
        d = self.start()
        base = detect.Baseline(d)
        worker = self.only_worker(d)
        os.kill(worker, signal.SIGSTOP)
        self.addCleanup(self._cont, worker)
        problems = base.hang()
        self.assertTrue(problems and "hung" in problems[0], problems)

    @staticmethod
    def _cont(pid):
        try:
            os.kill(pid, signal.SIGCONT)
        except OSError:
            pass

    def test_harness_detects_socket_held(self):
        d = self.start()
        base = detect.Baseline(d)
        self.only_worker(d)
        c = d.connect()
        self.addCleanup(c.close)
        self.assertTrue(c.pap("alice", "alicepw").ok)
        problems = base.sockets_held()
        self.assertTrue(problems and "TCP sockets" in problems[0], problems)
        c.close()
        self.assertEqual(base.sockets_held(), [])

    def test_harness_detects_report_between_tests(self):
        """A report written after one test's check is the next test's finding, not lost."""
        d = self.start()
        first = detect.Baseline(d)
        self.assertEqual(first.check(), [])
        with open(os.path.join(d.tmp, "crash.pids"), "a") as f:
            f.write("4242\n")
        second = detect.Baseline(d, since=first)
        self.assertEqual(len(second.marker()), 1, "lost between two tests")
        self.assertEqual(len(first.shutdown()), 1, "lost at shutdown")
        second.check()
        self.assertEqual(detect.Baseline(d, since=second).marker(), [], "reported twice")

    def test_harness_teardown_kills_detached_processes(self):
        """Workers setsid() and spawn MAVIS children: all must be gone after stop()."""
        if not LINUX:
            self.skipTest("process discovery needs /proc")
        # "exec = <path> <argv0> <args>": two children that never answer
        body = POLICY + """
	mavis module = external {
		exec = %s sleep 3600
		childs min = 2
		childs max = 2
	}
""" % shutil.which("sleep")
        d = self.start(body)
        worker = self.only_worker(d)
        procs = poll(lambda: len(d.descendants()) >= 3 and d.descendants(), 5)
        self.assertTrue(procs, "expected a worker and two MAVIS children, got %s" % d.descendants())
        # stop() has to find the children itself, as when a worker dies between two looks
        for pid in procs:
            if pid != worker:
                d.seen.pop(pid, None)
        # orphan the MAVIS children the way a crashing worker would
        os.kill(worker, signal.SIGKILL)
        children = [p for p in procs if p != worker]
        orphaned = poll(lambda: all((proc_stat(p) or ("X", 0))[1] != worker for p in children), 5)
        self.assertTrue(orphaned, "the MAVIS children were not reparented")
        self.assertEqual(d.stop(remove=False), [])
        survivors = [p for p, s in procs.items() if detect.alive(p, s)]
        self.assertEqual(survivors, [])

    def test_harness_retries_port_on_exit_75(self):
        """spawnd exits with EX_TEMPFAIL if it can't bind; start() then picks a new port."""
        with socket.socket() as busy:
            busy.bind(("127.0.0.1", 0))
            busy.listen(1)
            taken = busy.getsockname()[1]
            d = self.start(ports=[taken])
        self.assertEqual(d.exit_codes, [75])
        self.assertNotEqual(d.port, taken)

    def test_harness_reload_waits_for_new_generation(self):
        d = self.start()
        d.reload(POLICY.replace("alicepw", "newpw"))
        with d.connect() as c:
            self.assertTrue(c.pap("alice", "newpw").ok)
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "FAIL")



if __name__ == "__main__":
    unittest.main()
