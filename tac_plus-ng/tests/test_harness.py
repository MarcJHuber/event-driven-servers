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

from tactest import LINUX, SUPPRESSIONS, Closed, DaemonTestCase, ProtocolError, detect, sanitizers
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

UBSAN_WAIT = 5.0

# UBSan check name in ubsan.supp: the text of its runtime error
UBSAN_MESSAGES = {
    "bounds": "out of bounds for type",
    "nonnull-attribute": "null pointer passed as argument",
    "vla-bound": "variable length array bound evaluates to non-positive value",
    "signed-integer-overflow": "cannot be represented in type",
}


def _pap(d):
    with d.connect(timeout=2.0) as c:
        c.pap("alice", "alicepw")


def _author(d):
    with d.connect(timeout=2.0) as c:
        c.author("alice", ["service=shell", "cmd="])


def _acct(d):
    with d.connect(timeout=2.0) as c:
        c.acct("alice", ["task_id=1", "service=shell"])


def _two_sessions(d):
    """Two open sessions on one connection whose ids differ by more than INT_MAX.

    The ids read the same in either byte order, so the daemon compares
    0x7f00007f with (int) 0x80000080 on any host.
    """
    with d.connect(timeout=2.0, source="127.0.0.3", single_connect=True) as c:
        c.session(0x7F00007F).start(user="alice")
        c.session(0x80000080).start(user="alice")


# every reply type, and a connection with two sessions: each has its own findings
REQUESTS = (_pap, _author, _acct, _two_sessions)


def poll(fn, timeout):
    """Call fn() until it returns something true or the deadline passes."""
    deadline = time.monotonic() + timeout
    while True:
        value = fn()
        if value or time.monotonic() > deadline:
            return value
        select.select([], [], [], 0.05)


def suppressions(path=SUPPRESSIONS):
    """[(check, function)] of the active lines of a UBSan suppressions file."""
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                check, function = line.split(":", 1)
                out.append((check, function))
    return out


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

    def _ubsan_run(self, path):
        """Start a daemon with the suppressions in path, send requests, wait for UBSan reports."""
        d = self.start_daemon(POLICY, check=False, suppressions=path,
                              name="ubsan-%s" % os.path.basename(path))
        base = detect.Baseline(d)
        for request in REQUESTS:
            try:
                request(d)
            except (OSError, Closed, ProtocolError):
                pass                    # halt_on_error=1 may stop the worker mid-reply
        # a finding outside the request path (io_poll) needs a periodic tick
        return poll(base.sanitizer, UBSAN_WAIT)

    def test_harness_ubsan_suppressions_are_needed(self):
        """Every line of ubsan.supp still fires without it, and none fires with the whole file.

        An unused suppression is silently ignored, so a fixed finding would
        otherwise leave a line behind that hides the next one.
        """
        if "undefined" not in sanitizers():
            self.skipTest("built without UBSan")
        lines = suppressions()
        self.assertTrue(lines)
        self.assertEqual(self._ubsan_run(SUPPRESSIONS), [], "a finding ubsan.supp does not cover")
        for check, function in lines:
            with self.subTest(suppression="%s:%s" % (check, function)):
                path = os.path.join(self._scratch[0].tmp, "without-%s.supp" % function)
                with open(path, "w") as f:
                    f.writelines("%s:%s\n" % line for line in lines if line != (check, function))
                reports = "\n".join(self._ubsan_run(path))
                self.assertIn(check, UBSAN_MESSAGES, "add the runtime error text of %s to UBSAN_MESSAGES" % check)
                self.assertIn(UBSAN_MESSAGES[check], reports,
                              "drop %s:%s from ubsan.supp, it no longer fires" % (check, function))
                if "#0 " in reports:        # some reports come without a stack trace
                    self.assertIn(" in %s " % function, reports)


if __name__ == "__main__":
    unittest.main()
