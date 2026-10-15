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


"""spawnd and the workers: signals, connection life time."""

import os
import select
import signal
import time
import unittest

from tactest import LINUX, DaemonTestCase, detect
from tactest.daemon import proc_stat

POLICY = """
	user alice { password pap = clear alicepw }
	ruleset {
		rule { script { permit } }
	}
"""


class MayClose(DaemonTestCase):
    """#251: "single-connection may-close = yes" had no effect.

    The setting was parsed into the device, but the code that closes the
    connection looked at a copy in the connection context that was never
    set.
    """

    CONFIG = """
	single-connection may-close = yes
	device single {
		address = 127.0.0.3
		key = tactest
		single-connection = yes
	}
""" + POLICY

    def test_issue251_connection_closed_after_the_session(self):
        c = self.connect()
        self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")
        self.assertTrue(c.closed(timeout=3), "the daemon kept the connection open")

    def test_issue251_single_connect_flag_keeps_the_connection(self):
        """A client that asks for single-connection, on a device that allows it, keeps the connection."""
        c = self.connect(source="127.0.0.3", single_connect=True)
        for _ in range(2):
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")


class KeepOpen(DaemonTestCase):
    """Without may-close the daemon answers further sessions on a connection, flag or not."""

    CONFIG = POLICY

    def test_two_sessions_without_the_flag(self):
        c = self.connect()
        for _ in range(2):
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")


@unittest.skipUnless(LINUX, "workers are found through /proc")
class StopAndContinue(DaemonTestCase):
    """#255: epoll_wait() interrupted (EINTR) made master and worker exit with status 70.

    Linux lets epoll_wait() fail with EINTR when the process was stopped and
    continued -- SIGSTOP/SIGCONT, a debugger attaching, the freezer of a
    container snapshot (the case in #255) -- even without a signal handler.
    io_sched.c took every error of the poll call for fatal. Both processes
    must sleep in epoll_wait() when stopped, so the test waits for idle.
    """

    CONFIG = POLICY
    STOPPED = 0.5

    def stop_and_continue(self, pid):
        os.kill(pid, signal.SIGSTOP)
        deadline = time.monotonic() + 5
        while proc_stat(pid)[0] != "T" and time.monotonic() < deadline:
            select.select([], [], [], 0.02)
        self.assertEqual(proc_stat(pid)[0], "T", "process %d did not stop" % pid)
        select.select([], [], [], self.STOPPED)
        os.kill(pid, signal.SIGCONT)

    def test_issue255_worker_survives_stop_and_continue(self):
        self.assertEqual(self.connect().pap("alice", "alicepw").status_name, "PASS")
        (worker,) = self.daemon.workers()
        self.stop_and_continue(worker)
        self.assertEqual(self.connect().pap("alice", "alicepw").status_name, "PASS")
        self.assertEqual(list(self.daemon.workers()), [worker], "the worker was replaced")

    def test_issue255_master_survives_stop_and_continue(self):
        self.stop_and_continue(self.daemon.pid)
        # the master looks at its state once per second (periodics)
        select.select([], [], [], 1.5)
        self.assertIsNone(self.daemon.proc.poll(), "master exited:\n" + self.daemon.stderr_tail())
        self.assertEqual(self.connect().pap("alice", "alicepw").status_name, "PASS")


@unittest.skipUnless(LINUX, "workers are found through /proc")
class AbandonWorkers(DaemonTestCase):
    """#252: SIGUSR1 to the master made it exit with status 70 instead of abandoning its workers.

    tac_plus-ng.txt: "Sending SIGUSR1 to the master process will cause it
    to abandon existing child processes (these will continue to serve the
    existing connections only) and start new child processes."
    """

    CONFIG = None
    WATCH = 5.0

    def test_issue252_sigusr1_abandons_the_workers(self):
        d = self.start_daemon(POLICY)
        (old,) = d.workers()
        held = self.connect(daemon=d)
        self.assertEqual(held.pap("alice", "alicepw").status_name, "PASS")

        os.kill(d.pid, signal.SIGUSR1)
        deadline = time.monotonic() + self.WATCH
        new = set()
        while time.monotonic() < deadline:
            self.assertIsNone(d.proc.poll(), "master exited after SIGUSR1:\n" + d.stderr_tail())
            with d.connect() as c:
                self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")
            new |= set(d.workers()) - {old}
            select.select([], [], [], 0.25)
        self.assertTrue(new, "no new worker within %.0f s" % self.WATCH)
        self.assertEqual(held.pap("alice", "alicepw").status_name, "PASS", "the abandoned worker stopped serving")
        held.close()
        # the abandoned worker leaves when its last connection is gone
        d.baseline = detect.Baseline(d, since=d.baseline)
        d.baseline.forget(old)
