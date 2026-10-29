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

import collections
import os
import select
import signal
import threading
import time
import unittest

from tactest import LINUX, Closed, DaemonTestCase, ProtocolError, detect
from tactest.daemon import free_port, proc_stat

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


def listeners(pid):
    """{(protocol, port): socket inode} of the listening TCP and the UDP sockets of pid (Linux)."""
    table = {}
    for name, proto, state in (("tcp", "tcp", "0A"), ("tcp6", "tcp", "0A"), ("udp", "udp", "07"), ("udp6", "udp", "07")):
        try:
            with open("/proc/%d/net/%s" % (pid, name)) as f:
                next(f)
                for line in f:
                    fields = line.split()
                    if fields[3] == state:
                        table[fields[9]] = (proto, int(fields[1].rsplit(":", 1)[1], 16))
        except (OSError, StopIteration):
            pass
    out = {}
    for fd in os.listdir("/proc/%d/fd" % pid):
        try:
            target = os.readlink("/proc/%d/fd/%s" % (pid, fd))
        except OSError:
            continue
        if target.startswith("socket:[") and target[8:-1] in table:
            out[table[target[8:-1]]] = target[8:-1]
    return out


@unittest.skipUnless(LINUX, "sockets and workers are found through /proc")
class ReloadKeepsListeners(DaemonTestCase):
    """SIGHUP re-executes spawnd; its listening sockets must survive that.

    The listeners were created with FD_CLOEXEC, so execve() closed them and
    the new image bound them again. In between the port was closed: new
    connections were refused, and those still in the listen backlog were
    reset. Every reload of the configuration did that to the clients.
    """

    CONFIG = None
    RELOADS = 3
    THREADS = 4

    def settle(self, d):
        """Wait until the workers retired by the reloads are gone, then take a new baseline.

        descendants(), not workers(): an exiting worker may no longer show
        its executable in /proc, but it isn't gone yet.
        """
        deadline = time.monotonic() + 10
        while len(d.descendants()) > 1 and time.monotonic() < deadline:
            select.select([], [], [], 0.05)
        self.assertEqual(list(d.descendants()), list(d.workers()), "retired workers did not exit")
        d.baseline = detect.Baseline(d, since=d.baseline)

    def test_sighup_keeps_the_listeners_under_load(self):
        d = self.start_daemon(POLICY, udp=True)
        before = listeners(d.pid)
        self.assertEqual(sorted(before), [("tcp", d.port), ("udp", d.udp_port)])

        failures = collections.Counter()
        done = [0]
        stop = threading.Event()

        def load():
            while not stop.is_set():
                try:
                    with d.connect(timeout=5.0) as c:
                        c.pap("alice", "alicepw")
                    done[0] += 1
                except (OSError, Closed, ProtocolError) as e:
                    failures[type(e).__name__] += 1

        threads = [threading.Thread(target=load) for _ in range(self.THREADS)]
        for t in threads:
            t.start()
        replaced = []
        try:
            for _ in range(self.RELOADS):
                d.reload()
                if listeners(d.pid) != before:
                    replaced.append(listeners(d.pid))
        finally:
            stop.set()
            for t in threads:
                t.join()
        self.assertGreater(done[0], 0)
        self.assertEqual(dict(failures), {}, "failed connections during %d reloads (%d succeeded)"
                         % (self.RELOADS, done[0]))
        self.assertEqual(replaced, [], "listening sockets replaced, before: %s" % before)
        self.settle(d)

    def test_sighup_honours_added_and_removed_listeners(self):
        d = self.start_daemon(POLICY, listen={"old": ""})
        before = listeners(d.pid)
        with d.connect(listener="old") as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")

        del d.listen["old"]
        d.listen["new"] = ""
        d.ports["new"] = free_port(d.address)
        d.reload()

        after = listeners(d.pid)
        self.assertEqual(sorted(after), sorted([("tcp", d.port), ("tcp", d.ports["new"])]))
        self.assertEqual(after[("tcp", d.port)], before[("tcp", d.port)], "the kept listener was replaced")
        with d.connect(listener="new") as c:
            self.assertEqual(c.pap("alice", "alicepw").status_name, "PASS")
        with self.assertRaises(ConnectionRefusedError):
            d.connect(timeout=2.0, listener="old").close()
        self.settle(d)
