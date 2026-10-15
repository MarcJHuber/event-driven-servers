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

"""Worker crash detectors.

spawnd restarts a dead worker and the next request succeeds, so a crash is
invisible to the client. No single detector sees every kind of crash, hence
several, all checked after every test:

  1 marker     debug-cmd appends $CRASHPID to crash.pids from the SIGSEGV
               handler (any OS; not with ASan, which owns SIGSEGV there)
  2 sanitizer  non-empty ASan/UBSan report files in the scratch directory
  3 census     a process that was below the master when the test started is
               gone or a zombie (Linux): SIGABRT, SIGBUS, exit() on a fatal
               error, a dead MAVIS child
  4 hang       a fresh connection gets no reply within 5 s although the
               worker exists: deadlock in the SIGSEGV handler, endless loop
  5 sockets    a worker still holds TCP sockets after every client closed
               its connection (Linux): the "connection closed, fd not" class
"""

import glob
import os
import select
import time

from .daemon import LINUX, alive, tcp_fds
from .tacacs import Closed, ProtocolError

PROBE_TIMEOUT = 5.0
SOCKET_SETTLE = 3.0
REPORT_LIMIT = 4000


def _read_from(path, offset):
    """(text from byte offset on, offset after it)."""
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read()
    except OSError:
        return "", offset
    return data.decode("utf-8", "replace"), offset + len(data)


def _size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def sanitizer_reports(tmp):
    return {p: _size(p) for p in glob.glob(os.path.join(tmp, "asan.*")) + glob.glob(os.path.join(tmp, "ubsan.*"))}


def tcp_sockets(pid):
    return len(tcp_fds(pid))


class Baseline:
    """State before a test; check() compares against it.

    since: the Baseline of the previous test on the same daemon. Crash
    markers and sanitizer reports are then read from where its check()
    stopped, so nothing written between two tests is lost; check() moves
    that position forward over what it reported.
    """

    def __init__(self, daemon, since=None):
        self.daemon = daemon
        if since is not None:
            self.crash_offset, self.reports = since.crash_offset, dict(since.reports)
        else:
            self.crash_offset, self.reports = _size(self._crash_file), sanitizer_reports(daemon.tmp)
        self._read = (self.crash_offset, dict(self.reports))
        self.processes = daemon.snapshot()
        self.sockets = {pid: tcp_sockets(pid) for pid in daemon.workers()} if LINUX else {}
        self.logs = {name: daemon.log_size(name) for name in daemon.LOGS}

    @property
    def _crash_file(self):
        return os.path.join(self.daemon.tmp, "crash.pids")

    def forget(self, pid):
        """The test killed or retired this process on purpose."""
        self.processes.pop(pid, None)

    # the detectors; each returns a list of problems

    def marker(self):
        text, end = _read_from(self._crash_file, self.crash_offset)
        self._read = (end, self._read[1])
        return ["worker crashed (SIGSEGV handler ran for pid %s)" % p for p in text.split()]

    def sanitizer(self):
        out, read = [], {}
        for path, size in sorted(sanitizer_reports(self.daemon.tmp).items()):
            old = self.reports.get(path, 0)
            read[path] = old
            if size > old:
                text, read[path] = _read_from(path, old)
                out.append("sanitizer report %s:\n%s" % (os.path.basename(path), text[:REPORT_LIMIT]))
        self._read = (self._read[0], read)
        return out

    def census(self):
        if not LINUX:
            return []
        out = []
        code = self.daemon.proc.poll()
        if code is not None:
            out.append("master exited with code %s\n%s" % (code, self.daemon.stderr_tail()))
        for pid, start in sorted(self.processes.items()):
            if not alive(pid, start):
                out.append("process %d below the master died during the test" % pid)
        return out

    def hang(self):
        """A fresh login of the user every configuration has (config.BASE).

        A successful login, because a failed one is answered only after
        the daemon's failure delay of a second or more.
        """
        if self.daemon.proc.poll() is not None:
            return []
        try:
            with self.daemon.connect(timeout=PROBE_TIMEOUT) as c:
                c.pap("tactest-generation-%d" % self.daemon.generation, "tactest")
        except TimeoutError:
            return ["worker hung: no reply to a fresh request within %.0f s" % PROBE_TIMEOUT]
        except Closed:
            return ["daemon closed a fresh connection without replying"]
        except ProtocolError as e:
            return ["daemon sent a malformed reply to a fresh request: %s" % e]
        except OSError as e:
            return ["daemon does not accept connections: %s" % e]
        return []

    def sockets_held(self):
        if not LINUX:
            return []
        deadline = time.monotonic() + SOCKET_SETTLE
        while True:
            over = {}
            for pid in self.daemon.workers():
                n, base = tcp_sockets(pid), self.sockets.get(pid, 0)
                if n > base:
                    over[pid] = (n, base)
            if not over or time.monotonic() > deadline:
                break
            select.select([], [], [], 0.05)
        return ["worker %d holds %d TCP sockets after the test (before: %d)" % (pid, n, base)
                for pid, (n, base) in sorted(over.items())]

    def check(self):
        """All detectors, census first: the hang probe may spawn a new worker."""
        problems = self.census()
        problems += self.hang()
        problems += self.marker()
        problems += self.sanitizer()
        problems += self.sockets_held()
        self.crash_offset, self.reports = self._read
        return problems

    def shutdown(self):
        """Crash markers and sanitizer reports written since check(), e.g. by stop()."""
        return self.marker() + self.sanitizer()
