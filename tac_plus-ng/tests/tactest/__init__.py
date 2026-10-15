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

"""Test harness for tac_plus-ng: daemon control, crash detectors, clients.

A test class derives from DaemonTestCase and sets CONFIG to the policy
body (see config.BASE for what surrounds it). The daemon is started once
per class; the crash detectors run after every test, so a crash is pinned
to the test that caused it. A test that needs a daemon of its own (a
configuration the tree under test may not parse, a reload) sets CONFIG =
None and calls self.start_daemon(body): the same detectors run when the
test ends.

Environment:
  TACTEST_PREFIX   install prefix of the daemon under test
  TACTEST_WORKDIR  where scratch directories go (default: system temp)
  TACTEST_KEEP     keep scratch directories even if the tests pass
  TACTEST_DEBUG    debug mask, passed as "-d <mask> -D"
"""

import sys
import unittest

from . import config, daemon, detect, mavis_stub, radius, tacacs, tls
from .daemon import (LINUX, SUPPRESSIONS, Daemon, DaemonError, binary, cpu_seconds, features, ipv6_available, prefix,
                     sanitizers)
from .mavis_stub import Stub
from .tacacs import Closed, Connection, Packet, ProtocolError

__all__ = ["DaemonTestCase", "Daemon", "DaemonError", "Connection", "Packet", "Closed", "ProtocolError", "Stub",
           "binary", "cpu_seconds", "prefix", "sanitizers", "features", "ipv6_available", "config", "detect",
           "mavis_stub", "radius", "tacacs", "tls", "LINUX", "SUPPRESSIONS", "SOURCE"]

# top of the source tree: the samples, the RADIUS dictionary
SOURCE = daemon.TOP


class DaemonTestCase(unittest.TestCase):
    """A test class with a daemon per class (CONFIG) or per test (start_daemon).

    The crash detectors run after every test and once more after the
    daemon was stopped. Scratch directories of failed tests are kept.
    """

    CONFIG = ""             # policy body; None: the tests start their own daemons
    ADDRESS = "127.0.0.1"
    SPAWND = ""
    TOP = ""
    UDP = False             # also listen for RADIUS over UDP
    LISTEN = None           # more listeners, {name: options}; see Daemon

    daemon = None
    _failed = False
    _last = None            # Baseline of the latest test on the class daemon

    @classmethod
    def setUpClass(cls):
        cls._failed = False
        cls._last = None
        if cls.CONFIG is None:
            return
        cls.daemon = Daemon(cls.CONFIG, name=cls.__name__, address=cls.ADDRESS, spawnd=cls.SPAWND, top=cls.TOP,
                            udp=cls.UDP, listen=cls.LISTEN)
        try:
            cls.daemon.start()
        except Exception:
            cls.daemon.stop(remove=False)
            print("\nkept %s" % cls.daemon.tmp, file=sys.stderr)
            raise
        cls._last = detect.Baseline(cls.daemon)

    @classmethod
    def tearDownClass(cls):
        if cls.daemon is None:
            return
        problems = cls.daemon.stop(remove=False)
        if cls._last is not None:
            problems += ["after the last test: " + p for p in cls._last.shutdown()]
        if cls._failed or problems:
            print("\nkept %s" % cls.daemon.tmp, file=sys.stderr)
        else:
            cls.daemon.remove()
        cls.daemon = None
        if problems:
            raise AssertionError("teardown: " + "; ".join(problems))

    def run(self, result=None):
        self._scratch = []
        before = self._bad(result)
        out = super().run(result)
        failed = result is not None and self._bad(result) != before
        if failed:
            type(self)._failed = True
        for d in self._scratch:
            if failed:
                print("\nkept %s" % d.tmp, file=sys.stderr)
            else:
                d.remove()
        return out

    @staticmethod
    def _bad(result):
        if result is None:
            return 0
        return len(result.failures) + len(result.errors) + len(getattr(result, "unexpectedSuccesses", ()))

    def setUp(self):
        if self.daemon is not None:
            # registered first, so it runs last: after every connection is closed
            self.addCleanup(self._check_daemon)
            self.rebaseline()

    def _check_daemon(self):
        problems = self.baseline.check()
        if problems:
            self.fail("daemon problems after the test:\n" + "\n".join(problems))

    def rebaseline(self):
        """Call after a deliberate change of the process set (reload, kill)."""
        self.baseline = detect.Baseline(self.daemon, since=type(self)._last)
        type(self)._last = self.baseline

    def start_daemon(self, body="", check=True, ports=(), **kw):
        """Start a daemon for this test only; stopped and checked when the test ends.

        check=False skips the crash detectors (a test that breaks the
        daemon on purpose); leftover processes still fail the test.
        Keyword arguments go to Daemon.
        """
        kw.setdefault("name", self.id().split(".")[-1])
        d = Daemon(body, **kw)
        d.baseline = None
        self._scratch.append(d)
        self.addCleanup(self._finish_daemon, d, check)
        d.start(ports)
        if check:
            d.baseline = detect.Baseline(d)
        return d

    def _finish_daemon(self, d, check):
        base = d.baseline if check else None
        problems = base.check() if base else []
        problems += d.stop(remove=False)
        if base:
            problems += ["after stop: " + p for p in base.shutdown()]
        if problems:
            self.fail("daemon problems after the test:\n" + "\n".join(problems))

    def connect(self, daemon=None, **kw):
        c = (daemon or self.daemon).connect(**kw)
        self.addCleanup(c.close)
        return c

    def radius(self, secret, daemon=None, **kw):
        c = (daemon or self.daemon).radius(secret, **kw)
        self.addCleanup(c.close)
        return c

    def wait_log(self, name, text, timeout=5.0, daemon=None):
        """Daemon.wait_log() on what the test itself caused: from the size the log had at its start."""
        d = daemon or self.daemon
        base = d.baseline if daemon is not None else self.baseline
        return d.wait_log(name, text, timeout, offset=base.logs.get(name, 0) if base else 0)
