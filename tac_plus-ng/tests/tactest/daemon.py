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

"""Run tac_plus-ng under spawnd, the way users run it.

One Daemon = one master process with its own scratch directory, config and
port. Workers are found through /proc (Linux) because they leave the
master's process group with setsid(), so killpg() can't reach them.
"""

import errno
import glob
import os
import re
import select
import shutil
import signal
import socket
import subprocess
import tempfile
import time

from . import config, radius
from .tacacs import Closed, Connection, ProtocolError

EX_TEMPFAIL = 75        # spawnd: failed to bind any listener
START_ATTEMPTS = 3
READY_TIMEOUT = 30.0
STOP_TIMEOUT = 5.0

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.dirname(HERE)
TOP = os.path.dirname(os.path.dirname(TESTS))

LINUX = os.path.isdir("/proc/self/task")


class DaemonError(Exception):
    pass


def build_os():
    """build/<OS> directory name, computed like GNUmakefile does."""
    u = os.uname()
    release = u.release
    if "(" in release:
        release = release[:release.index("(")] + release[release.index(")") + 1:]

    def norm(s):
        return s.lower().replace("/", "-").replace(" ", "-")
    return "%s-%s-%s" % (norm(u.sysname), norm(release), norm(u.machine))


def prefix():
    p = os.environ.get("TACTEST_PREFIX")
    if not p:
        p = os.path.join(TOP, "build", build_os(), "tests-prefix")
    return os.path.abspath(p)


def binary():
    path = os.path.join(prefix(), "sbin", "tac_plus-ng")
    if not os.access(path, os.X_OK):
        raise DaemonError("%s not found; run tac_plus-ng/tests/run-tests or set TACTEST_PREFIX" % path)
    return path


SUPPRESSIONS = os.path.join(TESTS, "ubsan.supp")


def symbolizer():
    """llvm-symbolizer for the stack traces of sanitizer reports.

    With the "clang" package alone, Ubuntu has it only as
    /usr/lib/llvm-<N>/bin/llvm-symbolizer, not on PATH; take the newest.
    """
    found = shutil.which("llvm-symbolizer")
    if found:
        return found
    candidates = glob.glob("/usr/lib/llvm-*/bin/llvm-symbolizer")
    candidates.sort(key=lambda p: int(re.search(r"llvm-(\d+)", p).group(1)))
    return candidates[-1] if candidates else None


def _quote(path):
    """A path as a sanitizer option value: the option parser splits at blanks."""
    return '"%s"' % path


def sanitizer_env(tmp=None, suppressions=SUPPRESSIONS):
    """Sanitizer runtime options; harmless for a binary built without them.

    allow_user_segv_handler=0: the daemon's own SIGSEGV handler would
    otherwise swallow the signal and ASan would print no report.
    detect_leaks=0: configuration pools live until the process exits, so
    LeakSanitizer reports them at every exit; leaks are a separate topic.
    report_error_type=1: the UBSan summary names the kind of error.

    ASAN_OPTIONS and UBSAN_OPTIONS from the environment come after these
    defaults, so they add to them and win where they set the same option.
    Only log_path is forced: reports go to files in tmp if given (the
    crash detectors read them there), else to stderr.
    """
    env = dict(os.environ)
    asan = ["allow_user_segv_handler=0", "detect_leaks=0", "abort_on_error=0"]
    ubsan = ["halt_on_error=1", "print_stacktrace=1", "report_error_type=1"]
    if suppressions:
        ubsan.append("suppressions=" + _quote(suppressions))
    path = symbolizer()
    if path:
        asan.append("external_symbolizer_path=" + _quote(path))
        ubsan.append("external_symbolizer_path=" + _quote(path))
    for options, name in ((asan, "ASAN_OPTIONS"), (ubsan, "UBSAN_OPTIONS")):
        if env.get(name):
            options.append(env[name])
    if tmp:
        asan.append("log_path=" + _quote(os.path.join(tmp, "asan")))
        ubsan.append("log_path=" + _quote(os.path.join(tmp, "ubsan")))
    env["ASAN_OPTIONS"] = ":".join(asan)
    env["UBSAN_OPTIONS"] = ":".join(ubsan)
    return env


_sanitizers = {}


def sanitizers():
    """{"address", "undefined"} as far as the daemon binary was built with them."""
    path = binary()
    if path not in _sanitizers:
        with open(path, "rb") as f:
            data = f.read()
        found = set()
        if b"__asan_init" in data:
            found.add("address")
        if b"__ubsan_handle_" in data:
            found.add("undefined")
        _sanitizers[path] = found
    return _sanitizers[path]


def scratch_dir(name):
    base = os.environ.get("TACTEST_WORKDIR")
    if base:
        os.makedirs(base, exist_ok=True)
    return tempfile.mkdtemp(prefix="tactest-%s-" % name, dir=base or None)


def free_port(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.bind((address, 0))
        return s.getsockname()[1]


def free_udp_port(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.bind((address, 0))
        return s.getsockname()[1]


_features = {}


def features():
    """What the daemon binary was built with, from "tac_plus-ng -v": {"pcre2", "openssl"}.

    "openssl" also means MS-CHAP, TLS and the RADIUS Message-Authenticator;
    "configure --minimum" leaves it out.
    """
    path = binary()
    if path not in _features:
        out = subprocess.run([path, "-v"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             env=sanitizer_env()).stdout.decode("utf-8", "replace")
        found = set()
        if "/PCRE2" in out:
            found.add("pcre2")
        if "/OpenSSL" in out:
            found.add("openssl")
        _features[path] = found
    return _features[path]


def parse_only(path, cwd=None, timeout=30):
    """tac_plus-ng -P path: (exit code, output); a negative code is the signal that killed the parser.

    Since #264 "-P" turns a parser killed by signal n into exit code 128 + n
    (mavis/spawnd_main.c), so a crashing configuration no longer hides behind
    exit code 0; map it back to the -n this returns for a signal.
    """
    p = subprocess.run([binary(), "-P", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       stdin=subprocess.DEVNULL, timeout=timeout, cwd=cwd, env=sanitizer_env())
    code = p.returncode
    out = p.stdout.decode("utf-8", "replace")
    if code >= 128:
        return 128 - code, out
    return code, out


def ipv6_available():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


# --- /proc ------------------------------------------------------------------

def proc_stat(pid):
    """(state, ppid, starttime, session id) or None if the process is gone."""
    try:
        with open("/proc/%d/stat" % pid) as f:
            data = f.read()
    except OSError:
        return None
    fields = data[data.rindex(")") + 2:].split()
    return fields[0], int(fields[1]), int(fields[19]), int(fields[3])


def all_processes():
    out = {}
    for name in os.listdir("/proc"):
        if name.isdigit():
            st = proc_stat(int(name))
            if st:
                out[int(name)] = st
    return out


def tcp_table(pid):
    """{socket inode: (local port, state)} of the network namespace of pid."""
    out = {}
    for name in ("tcp", "tcp6"):
        try:
            with open("/proc/%d/net/%s" % (pid, name)) as f:
                next(f)
                for line in f:
                    fields = line.split()
                    out[fields[9]] = (int(fields[1].rsplit(":", 1)[1], 16), fields[3])
        except (OSError, StopIteration):
            pass
    return out


def tcp_fds(pid):
    """[(local port, state)] of the TCP sockets among the open fds of pid."""
    table = tcp_table(pid)
    out = []
    try:
        fds = os.listdir("/proc/%d/fd" % pid)
    except OSError:
        return out
    for fd in fds:
        try:
            target = os.readlink("/proc/%d/fd/%s" % (pid, fd))
        except OSError:
            continue
        if target.startswith("socket:[") and target[8:-1] in table:
            out.append(table[target[8:-1]])
    return out


TCP_LISTEN = "0A"


def cpu_seconds(pid):
    """utime + stime of a process (Linux)."""
    with open("/proc/%d/stat" % pid) as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def alive(pid, starttime=None):
    """True unless the process is gone, a zombie, or a recycled PID."""
    st = proc_stat(pid)
    if st is None or st[0] in ("Z", "X"):
        return False
    return starttime is None or st[2] == starttime


# --- the daemon -------------------------------------------------------------

class Daemon:
    def __init__(self, body="", name="daemon", key=config.KEY, address="127.0.0.1",
                 spawnd="", top="", template=config.BASE, suppressions=SUPPRESSIONS, udp=False, listen=None):
        """udp: also listen for RADIUS on a UDP port (udp_port) of the same address.

        listen: more listeners on the same address, {name: options}, e.g.
        {"tls": "tls = yes", "radius": "protocol = UDP realm = r"}; each
        gets a port of its own, ports[name]. The first listener stays plain
        TACACS+, because the crash detectors probe it.
        """
        self.body, self.key, self.address = body, key, address
        self.udp = udp
        self.udp_port = None
        self.listen = dict(listen or {})
        self.ports = {}
        self.suppressions = suppressions
        self.spawnd, self.top, self.template = spawnd, top, template
        self.generation = 0
        self.tmp = scratch_dir(name)
        self.cfg = os.path.join(self.tmp, "tac_plus-ng.cfg")
        self.stderr_path = os.path.join(self.tmp, "stderr.log")
        self.proc = None
        self.port = None
        self.exit_codes = []        # of failed start attempts
        self.seen = {}              # pid -> starttime of every descendant ever seen

    # configuration

    def config_text(self):
        spawnd = self.spawnd
        if self.udp:
            spawnd += "\tlisten { address = %s port = %d protocol = UDP }\n" % (self.address, self.udp_port)
        for name, options in self.listen.items():
            spawnd += "\tlisten { address = %s port = %d %s }\n" % (self.address, self.ports[name], options)
        return config.render(self.template, tmp=self.tmp, address=self.address, port=self.port, key=self.key,
                             generation=self.generation, spawnd=spawnd, top=self.top, body=self.body)

    def write_config(self):
        tmp = self.cfg + ".new"
        with open(tmp, "w") as f:
            f.write(self.config_text())
        os.replace(tmp, self.cfg)

    # lifecycle

    @property
    def addr(self):
        return (self.address, self.port)

    @property
    def udp_addr(self):
        return (self.address, self.udp_port)

    @property
    def pid(self):
        return self.proc.pid

    def start(self, ports=()):
        """Start the master and wait until it accepts connections.

        A listener that can't bind makes spawnd exit with EX_TEMPFAIL; that
        is the race "port taken between picking and binding", so retry on a
        fresh port. Any other early exit is a failure.
        """
        ports = list(ports)
        for _ in range(START_ATTEMPTS):
            self.port = ports.pop(0) if ports else free_port(self.address)
            if self.udp:
                self.udp_port = free_udp_port(self.address)
            for name, options in self.listen.items():
                udp = re.search(r"protocol\s*=\s*udp", options, re.I)
                self.ports[name] = (free_udp_port if udp else free_port)(self.address)
            self.write_config()
            stderr = open(self.stderr_path, "ab")
            argv = [binary()]
            if os.environ.get("TACTEST_DEBUG"):
                argv += ["-d", os.environ["TACTEST_DEBUG"], "-D"]
            self.proc = subprocess.Popen(argv + ["-f", self.cfg], stderr=stderr, stdout=stderr,
                                         stdin=subprocess.DEVNULL,
                                         env=sanitizer_env(self.tmp, self.suppressions))
            stderr.close()
            code = self._wait_ready()
            if code is None:
                return self
            self.exit_codes.append(code)
            if code != EX_TEMPFAIL:
                break
        raise DaemonError("tac_plus-ng exited with code %s during startup (attempts: %s)\n%s"
                          % (self.exit_codes[-1], self.exit_codes, self.stderr_tail()))

    def _wait_ready(self):
        deadline = time.monotonic() + READY_TIMEOUT
        family = socket.AF_INET6 if ":" in self.address else socket.AF_INET
        while time.monotonic() < deadline:
            code = self.proc.poll()
            if code is not None:
                return code
            # spawnd binds before it forks the first worker
            if self._listening(family) and (not LINUX or self.workers()):
                self.snapshot()
                return None
            select.select([], [], [], 0.02)
        self.proc.kill()
        self.proc.wait()
        raise DaemonError("tac_plus-ng did not accept connections within %.0f s\n%s"
                          % (READY_TIMEOUT, self.stderr_tail()))

    def _listening(self, family):
        if LINUX:
            # not just "something accepts on the port": the port may belong to someone else
            return (self.port, TCP_LISTEN) in tcp_fds(self.pid)
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex(self.addr) == 0

    def stderr_tail(self, lines=30):
        try:
            with open(self.stderr_path, errors="replace") as f:
                return "".join(f.readlines()[-lines:])
        except OSError:
            return ""

    LOGS = ("authentication", "authorization", "accounting")

    def log_size(self, name):
        try:
            return os.path.getsize(os.path.join(self.tmp, name + ".log"))
        except OSError:
            return 0

    def read_log(self, name, offset=0):
        try:
            with open(os.path.join(self.tmp, name + ".log"), "rb") as f:
                f.seek(offset)
                return f.read().decode("utf-8", "replace")
        except FileNotFoundError:
            return ""

    def wait_log(self, name, text, timeout=5.0, offset=0):
        """Wait until log <name> (authentication, authorization, accounting) contains text.

        Only the part from byte offset on is searched; DaemonTestCase.wait_log()
        passes the size the log had when the test started. The worker writes
        log lines after it sent the reply, so a log is never checked right
        after the answer arrived.
        """
        deadline = time.monotonic() + timeout
        while True:
            content = self.read_log(name, offset)
            if text in content:
                return content
            if time.monotonic() > deadline:
                raise AssertionError("%r not in %s.log within %.0f s:\n%s" % (text, name, timeout, content[-2000:]))
            select.select([], [], [], 0.02)

    def connect(self, listener=None, **kw):
        """A TACACS+ connection to the first listener, or to ports[listener]."""
        kw.setdefault("timeout", 5.0)
        addr = self.addr if listener is None else (self.address, self.ports[listener])
        return Connection(addr, kw.pop("key", self.key), **kw)

    def radius(self, secret, tcp=False, listener=None, **kw):
        """A RADIUS client: UDP to udp_port, or RADIUS/TCP to the TACACS+ port (the daemon tells them apart).

        listener: to ports[listener] instead (TCP if tcp, else UDP).
        """
        kw.setdefault("timeout", 5.0)
        if listener is not None:
            addr = (self.address, self.ports[listener])
        else:
            addr = self.addr if tcp else self.udp_addr
        return radius.Client(addr, secret, tcp=tcp, **kw)

    def reload(self, body=None, probe=None, timeout=20.0):
        """Rewrite the config, SIGHUP the master, wait until a new connection sees it.

        spawnd keeps SIGHUP blocked and looks at pending signals only every
        eighth second (mavis/spawnd_main.c periodics), so a reload may take
        8 s before the re-exec even starts.

        The default probe logs in as tactest-generation-<N>, a user that only
        exists in the new configuration, so "port open again" is not enough.
        """
        if body is not None:
            self.body = body
        self.generation += 1
        self.write_config()
        os.kill(self.pid, signal.SIGHUP)
        user = "tactest-generation-%d" % self.generation

        def default_probe():
            with self.connect(timeout=1.0) as c:
                return c.pap(user, "tactest").ok
        probe = probe or default_probe
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise DaemonError("tac_plus-ng exited with code %s after SIGHUP\n%s"
                                  % (self.proc.returncode, self.stderr_tail()))
            try:
                if probe():
                    self.snapshot()
                    return
            except (OSError, Closed, ProtocolError, TimeoutError):
                pass
            select.select([], [], [], 0.05)
        raise DaemonError("configuration generation %d not visible within %.0f s\n%s"
                          % (self.generation, timeout, self.stderr_tail()))

    # processes

    def descendants(self):
        """{pid: starttime} of all live descendants of the master (Linux only)."""
        if not LINUX or self.proc is None:
            return {}
        procs = all_processes()
        out, todo = {}, [self.pid]
        while todo:
            parent = todo.pop()
            for pid, (state, ppid, start, _) in procs.items():
                if ppid == parent and pid not in out:
                    if state not in ("Z", "X"):
                        out[pid] = start
                    todo.append(pid)
        return out

    def workers(self):
        """{pid: starttime} of the master's live children running tac_plus-ng.

        Not every child is a worker: a sanitizer build forks llvm-symbolizer
        to match suppressions by function name.
        """
        if not LINUX or self.proc is None:
            return {}
        exe = os.path.realpath(binary())
        out = {}
        for pid, st in all_processes().items():
            if st[1] == self.pid and st[0] not in ("Z", "X"):
                try:
                    if os.path.realpath("/proc/%d/exe" % pid) == exe:
                        out[pid] = st[2]
                except OSError:
                    pass
        return out

    def snapshot(self):
        found = self.descendants()
        self.seen.update(found)
        return found

    def stop(self, remove=True):
        """Terminate master, workers and MAVIS children; return leftover problems.

        Every PID ever seen below the master is killed by PID. So is every
        process in the session of a worker seen: a worker calls setsid(), so
        the MAVIS children of a worker that died are found by their session
        id after they were reparented away from the master.
        """
        problems = []
        if self.proc is not None:
            self.snapshot()
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    problems.append("master %d ignored SIGTERM for %.0f s" % (self.pid, STOP_TIMEOUT))
                    self.proc.kill()
                    self.proc.wait()
            self._sweep_sessions()
            for pid, start in self.seen.items():
                if alive(pid, start):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except OSError as e:
                        if e.errno != errno.ESRCH:
                            raise
            deadline = time.monotonic() + STOP_TIMEOUT
            left = list(self.seen.items())
            while left and time.monotonic() < deadline:
                left = [(p, s) for p, s in left if alive(p, s)]
                if left:
                    select.select([], [], [], 0.02)
            if left:
                problems.append("processes survived SIGKILL: %s" % [p for p, _ in left])
        if remove:
            self.remove()
        return problems

    def _sweep_sessions(self):
        if not LINUX:
            return
        procs = all_processes()
        # a session leader we saw, unless its PID now belongs to someone else
        sessions = {pid: start for pid, start in self.seen.items()
                    if pid != os.getsid(0) and (pid not in procs or procs[pid][2] == start)}
        for pid, (state, _, start, sid) in procs.items():
            if sid in sessions and start >= sessions[sid] and state not in ("Z", "X"):
                self.seen.setdefault(pid, start)

    def remove(self):
        """Delete the scratch directory, unless TACTEST_KEEP is set."""
        if not os.environ.get("TACTEST_KEEP"):
            shutil.rmtree(self.tmp, ignore_errors=True)
