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

import ast
import contextlib
import glob
import io
import os
import select
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
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


def py38_annotation_errors(source):
    """The lines of annotations that Python 3.8 cannot evaluate (README: Python 3.8).

    It evaluates class, module and def annotations at import time, or when
    the def runs: a builtin generic (list[int]) or a union (int | None)
    raises TypeError there. A Literal[...] holds values, not types.
    """
    tree = ast.parse(source)
    if any(isinstance(n, ast.ImportFrom) and n.module == "__future__" and any(a.name == "annotations" for a in n.names)
           for n in tree.body):
        return []

    def evaluated(body, in_def=False):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = node.args
                yield from (x.annotation for x in a.posonlyargs + a.args + a.kwonlyargs + [a.vararg, a.kwarg]
                            if x is not None and x.annotation is not None)
                if node.returns is not None:
                    yield node.returns
                yield from evaluated(node.body, True)
            elif isinstance(node, ast.ClassDef):
                # a class body runs at once, also in a def
                yield from evaluated(node.body)
            elif isinstance(node, ast.AnnAssign) and not in_def:
                yield node.annotation
            else:
                for field in ("body", "orelse", "finalbody", "handlers"):
                    yield from evaluated(getattr(node, field, []), in_def)

    def types(node):
        if isinstance(node, ast.Subscript) and getattr(node.value, "id", getattr(node.value, "attr", None)) == "Literal":
            return
        yield node
        for child in ast.iter_child_nodes(node):
            yield from types(child)

    found = set()
    for annotation in evaluated(tree.body):
        for n in types(annotation):
            if (isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name)
                    and n.value.id in ("dict", "list", "tuple", "set", "frozenset", "type")) or (
                    isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr)):
                found.add(n.lineno)
    return sorted(found)


def quoted_source_values(source, name="TLS_OPTIONS"):
    """The lines of f-strings for name (a dict key or a keyword) that put a value in quotes.

    The LDAP back-ends evaluate TLS_OPTIONS as Perl or Python source: a
    quote in the value ends such a string. Make the literal of the value
    with repr() or perl_string().
    """
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Dict):
            values = [v for k, v in zip(node.keys, node.values) if isinstance(k, ast.Constant) and k.value == name]
        elif isinstance(node, ast.keyword) and node.arg == name:
            values = [node.value]
        else:
            continue
        for value in values:
            parts = value.values if isinstance(value, ast.JoinedStr) else []
            for before, part in zip(parts, parts[1:]):
                if (isinstance(part, ast.FormattedValue) and isinstance(before, ast.Constant)
                        and before.value.endswith(("'", '"'))):
                    found.add(value.lineno)
    return sorted(found)


class TestFiles(unittest.TestCase):
    """A worker reads its configuration when it starts, which can be after the test removed a file in it."""

    def test_no_daemon_starts_inside_a_temporary_directory(self):
        found = []
        for path in sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_*.py"))):
            with open(path) as f:
                tree = ast.parse(f.read())
            for node in ast.walk(tree):
                if isinstance(node, ast.With) and any(
                        isinstance(i.context_expr, ast.Call) and getattr(i.context_expr.func, "attr", "") == "TemporaryDirectory"
                        for i in node.items):
                    found += ["%s:%d" % (os.path.basename(path), call.lineno) for call in ast.walk(node)
                              if isinstance(call, ast.Call) and getattr(call.func, "attr", "") == "start_daemon"]
        self.assertEqual(found, [], "write the files of the daemon with self.scratch_file()")

    def test_annotations_import_on_python_3_8(self):
        found = []
        here = os.path.dirname(os.path.abspath(__file__))
        for path in sorted(glob.glob(os.path.join(here, "test_*.py")) + glob.glob(os.path.join(here, "tactest", "*.py"))):
            with open(path) as f:
                found += ["%s:%d" % (os.path.relpath(path, here), n) for n in py38_annotation_errors(f.read())]
        self.assertEqual(found, [], "add 'from __future__ import annotations', or use typing.Dict and typing.Optional")

    def test_tls_options_quote_with_a_function(self):
        found = []
        for path in sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_*.py"))):
            with open(path) as f:
                found += ["%s:%d" % (os.path.basename(path), n) for n in quoted_source_values(f.read())]
        self.assertEqual(found, [], "TLS_OPTIONS is source code: use repr() or perl_string() for a value in it")

    def test_quoted_source_values(self):
        for source, lines in (("{'TLS_OPTIONS': f\"cafile => '{ca}'\"}", [1]),
                              ("f(TLS_OPTIONS=f'ca_certs_file=\"{ca}\"')", [1]),
                              ("{'TLS_OPTIONS': f'cafile => {perl_string(ca)}, {names}'}", []),
                              ("{'OTHER': f\"x='{ca}'\"}", [])):
            with self.subTest(source=source):
                self.assertEqual(quoted_source_values(source), lines)

    def test_py38_annotation_errors(self):
        for source, lines in (("x: Literal[1 | 2] = 3", []),         # an integer OR is a value, also in Literal
                              ("x: int | None = None", [1]),
                              ("def f(a: dict[str, int]): pass", [1]),
                              ("def f():\n    x: list[int] = []", []),
                              ("def f():\n    class C:\n        x: list[int] = []", [3]),
                              ("from __future__ import annotations\nx: int | None = None", [])):
            with self.subTest(source=source):
                self.assertEqual(py38_annotation_errors(source), lines)

class ScratchFiles(unittest.TestCase):
    """A failed test keeps its scratch files, also when run() makes its own result."""

    def test_run_without_a_result_keeps_the_files_of_a_failed_test(self):
        paths = []

        class Failing(DaemonTestCase):
            CONFIG = None

            def test_fails(self):
                paths.append(self.scratch_file("hosts", "127.0.0.9 nas\n"))
                self.fail("on purpose")

        with contextlib.redirect_stderr(io.StringIO()):
            out = Failing("test_fails").run()
        self.addCleanup(shutil.rmtree, os.path.dirname(paths[0]), True)
        self.assertEqual(len(out.failures), 1)
        self.assertTrue(os.path.exists(paths[0]), "run() removed the files of a failed test")


class SambaDcStart(unittest.TestCase):
    """samba-dc/start, its README commands and its CI steps, with stand-ins for docker and openssl."""

    here = os.path.dirname(os.path.abspath(__file__))
    # the DC is up at once on port 1636; each call of docker is logged
    DOCKER = 'echo "$*" >> "$TACTEST_DOCKER_LOG"; case $1 in port) echo 127.0.0.1:1636;; cp) : > "$3";; inspect) echo true;; esac'
    OPENSSL = "case $1 in rand) echo 0123456789abcdef01234567;; esac"
    # without the deadline: the tests do not need timeout(1) on the host
    TIMEOUT = 'while [ "${1#-}" != "$1" ]; do case $1 in -k|-s) shift;; esac; shift; done; shift; exec "$@"'
    RUN_TESTS = 'printf "%s\\n" "$TACTEST_SAMBA_DC" "$TACTEST_SAMBA_CA"'

    def checkout(self, tmp, name, docker=DOCKER, openssl=OPENSSL, timeout=TIMEOUT, run_tests=RUN_TESTS):
        """A checkout <tmp>/<name> with samba-dc/start and a run-tests that prints two settings; returns its run().

        timeout=None: the timeout(1) of the host.
        """
        top = os.path.join(tmp, name)
        tests = os.path.join(top, "tac_plus-ng", "tests")
        os.makedirs(os.path.join(tests, "samba-dc"))
        shutil.copy(os.path.join(self.here, "samba-dc", "start"), os.path.join(tests, "samba-dc"))
        bin_dir = os.path.join(top, "bin")
        os.mkdir(bin_dir)
        stubs = [(os.path.join(bin_dir, "docker"), docker), (os.path.join(bin_dir, "openssl"), openssl),
                 (os.path.join(tests, "run-tests"), run_tests)]
        if timeout is not None:
            stubs.append((os.path.join(bin_dir, "timeout"), timeout))
        for path, body in stubs:
            with open(path, "w") as f:
                f.write("#!/bin/sh\n" + body + "\n")
            os.chmod(path, 0o755)
        # the settings of a DC of the caller must not reach the commands
        env = dict({k: v for k, v in os.environ.items() if not k.startswith("TACTEST_SAMBA_")},
                   PATH=bin_dir + os.pathsep + os.environ["PATH"],
                   TACTEST_DOCKER_LOG=os.path.join(top, "docker.log"))

        def run(script, timeout=60):
            return subprocess.run(["sh", "-c", script], cwd=top, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, timeout=timeout, check=False)
        return top, run

    def readme_commands(self):
        with open(os.path.join(self.here, "README")) as f:
            blocks = [b for b in f.read().split("\n\n") if "tac_plus-ng/tests/samba-dc/start" in b]
        self.assertEqual(len(blocks), 1, "the README has no single command block for samba-dc/start")
        return "\n".join(line.strip() for line in blocks[0].splitlines())

    def test_readme_import_keeps_the_path(self):
        """A blank and a backslash in the checkout path: the echo of dash would make a tab of "\\t"."""
        for name in ("ad tests", "ad\\tests"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                top, run = self.checkout(tmp, name)
                p = run(self.readme_commands())
                self.assertEqual(p.stdout.splitlines(),
                                 ["ldaps://127.0.0.1:1636", os.path.join(top, "build", "samba-dc", "ca.pem")], p.stderr)

    def test_readme_commands_keep_the_settings_out_of_the_shell(self):
        """The README commands remove the container also when the tests fail, and exit with the status of the tests."""
        with tempfile.TemporaryDirectory() as tmp:
            top, run = self.checkout(tmp, "ad", run_tests="exit 7")
            p = run(self.readme_commands() + '\nrc=$?; echo "DC=${TACTEST_SAMBA_DC-unset}"; exit $rc')
            self.assertEqual((p.returncode, p.stdout), (7, "DC=unset\n"), p.stderr)
            with open(os.path.join(top, "docker.log")) as f:
                log = f.read().splitlines()
            self.assertEqual([line.split()[0] for line in log if line.split()[0] in ("run", "rm")], ["rm", "run", "rm"])

    def test_readme_commands_stop_when_start_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, run = self.checkout(tmp, "ad", docker="exit 1")
            p = run(self.readme_commands())
            self.assertEqual(p.stdout, "", "run-tests ran without a DC, so the AD tests skip and the run can pass")

    def test_each_checkout_has_its_own_container(self):
        names = []
        with tempfile.TemporaryDirectory() as tmp:
            for checkout in ("a", "b"):
                top, run = self.checkout(tmp, checkout)
                p = run("tac_plus-ng/tests/samba-dc/start")
                self.assertEqual(p.returncode, 0, p.stderr)
                name = dict(line.split("=", 1) for line in p.stdout.splitlines())["TACTEST_SAMBA_CONTAINER"]
                with open(os.path.join(top, "docker.log")) as f:
                    log = f.read().splitlines()
                self.assertIn("rm -f " + name, log)
                self.assertEqual([line for line in log if line.startswith("rm ")], ["rm -f " + name])
                names.append(name)
        self.assertNotEqual(names[0], names[1], "a start in one checkout removes the DC of the other")

    @unittest.skipUnless(shutil.which("timeout"), "no timeout(1)")
    def test_tls_probe_has_a_deadline(self):
        """A DC that accepts but does not answer the TLS handshake: start gives up, prints the logs, removes the DC."""
        docker = self.DOCKER.replace("inspect) echo true", "inspect) echo false")
        openssl = "case $1 in rand) echo 0123456789abcdef01234567;; s_client) exec sleep 120;; esac"
        with tempfile.TemporaryDirectory() as tmp:
            top, run = self.checkout(tmp, "ad", docker=docker, openssl=openssl, timeout=None)
            try:
                p = run("tac_plus-ng/tests/samba-dc/start", timeout=30)
            except subprocess.TimeoutExpired:
                self.fail("start waits for the TLS handshake without a deadline")
            self.assertEqual(p.returncode, 1)
            self.assertIn("the DC does not answer", p.stderr)
            with open(os.path.join(top, "docker.log")) as f:
                log = [line.split() for line in f.read().splitlines()]
            name = next(words[words.index("--name") + 1] for words in log if words[0] == "run")
            self.assertEqual([words for words in log if words[0] in ("run", "rm")][-1], ["rm", "-f", name],
                             "a failed start leaves its container")

    def workflow_steps(self):
        """The command of the start step and of the "wait for the DC" step of each job of the CI workflow."""
        with open(os.path.join(self.here, "..", "..", ".github", "workflows", "tac_plus-ng.yml")) as f:
            lines = f.read().splitlines()
        start = [line.split("- run: ", 1)[1] for line in lines if "samba-dc/start > build/samba-dc.env" in line]
        wait = [lines[i + 1].split("run: ", 1)[1] for i, line in enumerate(lines) if line.strip() == "- name: wait for the DC"]
        self.assertEqual(len(start), len(wait))
        self.assertTrue(start)
        return start, wait

    def test_ci_has_one_deadline_for_the_dc(self):
        """timeout around start is the only deadline: the wait step then always gets the status and prints the log."""
        start, wait = self.workflow_steps()
        for line in start:
            self.assertRegex(line, r"\(set \+e; timeout( -k \d+)? \d+ tac_plus-ng/tests/samba-dc/start ")
        for line in wait:
            with self.subTest(line=line):
                self.assertNotIn("timeout", line, "the wait step can stop before start, and then without the log")
                for rc, env in (("124", ""), ("0", "TACTEST_SAMBA_DC=x\n")):
                    with tempfile.TemporaryDirectory() as tmp:
                        _, run = self.checkout(tmp, "ci")
                        build = os.path.join(tmp, "ci", "build")
                        os.mkdir(build)
                        for name, text in (("samba-dc.rc", rc + "\n"), ("samba-dc.log", "the log\n"),
                                           ("samba-dc.env", "TACTEST_SAMBA_DC=x\n"), ("github.env", "")):
                            with open(os.path.join(build, name), "w") as f:
                                f.write(text)
                        # -e: a run step of GitHub Actions stops at the first failed command
                        p = run(f"GITHUB_ENV=build/github.env sh -e -c {shlex.quote(line)}")
                        self.assertEqual((p.returncode == 0, p.stdout.startswith("the log\n")), (rc == "0", True), p)
                        with open(os.path.join(build, "github.env")) as f:
                            self.assertEqual(f.read(), env)

    def test_ci_publishes_the_dc_status_in_one_step(self):
        """The wait step must never read an empty samba-dc.rc: the status goes to another file, then mv."""
        start, _ = self.workflow_steps()
        for line in start:
            with self.subTest(line=line):
                self.assertRegex(line, r"echo \$\? > (build/samba-dc\.rc\.\w+); mv \1 build/samba-dc\.rc\)")
                with tempfile.TemporaryDirectory() as tmp:
                    _, run = self.checkout(tmp, "ci", docker="exit 3")
                    run(line.rstrip("&").rstrip())
                    self.assertEqual(sorted(os.listdir(os.path.join(tmp, "ci", "build"))),
                                     ["samba-dc", "samba-dc.env", "samba-dc.log", "samba-dc.rc"])
                    with open(os.path.join(tmp, "ci", "build", "samba-dc.rc")) as f:
                        self.assertEqual(f.read(), "3\n")

if __name__ == "__main__":
    unittest.main()
