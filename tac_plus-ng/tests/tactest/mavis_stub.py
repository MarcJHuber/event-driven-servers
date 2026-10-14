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


"""A MAVIS backend for the tests, driven by a JSON file.

The stub side runs as an "external" MAVIS module on top of the installed
mavis.py (the copy users get):

    python3 -u mavis_stub.py <directory of mavis.py>

with TACTEST_STUB_STATE and TACTEST_STUB_LOG in its environment (set by
the "setenv" lines of Stub.module(), which so are tested all the time).
The state file is read again for every request, because MAVIS children
live long and restarting the daemon to change a scenario would make the
tests slow and different from production. A missing file means an empty
scenario. The test side (class Stub) writes it to a temporary file and
renames it, so a child never reads half of it.

State, all keys optional:

  users         {name: {"password": str,
                        "member": [groups] or a string as it is,
                        "sshkey": str, "mustchange": bool}}
  result        {key: "ACK" | "NAK" | "NOTFOUND" | "ERROR"}; the first of
                "<user>:<TYPE>", "<user>", "<TYPE>", "*" decides, TYPE
                being the MAVIS request type (AUTH, INFO, CHPW, ...)
  message       the user response (AV_A_USER_RESPONSE) of every answer
  exit          exit without an answer on the n-th request of a child
  quit          exit after answering the n-th request of a child, once the
                test released that request (see release)
  double_write  answer every request a second time, once the test released
                it, and journal that as result "again" (#228)
  release       the number of the request (n in the journal) up to which a
                child may go on with "quit" or "double_write"; Stub.release()
                sets it. Until then the child waits, so the test decides when
                the child acts -- after the client got the first answer --
                instead of a pause that a loaded host may stretch.

Without a forced result: an unknown user is NOTFOUND; INFO is ACK with
the user's attributes; AUTH and CHPW are ACK if the password matches,
else NAK; other request types are NOTFOUND.

Every request becomes one JSON line in the journal, written before the
answer with a single write() to a file opened with O_APPEND (all
children share it): pid, n (number of the request in this child), type,
user, result. Never the password.
"""

import json
import os
import sys
import time

RESULTS = ("ACK", "NAK", "NOTFOUND", "ERROR")
RELEASE_TIMEOUT = 60

HERE = os.path.abspath(__file__)


# --- test side --------------------------------------------------------------

class Stub:
    """The scenario and the journal of the stub of one daemon (its scratch directory)."""

    def __init__(self, daemon):
        self.state_path = os.path.join(daemon.tmp, "stub.json")
        self.log_path = os.path.join(daemon.tmp, "stub.log")

    @staticmethod
    def module(childs=None, script=""):
        """A "mavis module = external" block running the stub, for a policy body.

        childs: (min, max) of MAVIS children; scenarios that count per
        child or kill a child need (1, 1). script: "script in/out" lines
        as they go into the body (a literal "$" written "$$").
        """
        from .daemon import prefix
        lines = ["\tmavis module = external {",
                 '\t\texec = "%s" "%s" "-u" "%s" "%s"' % (sys.executable, sys.executable, HERE,
                                                         os.path.join(prefix(), "lib", "mavis")),
                 '\t\tsetenv TACTEST_STUB_STATE = "$tmp/stub.json"',
                 '\t\tsetenv TACTEST_STUB_LOG = "$tmp/stub.log"']
        if childs:
            lines.append("\t\tchilds min = %d\n\t\tchilds max = %d" % childs)
        if script:
            lines.append(script)
        lines.append("\t}\n")
        return "\n".join(lines)

    def set(self, **state):
        """Replace the scenario; the next request sees it."""
        tmp = self.state_path + ".new"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, self.state_path)

    def release(self, n):
        """Let a child go on with "quit" or "double_write" after its request n."""
        state = _load(self.state_path)
        state["release"] = n
        self.set(**state)

    def requests(self, type=None, user=None):
        """Journal entries so far, optionally only of one request type and/or user."""
        try:
            with open(self.log_path) as f:
                entries = [json.loads(line) for line in f if line.strip()]
        except FileNotFoundError:
            return []
        return [e for e in entries if (type is None or e["type"] == type) and (user is None or e["user"] == user)]

    def count(self, type=None, user=None):
        return len(self.requests(type, user))


# --- stub side --------------------------------------------------------------

def _load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _wait_release(path, n, timeout=RELEASE_TIMEOUT):
    """Wait until the test released request n; go on anyway after timeout."""
    deadline = time.monotonic() + timeout
    while (_load(path).get("release") or 0) < n and time.monotonic() < deadline:
        time.sleep(0.02)


def _forced(state, user, tactype):
    table = state.get("result") or {}
    for key in ("%s:%s" % (user, tactype), user, tactype, "*"):
        if key in table:
            if table[key] not in RESULTS:
                raise SystemExit("mavis_stub: unknown result %r" % table[key])
            return table[key]
    return None


def serve(libdir):
    sys.path.insert(0, libdir)
    import mavis as M

    state_path = os.environ["TACTEST_STUB_STATE"]
    journal = os.open(os.environ["TACTEST_STUB_LOG"], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    answers = {
        "ACK": (M.MAVIS_FINAL, M.AV_V_RESULT_OK),
        "NAK": (M.MAVIS_FINAL, M.AV_V_RESULT_FAIL),
        "ERROR": (M.MAVIS_FINAL, M.AV_V_RESULT_ERROR),
        "NOTFOUND": (M.MAVIS_DOWN, M.AV_V_RESULT_NOTFOUND),
    }
    n = 0
    while True:
        d = M.Mavis()           # exits when the daemon closes stdin
        n += 1
        state = _load(state_path)
        av = d.av_pairs
        user, tactype = av.get(M.AV_A_USER, ""), av.get(M.AV_A_TACTYPE, "")
        known = state.get("users", {}).get(user)
        result = _forced(state, user, tactype)
        if result is None:
            if known is None or tactype not in ("INFO", "AUTH", "CHPW"):
                result = "NOTFOUND"
            elif tactype == "INFO" or av.get(M.AV_A_PASSWORD) == known.get("password"):
                result = "ACK"
            else:
                result = "NAK"
        dying = state.get("exit") == n
        entry = {"pid": os.getpid(), "n": n, "type": tactype, "user": user, "result": "exit" if dying else result}
        os.write(journal, (json.dumps(entry) + "\n").encode())
        if dying:
            os._exit(0)
        if result == "ACK" and known:
            member = known.get("member")
            if member:
                d.set_tacmember(member if isinstance(member, str) else ",".join('"%s"' % m for m in member))
            if known.get("sshkey"):
                d.set_sshpubkey(known["sshkey"])
            d.password_mustchange(bool(known.get("mustchange")))
        verdict, code = answers[result]
        d.write(verdict, code, state.get("message"))
        if state.get("double_write"):
            _wait_release(state_path, n)
            d.write(verdict, code, state.get("message"))
            entry["result"] = "again"
            os.write(journal, (json.dumps(entry) + "\n").encode())
        if state.get("quit") == n:
            _wait_release(state_path, n)
            os._exit(0)


if __name__ == "__main__":
    serve(sys.argv[1])
