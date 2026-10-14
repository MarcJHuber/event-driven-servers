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


"""#264: "tac_plus-ng -P" exited 0 when the parser child was killed by a signal.

"-P" forks the parser and exits with WEXITSTATUS() of it. WEXITSTATUS() is 0
for a child killed by a signal, so a configuration that crashed the parser was
reported as valid. This calls "tac_plus-ng -P" directly (not through
tactest.daemon.parse_only(), which worked around exactly this) and checks the
exit code.

The trigger is a configuration with deeply nested groups: parse_group()
recurses, so the parser child overflows its stack and dies with SIGSEGV. It
does not depend on any other fix, which keeps the test valid wherever it sits
in a patch series.
"""

import os
import resource
import subprocess
import tempfile
import unittest

from tactest.daemon import binary, sanitizer_env

SPAWND = "id = spawnd { listen { port = 4949 } }\n"
GOOD = SPAWND + "id = tac_plus-ng { device localhost { address = 127.0.0.0/8 key = test } }\n"
BAD = SPAWND + "id = tac_plus-ng { device localhost { address = 127.0.0.0/8 key = test\n"       # no closing braces

# A small stack for the parser, so the recursion below overflows regardless of
# the host's "ulimit -s" (CI runners often have 8 MB, where 200k frames fit).
STACK_LIMIT = 2 * 1024 * 1024


def nested_groups(n=200000):
    inner = "".join("group g%d {" % i for i in range(n))   # unique names, so each nests
    return SPAWND + "id = tac_plus-ng {\n" + inner + "}" * n + "\n}\n"


def parse(text, stack_limit=None):
    """Run "tac_plus-ng -P <file>" directly; return (returncode, output).

    A returncode below 0 means -P itself was killed by that signal; 128 + n
    means -P turned a parser killed by signal n into its own exit code.
    stack_limit (bytes) caps the parser's stack via RLIMIT_STACK in the child.
    """
    preexec = None
    if stack_limit is not None:
        def preexec():
            resource.setrlimit(resource.RLIMIT_STACK, (stack_limit, stack_limit))
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "tac_plus-ng.cfg")
        with open(path, "w") as f:
            f.write(text)
        p = subprocess.run([binary(), "-P", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           stdin=subprocess.DEVNULL, timeout=60, env=sanitizer_env(), preexec_fn=preexec)
        return p.returncode, p.stdout.decode("utf-8", "replace")


class ParseOnlyExitCode(unittest.TestCase):
    def test_issue264_good_config_exits_zero(self):
        code, out = parse(GOOD)
        self.assertEqual(code, 0, out)

    def test_issue264_syntax_error_exits_nonzero(self):
        code, out = parse(BAD)
        self.assertGreater(code, 0, out)

    def test_issue264_parser_killed_by_signal_is_not_success(self):
        """A configuration that crashes the parser must not be reported as valid."""
        code, out = parse(nested_groups(), stack_limit=STACK_LIMIT)
        self.assertNotEqual(code, 0, "-P returned 0 although the parser was killed by a signal\n" + out)


if __name__ == "__main__":
    unittest.main()
