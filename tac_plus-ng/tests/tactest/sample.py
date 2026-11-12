"""A configuration shipped in tac_plus-ng/sample or tac_plus-ng/extra as the template of a test daemon.

The sample stays as it is, except for the edits a test gives: each one is
an (old, new) pair, "old" is text of the sample and must occur exactly
once, "new" is template text ($address, $port, $tmp, $spawnd, see
config.py). So a change of the sample that a test depends on fails that
test instead of testing something else. A "$" in the sample is literal.

Two lines are added for the harness: the debug-cmd of config.BASE and the
user tactest-generation-$generation, which the hang detector logs in as.
A sample whose rules deny that user still answers the probe, only later.
"""

import os

from .daemon import TOP

COMPONENT = os.path.join(TOP, "tac_plus-ng")
HEAD = "debug-cmd = \"echo $$CRASHPID >> '$tmp/crash.pids'\"\n"
GENERATION_USER = "\n\tuser tactest-generation-$generation {\n\t\tpassword pap = clear tactest\n\t}\n"


def path(name):
    """name: relative to tac_plus-ng, e.g. "sample/tac_plus-ng.cfg"."""
    return os.path.join(COMPONENT, name)


def template(name, edits=()):
    with open(path(name)) as f:
        text = f.read().replace("$", "$$")
    edits = list(edits) + [("id = tac_plus-ng {", "id = tac_plus-ng {" + GENERATION_USER)]
    for old, new in edits:
        old = old.replace("$", "$$")
        count = text.count(old)
        if count != 1:
            raise ValueError("%s: %r occurs %d times, not once" % (name, old, count))
        text = text.replace(old, new)
    return HEAD + text
