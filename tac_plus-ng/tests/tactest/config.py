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

"""Configuration templates for the daemon under test.

string.Template placeholders:

  $tmp        per-daemon scratch directory (logs, crash markers)
  $address    listen address (127.0.0.1 or ::1)
  $port       listen port, picked by the harness
  $key        shared secret of the "localhost" device
  $generation incremented by every Daemon.reload()
  $spawnd     extra lines for the spawnd section
  $top        extra lines before "id = tac_plus-ng"
  $body       the policy, written by the test itself

A literal "$" in a test body must be written as "$$". Paths built from
$tmp are quoted, so a scratch directory may contain spaces.

"mavis cache timeout = 0" because the daemon otherwise caches MAVIS answers
for 120 seconds, hiding any change of the stub scenario within a test.

debug-cmd replaces the default "gdb ... ; sleep 3" in the worker's SIGSEGV
handler with a marker file the harness checks after every test.

The "tactest-generation-$generation" user lets Daemon.reload() prove that
a new connection sees the new configuration rather than the old one.
"""

import string

KEY = "tactest"

BASE = """\
debug-cmd = "echo $$CRASHPID >> '$tmp/crash.pids'"
$top
id = spawnd {
	background = no
	listen { address = $address port = $port }
	spawn { instances min = 1 instances max = 1 }
$spawnd
}

id = tac_plus-ng {
	log authentication { destination = "$tmp/authentication.log" }
	log authorization { destination = "$tmp/authorization.log" }
	log accounting { destination = "$tmp/accounting.log" }
	authentication log = authentication
	authorization log = authorization
	accounting log = accounting

	mavis cache timeout = 0

	device localhost {
		address = 127.0.0.0/8
		address = ::1/128
		key = $key
	}

	user tactest-generation-$generation {
		password pap = clear tactest
	}

$body
}
"""


def render(template=BASE, **values):
    defaults = dict(top="", spawnd="", body="", key=KEY, generation=0, address="127.0.0.1", port=49, tmp="/tmp")
    defaults.update(values)
    # the body is a template too: "$tmp" in a policy is the scratch directory
    defaults["body"] = string.Template(defaults["body"]).substitute(defaults)
    return string.Template(template).substitute(defaults)
