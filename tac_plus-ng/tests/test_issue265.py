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


"""#265: a TACMEMBER with an unknown group and then a syntax error crashed the worker.

parse_member() (config.c) caught "Group not found" with a setjmp() of its own
on sym->env, the jmp_buf of parse_user_profile(), and left it pointing into
its own frame; the next parse error longjmp()ed into that dead frame. The
member list reaches parse_member() through the profile the daemon builds from
the TACMEMBER of an external MAVIS module. The outcome depended on the build:
a SIGSEGV with optimization or ASan, the user let in instead of denied by a
clang -O0 build. Either way the login must be a plain FAIL now, and the crash
detectors run after each test as always.
"""

import unittest

from tactest import DaemonTestCase, Stub

POLICY = Stub.module(childs=(1, 1)) + """
	user backend = mavis
	login backend = mavis
	pap backend = mavis
	ruleset {
		rule { script { permit } }
	}
"""


class BadGroupList(DaemonTestCase):
    CONFIG = POLICY

    def login(self, member):
        Stub(self.daemon).set(users={"alice": {"password": "pw", "member": member}})
        return self.connect().pap("alice", "pw").status_name

    def test_issue265_unknown_group_then_a_syntax_error(self):
        self.assertEqual(self.login(',"nosuchgroup"'), "FAIL")

    def test_issue265_script_out_list_of_a_user_without_groups(self):
        """What the "script out" of #189 makes of a user without groups: ',"no-login-profile"'."""
        self.assertEqual(self.login(',"no-login-profile"'), "FAIL")


if __name__ == "__main__":
    unittest.main()
