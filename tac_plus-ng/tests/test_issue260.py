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


"""#260: md5_xor() declared its digest buffer transposed (u_char digest[MD5_LEN][2]).

gcc at -O1 and above takes the declared bound at its word, XORs only 2
of every 16 bytes, and every obfuscated packet is garbled. configure
builds with gcc -O2 by default (since 59d6a7f), so there every test that
talks to the daemon shows it; a --debug build (-O0) or clang don't. This
test compiles md5_xor() from packet.c as it is, with -O2 and with array
bounds trapping, and compares it with RFC 8907 obfuscation, whatever the
daemon under test was built with.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

from tactest import SOURCE, tacacs

DRIVER = r"""
#include <sys/types.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "misc/mymd5.h"
#include "tac_plus-ng/protocol_tacacs.h"

#define MD5_LEN 16
static __inline__ int minimum(int a, int b) { return a < b ? a : b; }

/* md5_xor() from tac_plus-ng/packet.c */
%s

/* stdin: a TACACS+ packet; stdout: the same packet after md5_xor() with the key argv[1] */
int main(int argc, char **argv)
{
    static u_char buf[65536];
    ssize_t len = 0, n;
    while ((n = read(0, buf + len, sizeof(buf) - len)) > 0)
        len += n;
    if (argc != 2 || len < TAC_PLUS_HDR_SIZE)
        return 2;
    md5_xor((tac_pak_hdr *) buf, argv[1], (int) strlen(argv[1]));
    return fwrite(buf, 1, len, stdout) == (size_t) len ? 0 : 1;
}
"""

KEY = "md5xor-test-key"


def md5_xor_source():
    with open(os.path.join(SOURCE, "tac_plus-ng", "packet.c")) as f:
        text = f.read()
    m = re.search(r"^static void md5_xor\(.*?^}\n", text, re.M | re.S)
    if not m:
        raise AssertionError("md5_xor() not found in tac_plus-ng/packet.c")
    return m.group(0)


def compiler():
    return shutil.which(os.environ.get("CC", "").split(" ")[0] or "cc") or shutil.which("cc")


class Md5Xor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cc = compiler()
        if not cls.cc:
            raise unittest.SkipTest("no C compiler")
        cls.tmp = tempfile.mkdtemp(prefix="tactest-md5xor-")
        cls.driver = os.path.join(cls.tmp, "md5x.c")
        with open(cls.driver, "w") as f:
            f.write(DRIVER % md5_xor_source())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def build(self, name, flags):
        exe = os.path.join(self.tmp, name)
        p = subprocess.run([self.cc] + flags + ["-I", SOURCE, "-o", exe, self.driver,
                                                os.path.join(SOURCE, "misc", "mymd5.c")],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return exe if p.returncode == 0 else None

    def check(self, exe):
        for length in (1, 15, 16, 17, 31, 32, 33, 100, 1000):
            with self.subTest(body_length=length):
                body = bytes((i * 7 + 3) & 0xFF for i in range(length))
                pkt = tacacs.Packet(tacacs.TYPE_AUTHEN, body, seq_no=3, session_id=0x11223344,
                                    version=tacacs.VERSION_ONE, flags=tacacs.FLAG_UNENCRYPTED)
                wire = pkt.encode(KEY)
                p = subprocess.run([exe, KEY], input=wire, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(p.returncode, 0, "md5_xor() failed: %r" % p.stderr[-500:])
                expected = tacacs.obfuscate(body, 0x11223344, KEY.encode(), tacacs.VERSION_ONE, 3)
                self.assertEqual(p.stdout[tacacs.HEADER_LEN:].hex(), expected.hex())

    def test_issue260_md5_xor_optimized(self):
        """-O2, as a distribution package of tac_plus-ng is built with gcc."""
        exe = self.build("md5x-O2", ["-O2"])
        self.assertTrue(exe, "the md5_xor() driver doesn't compile with %s -O2" % self.cc)
        self.check(exe)

    def test_issue260_md5_xor_within_array_bounds(self):
        """Trap on any out-of-bounds index; clang doesn't exploit the bound, but this sees it."""
        for flags in (["-fsanitize=bounds", "-fsanitize-trap=bounds"],
                      ["-fsanitize=bounds", "-fsanitize-undefined-trap-on-error"]):
            exe = self.build("md5x-bounds", ["-O0"] + flags)
            if exe:
                break
        else:
            self.skipTest("%s can't trap on array bounds" % self.cc)
        self.check(exe)


if __name__ == "__main__":
    unittest.main()
