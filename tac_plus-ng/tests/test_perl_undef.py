"""No undef as a condition in the Perl scripts of the tree.

undef(EXPR) clears EXPR and returns undef, so "if (undef($x))" is always
false and clears $x; defined($x) was meant. The check reads the source
outside POD and full-line comments, also across line ends. It does not
parse Perl: it does not strip a comment at the end of a line.
"""

import os
import re
import unittest

from tactest import SOURCE

CONDITION = re.compile(r"""
    \b(?:if|elsif|unless|while|until)\s*\(\s*(?:!\s*)?\(?\s*undef\b   # if (undef($x)), elsif (undef $x)
  | \b(?:if|unless|while|until)\s+undef\b                            # ... if undef $x;
  | (?:&&|\|\|)\s*(?:!\s*)?\(?\s*undef\s*[($]                         # ... && undef($x)
""", re.VERBOSE)

BAD = ("\t\t\tif (undef($flag_authorize_only)) {",
       "} elsif (undef $mkpasswd) {",
       "unless (!undef $x) {",
       "print 1 if undef $x;",
       "if ($a && undef($b)) {")
VALID = ("undef $mkpasswd unless -x $mkpasswd;",
         "\treturn undef;",
         "if (!defined($flag_authorize_only)) {",
         "} elsif (!defined $mkpasswd) {",
         "my $x = $y || undef;",
         "\t\t\t# \tif (undef($TACMEMBER) && $RESULT == ACK) set RESULT = NAK")


def findings(lines):
    """(line number, line) of the undef in each undef condition outside POD and full-line comments."""
    code, pod = [], False
    for line in lines:
        line = line.rstrip("\n")
        if re.match(r"__(?:END|DATA)__\b", line):
            break
        if re.match(r"=[a-zA-Z]", line):
            pod = not line.startswith("=cut")
            line = ""
        elif pod or line.lstrip().startswith("#"):
            line = ""
        code.append(line)
    # blank lines keep the line numbers; the regex can then match across line ends
    text = "\n".join(code)
    for m in CONDITION.finditer(text):
        n = text.count("\n", 0, text.rindex("undef", m.start(), m.end()))
        yield n + 1, code[n]


def perl_files(top):
    for d, dirs, files in os.walk(top):
        # build output and hidden directories (.git) are not part of the source
        dirs[:] = sorted(x for x in dirs if not x.startswith(".") and not (d == top and x == "build"))
        yield from (os.path.join(d, f) for f in sorted(files) if f.endswith((".pl", ".pm", ".pl.in", ".pm.in")))


class PerlUndefCondition(unittest.TestCase):
    def test_samples(self):
        self.assertEqual([n for n, _ in findings(BAD)], list(range(1, len(BAD) + 1)))
        self.assertEqual(list(findings(VALID)), [])
        self.assertEqual(list(findings(["=pod", BAD[0], "=cut", BAD[1]])), [(4, BAD[1])])
        self.assertEqual(list(findings(["if (", "    undef($x)", ") {"])), [(2, "    undef($x)")])
        self.assertEqual(list(findings(["my $x = $y ||", "    undef;", "# if (", "undef($x);"])), [])

    def test_tree(self):
        files = list(perl_files(SOURCE))
        self.assertTrue(files, "no Perl files below " + SOURCE)
        found = []
        for path in files:
            with open(path, encoding="utf-8", errors="replace") as f:
                found += ["%s:%d: %s" % (os.path.relpath(path, SOURCE), n, line) for n, line in findings(f)]
        self.assertEqual(found, [], "undef(EXPR) clears EXPR; use defined() in a condition")


if __name__ == "__main__":
    unittest.main()
