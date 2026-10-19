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


"""TLS for the tests: a throw-away CA made with the openssl command, client
contexts, and a TLS 1.3 PSK client.

Nothing is kept in the tree: CA() creates keys and certificates in a
scratch directory, the way tac_plus-ng/sample/democa does it with make
(root CA -> server and client certificates). EC P-256 keys, because RSA key
generation is slow on a loaded host.

The standard library ssl module has no TLS-PSK client before Python 3.13,
so PskSocket runs "openssl s_client -psk" and talks through its pipes; it
has the few socket methods tacacs.Connection uses.

openssl_available() lets a test skip when the command is missing.
"""

import os
import select
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile

from .daemon import scratch_dir


def openssl_available():
    return shutil.which("openssl") is not None


def _openssl(*args, cwd=None):
    p = subprocess.run(["openssl"] + list(args), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       stdin=subprocess.DEVNULL, timeout=60)
    if p.returncode:
        raise RuntimeError("openssl %s failed:\n%s" % (" ".join(args), p.stdout.decode("utf-8", "replace")))
    return p.stdout


class CA:
    """A root CA in its own scratch directory; issue() makes certificates signed by it.

    The server certificate names 127.0.0.1, ::1 and localhost, so a client
    context can check the host name.
    """

    def __init__(self, name="ca"):
        self.dir = scratch_dir(name)
        self.cert = self.path("root.crt")
        self.key = self.path("root.key")
        self._newkey(self.key)
        self._ext("root.ext", "basicConstraints = critical, CA:true\n"
                              "keyUsage = critical, keyCertSign, cRLSign\n"
                              "subjectKeyIdentifier = hash\n")
        _openssl("req", "-batch", "-new", "-x509", "-key", self.key, "-subj", "/O=tactest/CN=tactest root",
                 "-days", "2", "-sha256", "-config", self._config(), "-extensions", "v3", "-out", self.cert)
        self.server = self.issue("server", "/O=tactest/CN=localhost", server=True,
                                 san="IP:127.0.0.1, IP:::1, DNS:localhost")

    def path(self, name):
        return os.path.join(self.dir, name)

    def _newkey(self, path):
        _openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", path)

    def _ext(self, name, text):
        with open(self.path(name), "w") as f:
            f.write(text)
        return self.path(name)

    def _config(self):
        """A minimal openssl.cnf: req needs one, and the system one may be missing or odd."""
        return self._ext("req.cnf", "[req]\ndistinguished_name = dn\n[dn]\n[v3]\n"
                                    "basicConstraints = critical, CA:true\n"
                                    "keyUsage = critical, keyCertSign, cRLSign\n"
                                    "subjectKeyIdentifier = hash\n")

    def issue(self, name, subject, server=False, san=None, days=2, expired=False):
        """(certificate, key) for subject, e.g. "/CN=nas1"; san e.g. "DNS:nas1, IP:127.0.0.5".

        expired: valid for one day in 2020. "openssl x509 -req" takes no
        dates in the past before OpenSSL 3.4, "openssl ca" does.
        """
        key, csr, crt = self.path(name + ".key"), self.path(name + ".csr"), self.path(name + ".crt")
        self._newkey(key)
        _openssl("req", "-batch", "-new", "-key", key, "-subj", subject, "-config", self._config(), "-out", csr)
        ext = "basicConstraints = CA:false\nkeyUsage = critical, digitalSignature\n"
        ext += "extendedKeyUsage = %s\n" % ("serverAuth" if server else "clientAuth")
        ext += "authorityKeyIdentifier = keyid\n"
        if san:
            ext += "subjectAltName = %s\n" % san
        ext = self._ext(name + ".ext", ext)
        if expired:
            db = self.path(name + ".db")
            os.mkdir(db)
            open(os.path.join(db, "index.txt"), "w").close()
            with open(os.path.join(db, "serial"), "w") as f:
                f.write("01\n")
            cnf = self._ext(name + ".ca.cnf", "[ca]\ndefault_ca = c\n[c]\ndatabase = %s/index.txt\nserial = %s/serial\n"
                                              "new_certs_dir = %s\ndefault_md = sha256\npolicy = p\n"
                                              "unique_subject = no\n[p]\ncommonName = optional\n" % (db, db, db))
            _openssl("ca", "-batch", "-notext", "-config", cnf, "-cert", self.cert, "-keyfile", self.key,
                     "-in", csr, "-extfile", ext, "-startdate", "20200101000000Z", "-enddate", "20200102000000Z",
                     "-out", crt)
        else:
            _openssl("x509", "-req", "-in", csr, "-CA", self.cert, "-CAkey", self.key, "-CAcreateserial",
                     "-days", str(days), "-sha256", "-extfile", ext, "-out", crt)
        return crt, key

    def context(self, cert=None, minimum=ssl.TLSVersion.TLSv1_3, maximum=None):
        """A client context that trusts this CA; cert = (certificate, key) to present."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = minimum
        if maximum is not None:
            ctx.maximum_version = maximum
        ctx.load_verify_locations(self.cert)
        if cert:
            ctx.load_cert_chain(*cert)
        return ctx

    def remove(self):
        if not os.environ.get("TACTEST_KEEP"):
            shutil.rmtree(self.dir, ignore_errors=True)


class PskSocket:
    """TLS 1.3 with a pre-shared key through "openssl s_client", for tacacs.Connection(sock=...).

    -quiet: no session information on stdout, only what the server sends;
    -nocommands: no command letters in what we send. If the handshake fails,
    s_client exits and the reader sees EOF -- a connection the daemon
    closed. MSG_PEEK is emulated with a buffer.
    """

    def __init__(self, addr, identity, key_hex, timeout=5.0, cipher="TLS_AES_128_GCM_SHA256"):
        host, port = addr[0], addr[1]
        target = "[%s]:%d" % (host, port) if ":" in host else "%s:%d" % (host, port)
        self.timeout = timeout
        self.peeked = b""
        self.err = tempfile.TemporaryFile()
        self.proc = subprocess.Popen(["openssl", "s_client", "-connect", target, "-tls1_3", "-ciphersuites", cipher,
                                      "-psk_identity", identity, "-psk", key_hex, "-quiet", "-nocommands"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err,
                                     start_new_session=True)
        self.out = self.proc.stdout.fileno()

    def settimeout(self, timeout):
        self.timeout = timeout

    def setsockopt(self, *args):
        pass

    def sendall(self, data):
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except BrokenPipeError:
            raise ConnectionResetError("openssl s_client exited:\n%s" % self.stderr())

    def recv(self, n, flags=0):
        if not self.peeked:
            r, _, _ = select.select([self.out], [], [], self.timeout)
            if not r:
                raise socket.timeout("timed out")
            self.peeked = os.read(self.out, 65536)
        data = self.peeked[:n]
        if not flags & socket.MSG_PEEK:
            self.peeked = self.peeked[n:]
        return data

    def stderr(self):
        self.err.seek(0)
        return self.err.read().decode("utf-8", "replace")

    def close(self):
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except OSError:
                pass
        self.proc.wait()
        for f in (self.proc.stdin, self.proc.stdout):
            try:
                f.close()
            except OSError:
                pass
        self.err.close()
