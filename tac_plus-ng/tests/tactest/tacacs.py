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


"""TACACS+ client (RFC 8907), Python standard library only.

Layers, each usable directly by a test:

  Packet      header fields + clear-text body; encode() can override every
              header field and skip obfuscation, for malformed-packet tests
  Connection  one TCP socket: send(), send_raw(), send_split(), recv() with
              a timeout, closed() to detect EOF without a reply. Replies are
              sorted by session id, so several sessions can share one
              single-connection socket at the same time.
  Session     one session_id and its sequence numbers on a Connection

and the dialogs on top: ascii_login, pap, chap, mschap (v1, v2), enable,
author, acct. Each returns the final reply; an
authentication dialog returns a Dialog with every REPLY on the way, for
tests of banners and prompts.

Transports: plain TCP; TLS (RFC 9887) with an ssl.SSLContext (tls=), where
packets go without obfuscation and with TAC_PLUS_UNENCRYPTED_FLAG; any
socket-like object (sock=, e.g. tls.PskSocket for TLS 1.3 PSK); and a PROXY
protocol header (proxy=, see proxy_v1() and proxy_v2()) sent before
anything else, as a load balancer does.
"""

import hashlib
import os
import socket
import ssl
import struct
import time

from . import crypto

# Header
VERSION_DEFAULT = 0xC0
VERSION_ONE = 0xC1
HEADER_LEN = 12

TYPE_AUTHEN = 1
TYPE_AUTHOR = 2
TYPE_ACCT = 3

FLAG_UNENCRYPTED = 0x01
FLAG_SINGLE_CONNECT = 0x04

# Authentication START
AUTHEN_LOGIN = 1

AUTHEN_TYPE_ASCII = 1
AUTHEN_TYPE_PAP = 2
AUTHEN_TYPE_CHAP = 3
AUTHEN_TYPE_MSCHAP = 5
AUTHEN_TYPE_MSCHAPV2 = 6

AUTHEN_SVC_LOGIN = 1
AUTHEN_SVC_ENABLE = 2
AUTHEN_SVC_PPP = 3

AUTHEN_METH_TACACSPLUS = 6

CONTINUE_FLAG_ABORT = 0x01
REPLY_FLAG_NOECHO = 0x01

AUTHEN_STATUS = {
    1: "PASS", 2: "FAIL", 3: "GETDATA", 4: "GETUSER",
    5: "GETPASS", 6: "RESTART", 7: "ERROR", 0x21: "FOLLOW",
}
AUTHOR_STATUS = {1: "PASS_ADD", 2: "PASS_REPL", 0x10: "FAIL", 0x11: "ERROR", 0x21: "FOLLOW"}
ACCT_STATUS = {1: "SUCCESS", 2: "ERROR", 0x21: "FOLLOW"}

ACCT_FLAG_START = 0x02
ACCT_FLAG_STOP = 0x04

DIALOG_LIMIT = 20       # REPLYs in one authentication dialog before giving up


class ProtocolError(Exception):
    """The server answered with something that is not a valid reply."""


class Closed(Exception):
    """The server closed the connection instead of answering."""


def _pad(session_id, key, version, seq_no, length):
    out, prev = b"", b""
    while len(out) < length:
        prev = hashlib.md5(struct.pack("!I", session_id) + key + bytes([version, seq_no]) + prev).digest()
        out += prev
    return out[:length]


def obfuscate(body, session_id, key, version, seq_no):
    """RFC 8907 section 4.5; the operation is its own inverse."""
    if not key:
        return body
    pad = _pad(session_id, key, version, seq_no, len(body))
    return bytes(a ^ b for a, b in zip(body, pad))


def _b(value):
    if isinstance(value, bytes):
        return value
    return str(value).encode()


def _args(args):
    """AV pairs as a list of bytes; str items are UTF-8 encoded."""
    out = [_b(a) for a in args]
    for a in out:
        if len(a) > 255:
            raise ValueError("argument longer than 255 bytes: %r" % a[:40])
    return out


class Packet:
    def __init__(self, type, body=b"", seq_no=1, session_id=None, flags=0, version=VERSION_DEFAULT):
        self.type = type
        self.body = body
        self.seq_no = seq_no
        self.session_id = session_id if session_id is not None else new_session_id()
        self.flags = flags
        self.version = version

    def encode(self, key, version=None, type=None, seq_no=None, flags=None, session_id=None, length=None):
        """Serialize; every keyword overrides what goes on the wire."""
        version = self.version if version is None else version
        type = self.type if type is None else type
        seq_no = self.seq_no if seq_no is None else seq_no
        flags = self.flags if flags is None else flags
        session_id = self.session_id if session_id is None else session_id
        body = self.body
        if not flags & FLAG_UNENCRYPTED:
            body = obfuscate(body, session_id, _b(key), version, seq_no)
        length = len(body) if length is None else length
        return struct.pack("!BBBBII", version, type, seq_no, flags, session_id, length) + body

    @classmethod
    def decode_header(cls, data):
        version, type, seq_no, flags, session_id, length = struct.unpack("!BBBBII", data[:HEADER_LEN])
        pkt = cls(type, b"", seq_no, session_id, flags, version)
        return pkt, length

    # bodies of the client's packets

    @classmethod
    def authen_start(cls, user="", port="tty0", rem_addr="127.0.0.1", data=b"",
                     action=AUTHEN_LOGIN, priv_lvl=1, authen_type=AUTHEN_TYPE_ASCII,
                     service=AUTHEN_SVC_LOGIN, **kw):
        u, p, r, d = _b(user), _b(port), _b(rem_addr), _b(data)
        body = struct.pack("!BBBBBBBB", action, priv_lvl, authen_type, service, len(u), len(p), len(r), len(d))
        return cls(TYPE_AUTHEN, body + u + p + r + d, **kw)

    @classmethod
    def authen_continue(cls, user_msg=b"", data=b"", flags=0, **kw):
        m, d = _b(user_msg), _b(data)
        return cls(TYPE_AUTHEN, struct.pack("!HHB", len(m), len(d), flags) + m + d, **kw)

    @classmethod
    def author_request(cls, user, args, port="tty0", rem_addr="127.0.0.1", priv_lvl=1,
                       authen_method=AUTHEN_METH_TACACSPLUS, authen_type=AUTHEN_TYPE_ASCII,
                       service=AUTHEN_SVC_LOGIN, **kw):
        u, p, r, a = _b(user), _b(port), _b(rem_addr), _args(args)
        body = struct.pack("!BBBBBBBB", authen_method, priv_lvl, authen_type, service,
                           len(u), len(p), len(r), len(a))
        body += bytes(len(x) for x in a) + u + p + r + b"".join(a)
        return cls(TYPE_AUTHOR, body, **kw)

    @classmethod
    def acct_request(cls, user, args, flags=ACCT_FLAG_START, port="tty0", rem_addr="127.0.0.1", priv_lvl=1,
                     authen_method=AUTHEN_METH_TACACSPLUS, authen_type=AUTHEN_TYPE_ASCII,
                     service=AUTHEN_SVC_LOGIN, **kw):
        u, p, r, a = _b(user), _b(port), _b(rem_addr), _args(args)
        body = struct.pack("!BBBBBBBBB", flags, authen_method, priv_lvl, authen_type, service,
                           len(u), len(p), len(r), len(a))
        body += bytes(len(x) for x in a) + u + p + r + b"".join(a)
        return cls(TYPE_ACCT, body, **kw)


def new_session_id():
    return struct.unpack("!I", os.urandom(4))[0]


# --- replies ------------------------------------------------------------------

class AuthenReply:
    def __init__(self, packet):
        b = packet.body
        if packet.type != TYPE_AUTHEN:
            raise ProtocolError("expected an authentication REPLY, got packet type %d" % packet.type)
        if len(b) < 6:
            raise ProtocolError("authentication REPLY body too short (%d bytes) -- wrong key?" % len(b))
        self.status, self.flags, msg_len, data_len = struct.unpack("!BBHH", b[:6])
        if 6 + msg_len + data_len != len(b) or self.status not in AUTHEN_STATUS:
            raise ProtocolError("malformed authentication REPLY (status %d, lengths %d+%d in %d bytes) -- wrong key?"
                                % (self.status, msg_len, data_len, len(b)))
        self.server_msg = b[6:6 + msg_len].decode("utf-8", "replace")
        self.data = b[6 + msg_len:]
        self.packet = packet

    @property
    def status_name(self):
        return AUTHEN_STATUS[self.status]

    @property
    def ok(self):
        return self.status_name == "PASS"

    @property
    def noecho(self):
        return bool(self.flags & REPLY_FLAG_NOECHO)

    def __repr__(self):
        return "AuthenReply(%s, server_msg=%r)" % (self.status_name, self.server_msg)


class Dialog:
    """An authentication dialog: every REPLY, the last one is the result."""

    def __init__(self, replies):
        self.replies = replies

    @property
    def final(self):
        return self.replies[-1]

    @property
    def status_name(self):
        return self.final.status_name

    @property
    def ok(self):
        return self.final.ok

    @property
    def server_msg(self):
        return self.final.server_msg

    @property
    def prompts(self):
        """server_msg of every GETUSER, GETPASS and GETDATA, in order."""
        return [r.server_msg for r in self.replies if r.status_name in ("GETUSER", "GETPASS", "GETDATA")]

    @property
    def statuses(self):
        return [r.status_name for r in self.replies]

    def __repr__(self):
        return "Dialog(%s)" % ", ".join("%s %r" % (r.status_name, r.server_msg) for r in self.replies)


class AuthorReply:
    def __init__(self, packet):
        b = packet.body
        if packet.type != TYPE_AUTHOR:
            raise ProtocolError("expected an authorization REPLY, got packet type %d" % packet.type)
        if len(b) < 6:
            raise ProtocolError("authorization REPLY body too short (%d bytes) -- wrong key?" % len(b))
        self.status, arg_cnt, msg_len, data_len = struct.unpack("!BBHH", b[:6])
        lens = b[6:6 + arg_cnt]
        if (self.status not in AUTHOR_STATUS or len(lens) != arg_cnt
                or 6 + arg_cnt + msg_len + data_len + sum(lens) != len(b)):
            raise ProtocolError("malformed authorization REPLY (status %d, %d args, %d bytes) -- wrong key?"
                                % (self.status, arg_cnt, len(b)))
        p = 6 + arg_cnt
        self.server_msg = b[p:p + msg_len].decode("utf-8", "replace")
        p += msg_len
        self.data = b[p:p + data_len]
        p += data_len
        self.args = []
        for n in lens:
            self.args.append(b[p:p + n].decode("utf-8", "replace"))
            p += n
        self.packet = packet

    @property
    def status_name(self):
        return AUTHOR_STATUS[self.status]

    @property
    def ok(self):
        return self.status_name in ("PASS_ADD", "PASS_REPL")

    def __repr__(self):
        return "AuthorReply(%s, args=%r, server_msg=%r)" % (self.status_name, self.args, self.server_msg)


class AcctReply:
    def __init__(self, packet):
        b = packet.body
        if packet.type != TYPE_ACCT:
            raise ProtocolError("expected an accounting REPLY, got packet type %d" % packet.type)
        if len(b) < 5:
            raise ProtocolError("accounting REPLY body too short (%d bytes) -- wrong key?" % len(b))
        msg_len, data_len, self.status = struct.unpack("!HHB", b[:5])
        if self.status not in ACCT_STATUS or 5 + msg_len + data_len != len(b):
            raise ProtocolError("malformed accounting REPLY (status %d, %d bytes) -- wrong key?"
                                % (self.status, len(b)))
        self.server_msg = b[5:5 + msg_len].decode("utf-8", "replace")
        self.data = b[5 + msg_len:]
        self.packet = packet

    @property
    def status_name(self):
        return ACCT_STATUS[self.status]

    @property
    def ok(self):
        return self.status_name == "SUCCESS"

    def __repr__(self):
        return "AcctReply(%s, server_msg=%r)" % (self.status_name, self.server_msg)


# --- PROXY protocol (haproxy.org/download/1.8/doc/proxy-protocol.txt) ------------

PROXY_V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
PROXY_LOCAL = 0
PROXY_PROXY = 1
PP2_TYPE_CRC32C = 0x03
PP2_TYPE_NOOP = 0x04


def proxy_v1(src, dst, sport=4711, dport=49):
    """The text header: "PROXY TCP4 <src> <dst> <sport> <dport>\\r\\n"."""
    family = "TCP6" if ":" in src else "TCP4"
    return ("PROXY %s %s %s %d %d\r\n" % (family, src, dst, sport, dport)).encode()


def proxy_tlv(type, value):
    return bytes([type]) + struct.pack("!H", len(value)) + value


def proxy_v2(src=None, dst=None, sport=4711, dport=49, tlvs=b"", command=PROXY_PROXY):
    """The binary header; src None: no addresses (family UNSPEC), as a LOCAL health check sends it.

    tlvs follow the addresses and count in the length field, e.g. the
    padding an AWS network load balancer adds (#88).
    """
    if src is None:
        family, addresses = 0x00, b""
    elif ":" in src:
        family = 0x21
        addresses = socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
        addresses += struct.pack("!HH", sport, dport)
    else:
        family = 0x11
        addresses = socket.inet_pton(socket.AF_INET, src) + socket.inet_pton(socket.AF_INET, dst)
        addresses += struct.pack("!HH", sport, dport)
    body = addresses + tlvs
    return PROXY_V2_SIGNATURE + bytes([0x20 | command, family]) + struct.pack("!H", len(body)) + body


# --- transport --------------------------------------------------------------

class Connection:
    """One TCP connection to the daemon. Usable as a context manager.

    source binds the local end, e.g. to 127.0.0.2, so the daemon sees
    another device address. With single_connect, every packet carries the
    flag, and replies for several sessions may be read in any order.

    proxy: bytes sent right after the TCP handshake (a PROXY header).
    tls: an ssl.SSLContext; the handshake follows the PROXY header, if any.
    sock: an already connected socket-like object instead of a new socket;
    packets then go as over TLS (no obfuscation).
    With TLS the key is not used: RFC 9887 forbids obfuscation there.
    """

    def __init__(self, addr, key, timeout=5.0, source=None, single_connect=False, proxy=None, tls=None,
                 server_hostname=None, sock=None):
        host, port = addr[0], addr[1]
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.tls = tls is not None or sock is not None
        self.key = b"" if self.tls else _b(key)
        self.timeout = timeout
        self.single_connect = single_connect
        self.pending = []           # packets read for another session than the one waited for
        self.buffered = b""         # bytes read by closed()/silent() but not consumed
        if sock is not None:
            self.sock = sock
            self.sock.settimeout(timeout)
            return
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        try:
            if source is not None:
                self.sock.bind((source, 0))
            self.sock.connect((host, port))
            if proxy:
                self.sock.sendall(proxy)
            if tls is not None:
                self.sock = tls.wrap_socket(self.sock, server_hostname=server_hostname or host)
        except Exception:
            self.sock.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        self.sock.close()

    def send_raw(self, data):
        self.sock.sendall(data)

    def _wire(self, pkt):
        if self.single_connect:
            pkt.flags |= FLAG_SINGLE_CONNECT
        if self.tls:
            pkt.flags |= FLAG_UNENCRYPTED
        return pkt.encode(self.key)

    def send(self, pkt):
        self.send_raw(self._wire(pkt))

    def send_split(self, pkt, gap=0.2, at=HEADER_LEN):
        """Send the first `at` bytes (the header), wait gap seconds, send the rest.

        TCP_NODELAY so the two parts leave as separate segments.
        """
        data = self._wire(pkt)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.send_raw(data[:at])
        time.sleep(gap)
        self.send_raw(data[at:])

    def _exact(self, n):
        buf, self.buffered = self.buffered[:n], self.buffered[n:]
        while len(buf) < n:
            try:
                chunk = self.sock.recv(n - len(buf))
            except socket.timeout:
                raise TimeoutError("no reply from the daemon within %.1f s" % self.timeout)
            except (ConnectionResetError, ssl.SSLError) as e:
                raise Closed("connection reset by the daemon after %d of %d bytes (%s)" % (len(buf), n, e))
            if not chunk:
                raise Closed("connection closed by the daemon after %d of %d bytes" % (len(buf), n))
            buf += chunk
        return buf

    def _read(self):
        pkt, length = Packet.decode_header(self._exact(HEADER_LEN))
        body = self._exact(length)
        if pkt.flags & FLAG_UNENCRYPTED:
            if self.key:
                # RFC 8907 4.5 deprecates the flag: with a key configured, a clear-text reply is a failure
                raise ProtocolError("reply without obfuscation (TAC_PLUS_UNENCRYPTED_FLAG) although a key is set")
        else:
            body = obfuscate(body, pkt.session_id, self.key, pkt.version, pkt.seq_no)
        pkt.body = body
        return pkt

    def recv(self, session_id=None):
        """The next packet, or the next one of session_id; others are kept for their session."""
        for i, pkt in enumerate(self.pending):
            if session_id is None or pkt.session_id == session_id:
                return self.pending.pop(i)
        while True:
            pkt = self._read()
            if session_id is None or pkt.session_id == session_id:
                return pkt
            self.pending.append(pkt)

    def _peek(self, timeout):
        """b"" if the daemon closed the connection, None if nothing came within timeout, else the byte read."""
        if self.buffered:
            return self.buffered[:1]
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(1)
        except socket.timeout:
            return None
        except (ConnectionResetError, ssl.SSLError):
            return b""
        finally:
            self.sock.settimeout(self.timeout)
        self.buffered += data
        return data

    def closed(self, timeout=None):
        """True if the daemon closes the connection without sending anything."""
        return self._peek(self.timeout if timeout is None else timeout) == b""

    def silent(self, timeout=1.0):
        """True if nothing arrives within timeout (or the daemon closes the connection)."""
        if self.pending:
            return False
        return not self._peek(timeout)

    def session(self, session_id=None):
        return Session(self, session_id)

    # one session per dialog
    def pap(self, user, password, **kw):
        return self.session().pap(user, password, **kw)

    def ascii_login(self, user, password, **kw):
        return self.session().ascii_login(user, password, **kw)

    def chap(self, user, password, **kw):
        return self.session().chap(user, password, **kw)

    def mschap(self, user, password, **kw):
        return self.session().mschap(user, password, **kw)

    def enable(self, password, **kw):
        return self.session().enable(password, **kw)

    def author(self, user, args, **kw):
        return self.session().author(user, args, **kw)

    def acct(self, user, args, **kw):
        return self.session().acct(user, args, **kw)


class Session:
    def __init__(self, conn, session_id=None):
        self.conn = conn
        self.session_id = session_id if session_id is not None else new_session_id()
        self.seq_no = 0
        self.version = None         # of the last packet sent

    def send(self, pkt):
        self.seq_no += 1
        pkt.seq_no = self.seq_no
        pkt.session_id = self.session_id
        self.version = pkt.version
        self.conn.send(pkt)

    def recv(self):
        pkt = self.conn.recv(self.session_id)
        if pkt.seq_no != self.seq_no + 1:
            raise ProtocolError("reply with seq_no %d, expected %d" % (pkt.seq_no, self.seq_no + 1))
        if self.version is not None and pkt.version != self.version:
            raise ProtocolError("reply with version 0x%02x to a request with 0x%02x" % (pkt.version, self.version))
        self.seq_no = pkt.seq_no
        return pkt

    # authentication

    def start(self, **kw):
        """Send an authentication START, return its REPLY."""
        self.send(Packet.authen_start(**kw))
        return AuthenReply(self.recv())

    def cont(self, user_msg=b"", data=b"", abort=False):
        """Send an authentication CONTINUE, return the REPLY (none after an abort)."""
        self.send(Packet.authen_continue(user_msg, data, CONTINUE_FLAG_ABORT if abort else 0))
        if abort:
            return None
        return AuthenReply(self.recv())

    def dialog(self, first, answers):
        """Answer GETUSER/GETPASS/GETDATA from answers until the server decides.

        answers: {"GETUSER": [...], "GETPASS": [...], "GETDATA": [...]};
        a list runs out -> ProtocolError (the server asked more than expected).
        """
        replies = [first]
        queues = {k: list(v) for k, v in answers.items()}
        while replies[-1].status_name in ("GETUSER", "GETPASS", "GETDATA"):
            if len(replies) >= DIALOG_LIMIT:
                raise ProtocolError("more than %d REPLYs in one dialog: %r" % (DIALOG_LIMIT, Dialog(replies)))
            asked = replies[-1].status_name
            queue = queues.get(asked)
            if not queue:
                raise ProtocolError("unexpected %s %r in %r" % (asked, replies[-1].server_msg, Dialog(replies)))
            replies.append(self.cont(queue.pop(0)))
        return Dialog(replies)

    def ascii_login(self, user, password, user_in_start=True, data=(), **kw):
        """ASCII login (RFC 8907 5.4.4.1).

        user_in_start=False sends an empty user and answers GETUSER instead.
        password: a string, or a list answering one GETPASS each (retries).
        data: answers to GETDATA (e.g. a new password).
        """
        passwords = [password] if isinstance(password, (str, bytes)) else list(password)
        first = self.start(user=user if user_in_start else "", authen_type=AUTHEN_TYPE_ASCII, **kw)
        return self.dialog(first, {"GETUSER": [user], "GETPASS": passwords, "GETDATA": list(data)})

    def enable(self, password, user="", priv_lvl=15, **kw):
        """Enable request: ASCII login with service ENABLE (RFC 8907 5.4.4.1)."""
        passwords = [password] if isinstance(password, (str, bytes)) else list(password)
        first = self.start(user=user, authen_type=AUTHEN_TYPE_ASCII, service=AUTHEN_SVC_ENABLE,
                           priv_lvl=priv_lvl, **kw)
        return self.dialog(first, {"GETUSER": [user], "GETPASS": passwords})

    def pap(self, user, password, **kw):
        """PAP login (RFC 8907 5.4.2.2): password in the START data field, version 0xc1."""
        kw.setdefault("version", VERSION_ONE)
        return Dialog([self.start(user=user, data=password, authen_type=AUTHEN_TYPE_PAP, **kw)])

    def chap(self, user, password, challenge=None, ppp_id=1, **kw):
        """CHAP (RFC 8907 5.4.2.3): id, challenge and MD5(id + secret + challenge) in START."""
        challenge = challenge or os.urandom(16)
        response = hashlib.md5(bytes([ppp_id]) + _b(password) + challenge).digest()
        kw.setdefault("version", VERSION_ONE)
        return Dialog([self.start(user=user, data=bytes([ppp_id]) + challenge + response,
                                  authen_type=AUTHEN_TYPE_CHAP, service=AUTHEN_SVC_PPP, **kw)])

    def mschap(self, user, password, version=2, ppp_id=1, **kw):
        """MS-CHAP v1 (RFC 2433) or v2 (RFC 2759), as RFC 8907 5.4.2.4/5 puts them in START.

        v1: id, 8-byte challenge, LM response (zeros), NT response, flags.
        v2: id, 16-byte authenticator challenge, peer challenge, 8 reserved
        bytes, NT response, flags.
        """
        nt = crypto.nt_hash(password)
        if version == 1:
            challenge = os.urandom(8)
            response = bytes(24) + crypto.challenge_response(challenge, nt) + b"\x01"
            authen_type = AUTHEN_TYPE_MSCHAP
        else:
            challenge, peer = os.urandom(16), os.urandom(16)
            hashed = crypto.mschapv2_challenge_hash(peer, challenge, _b(user))
            response = peer + bytes(8) + crypto.challenge_response(hashed, nt) + b"\x00"
            authen_type = AUTHEN_TYPE_MSCHAPV2
        kw.setdefault("version", VERSION_ONE)
        return Dialog([self.start(user=user, data=bytes([ppp_id]) + challenge + response,
                                  authen_type=authen_type, service=AUTHEN_SVC_PPP, **kw)])

    # authorization and accounting

    def author(self, user, args, **kw):
        self.send(Packet.author_request(user, args, **kw))
        return AuthorReply(self.recv())

    def acct(self, user, args, flags=ACCT_FLAG_START, **kw):
        self.send(Packet.acct_request(user, args, flags=flags, **kw))
        return AcctReply(self.recv())
