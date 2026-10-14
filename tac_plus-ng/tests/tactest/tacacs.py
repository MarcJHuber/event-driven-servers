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

"""Minimal TACACS+ client (RFC 8907), Python standard library only.

Three layers, each usable directly by a test:

  Packet      header fields + clear-text body; encode() can override every
              header field and skip obfuscation, for malformed-packet tests
  Connection  one TCP socket: send(), send_raw(), recv() with a timeout,
              closed() to detect EOF without a reply
  Session     one session_id and its sequence numbers on a Connection

plus ready-made dialogs on top (currently PAP only).
"""

import hashlib
import os
import socket
import struct

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
AUTHEN_SVC_LOGIN = 1

AUTHEN_STATUS = {
    1: "PASS", 2: "FAIL", 3: "GETDATA", 4: "GETUSER",
    5: "GETPASS", 6: "RESTART", 7: "ERROR", 0x21: "FOLLOW",
}


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


class Packet:
    def __init__(self, type, body=b"", seq_no=1, session_id=None, flags=0, version=VERSION_DEFAULT):
        self.type = type
        self.body = body
        self.seq_no = seq_no
        self.session_id = session_id if session_id is not None else new_session_id()
        self.flags = flags
        self.version = version

    def encode(self, key, version=None, type=None, seq_no=None, flags=None, session_id=None,
               length=None, obfuscate_body=True):
        """Serialize; every keyword overrides what goes on the wire."""
        version = self.version if version is None else version
        type = self.type if type is None else type
        seq_no = self.seq_no if seq_no is None else seq_no
        flags = self.flags if flags is None else flags
        session_id = self.session_id if session_id is None else session_id
        body = self.body
        if obfuscate_body and not flags & FLAG_UNENCRYPTED:
            body = obfuscate(body, session_id, _b(key), version, seq_no)
        length = len(body) if length is None else length
        return struct.pack("!BBBBII", version, type, seq_no, flags, session_id, length) + body

    @classmethod
    def decode_header(cls, data):
        version, type, seq_no, flags, session_id, length = struct.unpack("!BBBBII", data[:HEADER_LEN])
        pkt = cls(type, b"", seq_no, session_id, flags, version)
        return pkt, length

    @classmethod
    def authen_start(cls, user="", port="tty0", rem_addr="127.0.0.1", data=b"",
                     action=AUTHEN_LOGIN, priv_lvl=1, authen_type=AUTHEN_TYPE_ASCII,
                     service=AUTHEN_SVC_LOGIN, **kw):
        u, p, r, d = _b(user), _b(port), _b(rem_addr), _b(data)
        body = struct.pack("!BBBBBBBB", action, priv_lvl, authen_type, service, len(u), len(p), len(r), len(d))
        return cls(TYPE_AUTHEN, body + u + p + r + d, **kw)


def new_session_id():
    return struct.unpack("!I", os.urandom(4))[0]


class AuthenReply:
    def __init__(self, packet):
        b = packet.body
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

    def __repr__(self):
        return "AuthenReply(%s, server_msg=%r)" % (self.status_name, self.server_msg)


class Connection:
    """One TCP connection to the daemon. Usable as a context manager."""

    def __init__(self, addr, key, timeout=5.0, source=None, single_connect=False):
        host, port = addr[0], addr[1]
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.key = _b(key)
        self.timeout = timeout
        self.single_connect = single_connect
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        try:
            if source is not None:
                self.sock.bind((source, 0))
            self.sock.connect((host, port))
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

    def send(self, pkt):
        if self.single_connect:
            pkt.flags |= FLAG_SINGLE_CONNECT
        self.send_raw(pkt.encode(self.key))

    def _exact(self, n):
        buf = b""
        while len(buf) < n:
            try:
                chunk = self.sock.recv(n - len(buf))
            except socket.timeout:
                raise TimeoutError("no reply from the daemon within %.1f s" % self.timeout)
            if not chunk:
                raise Closed("connection closed by the daemon after %d of %d bytes" % (len(buf), n))
            buf += chunk
        return buf

    def recv(self):
        pkt, length = Packet.decode_header(self._exact(HEADER_LEN))
        body = self._exact(length)
        if not pkt.flags & FLAG_UNENCRYPTED:
            body = obfuscate(body, pkt.session_id, self.key, pkt.version, pkt.seq_no)
        pkt.body = body
        return pkt

    def closed(self, timeout=None):
        """True if the daemon closes the connection without sending anything."""
        self.sock.settimeout(self.timeout if timeout is None else timeout)
        try:
            return self.sock.recv(1) == b""
        except socket.timeout:
            return False
        except ConnectionResetError:
            return True
        finally:
            self.sock.settimeout(self.timeout)

    def session(self):
        return Session(self)

    def pap(self, user, password, **kw):
        return self.session().pap(user, password, **kw)


class Session:
    def __init__(self, conn, session_id=None):
        self.conn = conn
        self.session_id = session_id if session_id is not None else new_session_id()
        self.seq_no = 0

    def send(self, pkt):
        self.seq_no += 1
        pkt.seq_no = self.seq_no
        pkt.session_id = self.session_id
        self.conn.send(pkt)

    def recv(self):
        pkt = self.conn.recv()
        if pkt.session_id != self.session_id:
            raise ProtocolError("reply for session %#x, expected %#x" % (pkt.session_id, self.session_id))
        self.seq_no = pkt.seq_no
        return pkt

    def pap(self, user, password, **kw):
        """PAP login (RFC 8907 5.4.2.2): password in the START data field, version 0xc1."""
        self.send(Packet.authen_start(user=user, data=password, authen_type=AUTHEN_TYPE_PAP,
                                      version=VERSION_ONE, **kw))
        return AuthenReply(self.recv())
