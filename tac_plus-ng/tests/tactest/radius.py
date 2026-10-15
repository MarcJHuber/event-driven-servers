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


"""Minimal RADIUS client (RFC 2865/2866, RADIUS/TCP RFC 6613, RADIUS/TLS RFC 6614), standard library only.

  Packet      code, identifier, authenticator and attributes as fields;
              encode() can override the length and the Message-Authenticator
  Client      UDP, TCP or TLS over TCP: send_raw(), recv_raw() with a
              timeout, exchange() checks the Response Authenticator,
              access_request() with a PAP User-Password of arbitrary bytes

Message-Authenticator (RFC 3579 3.2) is added on request;
reply_message_authenticator() checks the one in a reply. Over TLS the
shared secret is "radsec" (RFC 6614 2.3).
"""

import hashlib
import hmac
import os
import socket
import struct

ACCESS_REQUEST = 1

CODES = {1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject", 4: "Accounting-Request",
         5: "Accounting-Response", 11: "Access-Challenge", 12: "Status-Server", 13: "Status-Client"}

# attributes
USER_NAME = 1
USER_PASSWORD = 2
REPLY_MESSAGE = 18
MESSAGE_AUTHENTICATOR = 80

HEADER_LEN = 20


def _b(value):
    if isinstance(value, bytes):
        return value
    return str(value).encode()


def encrypt_password(password, secret, authenticator):
    """RFC 2865 5.2: pad to 16 bytes, XOR with the MD5 chain. password is any bytes."""
    p = _b(password)
    if not p or len(p) % 16:
        p += b"\x00" * (16 - len(p) % 16)
    out, prev = b"", authenticator
    for i in range(0, len(p), 16):
        block = bytes(a ^ b for a, b in zip(p[i:i + 16], hashlib.md5(_b(secret) + prev).digest()))
        out += block
        prev = block
    return out


class ProtocolError(Exception):
    """The server answered with something that is not a valid reply."""


class Packet:
    def __init__(self, code, identifier=None, authenticator=None, attributes=()):
        self.code = code
        self.identifier = os.urandom(1)[0] if identifier is None else identifier
        self.authenticator = authenticator if authenticator is not None else os.urandom(16)
        self.attributes = [(t, _b(v)) for t, v in attributes]

    def get(self, attr_type):
        """Values of every attribute of attr_type."""
        return [v for t, v in self.attributes if t == attr_type]

    @property
    def code_name(self):
        return CODES.get(self.code, str(self.code))

    def _attrs(self):
        out = b""
        for t, v in self.attributes:
            if len(v) > 253:
                raise ValueError("attribute %d longer than 253 bytes" % t)
            out += bytes([t, len(v) + 2]) + v
        return out

    def encode(self, secret=None, length=None, message_authenticator=False):
        """Serialize; message_authenticator adds an HMAC-MD5 over the packet (needs secret).

        message_authenticator may also be 16 bytes to send instead of the
        right value.
        """
        attrs = self._attrs()
        if message_authenticator:
            attrs += bytes([MESSAGE_AUTHENTICATOR, 18]) + bytes(16)
        real = HEADER_LEN + len(attrs)
        data = struct.pack("!BBH", self.code, self.identifier, real) + self.authenticator + attrs
        if isinstance(message_authenticator, bytes):
            data = data[:-16] + message_authenticator
        elif message_authenticator:
            mac = hmac.new(_b(secret), data, hashlib.md5).digest()
            data = data[:-16] + mac
        if length is not None:
            data = data[:2] + struct.pack("!H", length) + data[4:]
        return data

    @classmethod
    def decode(cls, data):
        if len(data) < HEADER_LEN:
            raise ProtocolError("RADIUS packet too short (%d bytes)" % len(data))
        code, identifier, length = struct.unpack("!BBH", data[:4])
        if length != len(data):
            raise ProtocolError("RADIUS length field %d, packet has %d bytes" % (length, len(data)))
        pkt = cls(code, identifier, data[4:20], ())
        p = HEADER_LEN
        while p < length:
            if p + 2 > length or data[p + 1] < 2 or p + data[p + 1] > length:
                raise ProtocolError("malformed attribute at offset %d" % p)
            pkt.attributes.append((data[p], data[p + 2:p + data[p + 1]]))
            p += data[p + 1]
        pkt.raw = data
        return pkt

    def __repr__(self):
        return "Packet(%s, id=%d, attributes=%r)" % (self.code_name, self.identifier, self.attributes)


def reply_message_authenticator(raw, request_authenticator, secret):
    """None if the reply has no Message-Authenticator, else whether it is right.

    RFC 3579 3.2: HMAC-MD5 over the reply with the Request Authenticator in
    place of the Response Authenticator and the attribute's value zeroed.
    """
    p, found = HEADER_LEN, None
    while p + 2 <= len(raw) and raw[p + 1] >= 2 and p + raw[p + 1] <= len(raw):
        if raw[p] == MESSAGE_AUTHENTICATOR and raw[p + 1] == 18:
            found = p + 2
        p += raw[p + 1]
    if found is None:
        return None
    data = raw[:4] + request_authenticator + raw[20:found] + bytes(16) + raw[found + 16:]
    return hmac.compare_digest(hmac.new(_b(secret), data, hashlib.md5).digest(), raw[found:found + 16])


class Client:
    """One UDP socket (or TCP connection with tcp=True) to the daemon. Usable as a context manager.

    tls: an ssl.SSLContext for RADIUS over TLS (implies tcp); the secret
    should then be "radsec".
    """

    def __init__(self, addr, secret, timeout=5.0, source=None, tcp=False, tls=None):
        host, port = addr[0], addr[1]
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.secret = _b(secret)
        self.timeout = timeout
        self.tcp = tcp or tls is not None
        self.sock = socket.socket(family, socket.SOCK_STREAM if self.tcp else socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        try:
            if source is not None:
                self.sock.bind((source, 0))
            self.sock.connect((host, port))
            if tls is not None:
                self.sock = tls.wrap_socket(self.sock, server_hostname=host)
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

    def _exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed by the daemon after %d of %d bytes" % (len(buf), n))
            buf += chunk
        return buf

    def recv_raw(self):
        try:
            if not self.tcp:
                return self.sock.recv(65535)
            head = self._exact(4)
            return head + self._exact(struct.unpack("!H", head[2:4])[0] - 4)
        except socket.timeout:
            raise TimeoutError("no RADIUS reply from the daemon within %.1f s" % self.timeout)

    def exchange(self, request, message_authenticator=False):
        """Send request, return the reply after checking identifier and Response Authenticator.

        reply.message_authenticator: None (none in the reply), True or False (wrong).
        """
        self.send_raw(request.encode(self.secret, message_authenticator=message_authenticator))
        reply = Packet.decode(self.recv_raw())
        if reply.identifier != request.identifier:
            raise ProtocolError("reply identifier %d, request %d" % (reply.identifier, request.identifier))
        raw = reply.raw
        expected = hashlib.md5(raw[:4] + request.authenticator + raw[20:] + self.secret).digest()
        if expected != reply.authenticator:
            raise ProtocolError("wrong Response Authenticator -- wrong secret?")
        reply.message_authenticator = reply_message_authenticator(raw, request.authenticator, self.secret)
        return reply

    def access_request(self, user, password, attributes=(), message_authenticator=False):
        """Access-Request with a PAP User-Password; password may be any bytes, also not UTF-8."""
        req = Packet(ACCESS_REQUEST)
        req.attributes = [(USER_NAME, _b(user)),
                          (USER_PASSWORD, encrypt_password(password, self.secret, req.authenticator))]
        req.attributes += [(t, _b(v)) for t, v in attributes]
        return self.exchange(req, message_authenticator)
