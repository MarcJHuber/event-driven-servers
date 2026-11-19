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


"""EAP over RADIUS: unit tests for the packet helpers in tactest.radius.

The end-to-end EAP-TLS conversations come later; these tests pin the wire
format (RFC 3748, RFC 5216 3.1/3.2): EAP header lengths, EAP-Message
splitting at 253 bytes, State extraction, and the EAP-TLS flags.
"""

import os
import ssl
import struct
import unittest

from tactest import SOURCE, DaemonTestCase, features, radius, tls

DICTIONARY = os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")


class EapPacket(unittest.TestCase):
    def test_packet_round_trip(self):
        """Code/Identifier/Length, the type byte, and the data in between."""
        data = radius.eap_packet(radius.EAP_RESPONSE, 7, radius.EAP_TYPE_IDENTITY, b"alice")
        code, identifier, length = struct.unpack("!BBH", data[:4])
        self.assertEqual((code, identifier, length), (radius.EAP_RESPONSE, 7, 10))
        self.assertEqual(data[4], radius.EAP_TYPE_IDENTITY)
        self.assertEqual(data[5:], b"alice")

    def test_success_and_failure_have_no_type(self):
        """EAP-Success/Failure are the 4-byte header alone (RFC 3748 4.2/4.3)."""
        for code in (radius.EAP_SUCCESS, radius.EAP_FAILURE):
            data = radius.eap_packet(code, 9)
            self.assertEqual(data, struct.pack("!BBH", code, 9, 4))

    def test_attributes_split_at_253_bytes(self):
        """EAP-Message values are at most 253 bytes, in order (RFC 3579 3.1)."""
        eap = bytes(range(256)) * 2        # 512 bytes
        attrs = radius.eap_attributes(eap)
        self.assertEqual([t for t, _ in attrs], [radius.EAP_MESSAGE] * 3)
        self.assertEqual([len(v) for _, v in attrs], [253, 253, 6])
        self.assertEqual(b"".join(v for _, v in attrs), eap)

    def test_exactly_253_bytes_is_one_attribute(self):
        attrs = radius.eap_attributes(b"x" * 253)
        self.assertEqual(len(attrs), 1)
        self.assertEqual(attrs[0], (radius.EAP_MESSAGE, b"x" * 253))

    def test_eap_from_reply_concatenates_attributes(self):
        """The values are concatenated in order to rebuild the EAP packet."""
        eap = bytes(range(200)) + bytes(range(56))
        packet = radius.Packet(11, attributes=radius.eap_attributes(eap))
        reply = radius.Packet.decode(packet.encode())
        self.assertEqual(radius.eap_from_reply(reply), eap)

    def test_state_extraction(self):
        """State is attribute 24 and survives a RADIUS round trip."""
        state = b"\x01\x02\x03\x04"
        packet = radius.Packet(11, attributes=[(radius.STATE, state)])
        reply = radius.Packet.decode(packet.encode())
        self.assertEqual(reply.get(radius.STATE), [state])
        self.assertEqual(radius.eap_from_reply(reply), b"")

    def test_tls_ack_is_six_bytes_with_flags_zero(self):
        """An empty EAP-Response/EAP-TLS ACK has the type and a zero flags byte."""
        ack = radius.eap_tls_ack(5)
        self.assertEqual(len(ack), 6)
        self.assertEqual(ack, struct.pack("!BBH", radius.EAP_RESPONSE, 5, 6) +
                         bytes([radius.EAP_TYPE_TLS, 0]))
        self.assertEqual(ack[5], 0)

    def test_tls_l_flag_carries_total_length(self):
        """L includes the 4-byte TLS Message Length (RFC 5216 3.1)."""
        data = b"\x16\x03\x03" + bytes(10)
        packet = radius.eap_tls_packet(radius.EAP_REQUEST, 1, radius.EAP_TLS_L | radius.EAP_TLS_M,
                                       data, total=1000)
        self.assertEqual(len(packet), 4 + 1 + 1 + 4 + len(data))
        self.assertEqual(packet[4], radius.EAP_TYPE_TLS)
        self.assertEqual(packet[5], radius.EAP_TLS_L | radius.EAP_TLS_M)
        self.assertEqual(struct.unpack("!I", packet[6:10])[0], 1000)
        self.assertEqual(packet[10:], data)

    def test_tls_l_flag_defaults_to_data_length(self):
        data = b"abc"
        packet = radius.eap_tls_packet(radius.EAP_REQUEST, 1, radius.EAP_TLS_L, data)
        self.assertEqual(struct.unpack("!I", packet[6:10])[0], len(data))

    def test_tls_reserved_bits_are_zero(self):
        """Generated packets use only L/M/S; the reserved bits stay zero."""
        start = radius.eap_tls_packet(radius.EAP_REQUEST, 1, radius.EAP_TLS_S)
        self.assertEqual(start[5], radius.EAP_TLS_S)
        self.assertEqual(start[5] & 0x1f, 0)
        first = radius.eap_tls_packet(radius.EAP_REQUEST, 2, radius.EAP_TLS_L | radius.EAP_TLS_M,
                                      b"x", total=1)
        self.assertEqual(first[5] & 0x1f, 0)
        ack = radius.eap_tls_ack(3)
        self.assertEqual(ack[5] & 0x3f, 0)


EAP_STATE_LEN = 16
EAP_INVALID_LIMIT = 5
EAP_MAX_FRAGMENT = 3000


def eap_parse_hdr(eap):
    """Reference model of eap_parse_hdr() in eap.c (RFC 3748, RFC 5216 3.1/3.2).

    Returns code/identifier/length/type/flags/data. Raises ValueError for a
    header shorter than 4 bytes, a declared length below 4 or beyond the
    buffer, a missing type/flags byte, or the S bit in an EAP-Response.
    Trailing bytes beyond the declared length are padding and ignored.
    """
    if len(eap) < 4:
        raise ValueError("EAP packet shorter than the 4-byte header")
    code, identifier, length = struct.unpack("!BBH", eap[:4])
    if length < 4 or length > len(eap):
        raise ValueError("EAP length %d, buffer %d" % (length, len(eap)))
    parsed = {"code": code, "identifier": identifier, "length": length,
              "type": None, "flags": 0, "data": b""}
    if code not in (radius.EAP_REQUEST, radius.EAP_RESPONSE):
        parsed["data"] = eap[4:length]
        return parsed
    if length < 5:
        raise ValueError("EAP Request/Response without a type byte")
    eap_type = eap[4]
    parsed["type"] = eap_type
    off = 5
    if eap_type == radius.EAP_TYPE_TLS:
        if length < 6:
            raise ValueError("EAP-TLS without a flags byte")
        flags = eap[5]
        if code == radius.EAP_RESPONSE and flags & radius.EAP_TLS_S:
            raise ValueError("S bit set in EAP-Response/EAP-TLS")
        parsed["flags"] = flags & (radius.EAP_TLS_L | radius.EAP_TLS_M | radius.EAP_TLS_S)
        off = 6
    parsed["data"] = eap[off:length]
    return parsed


def collect_eap_message(attributes, max_message=65535):
    """Reference model of eap_collect() in eap.c.

    EAP-Message values must be consecutive (RFC 3579 3.1) and are
    concatenated in order; an empty value is EAP-Start. Raises ValueError
    when EAP-Message is absent, non-consecutive, or over max_message.
    """
    seen = False
    block_done = False
    chunks = []
    for attr_type, value in attributes:
        if attr_type == radius.EAP_MESSAGE:
            if block_done:
                raise ValueError("EAP-Message attributes are not consecutive")
            seen = True
            chunks.append(value)
        elif seen:
            block_done = True
    if not seen:
        raise ValueError("no EAP-Message attribute")
    eap = b"".join(chunks)
    if len(eap) > max_message:
        raise ValueError("EAP-Message longer than max-message")
    return eap


def eap_get_state(attributes):
    """Reference model of eap_get_state() in eap.c.

    Returns the first State value, or None. Raises ValueError for a
    zero-length State or a State longer than EAP_STATE_LEN.
    """
    for attr_type, value in attributes:
        if attr_type == radius.STATE:
            if not value:
                raise ValueError("zero-length State")
            if len(value) > EAP_STATE_LEN:
                raise ValueError("State longer than %d bytes" % EAP_STATE_LEN)
            return value
    return None


class EapParsing(unittest.TestCase):
    """RFC 3748 / RFC 5216 3.1/3.2 parsing rules.

    These tests pin the wire-format expectations with a reference model of
    the C helpers in eap.c; the C implementation itself is exercised
    end-to-end by the daemon tests added in Task 15.
    """

    def test_eap_header_accepts_declared_length(self):
        eap = radius.eap_packet(radius.EAP_RESPONSE, 4, radius.EAP_TYPE_IDENTITY, b"alice")
        parsed = eap_parse_hdr(eap)
        self.assertEqual(parsed["length"], len(eap))
        self.assertEqual(parsed["type"], radius.EAP_TYPE_IDENTITY)
        self.assertEqual(parsed["data"], b"alice")

    def test_eap_header_ignores_trailing_padding(self):
        """Octets beyond the EAP Length field are padding (RFC 5216 3.1/3.2)."""
        eap = radius.eap_tls_ack(7) + b"\x00\xff\x00"
        parsed = eap_parse_hdr(eap)
        self.assertEqual(parsed["length"], 6)
        self.assertEqual(parsed["flags"], 0)
        self.assertEqual(parsed["data"], b"")

    def test_eap_header_rejects_length_below_four(self):
        for length in (0, 1, 3):
            eap = struct.pack("!BBH", radius.EAP_RESPONSE, 1, length) + b"\x01"
            with self.assertRaises(ValueError):
                eap_parse_hdr(eap)

    def test_eap_header_rejects_length_beyond_buffer(self):
        eap = struct.pack("!BBH", radius.EAP_RESPONSE, 1, 100) + b"\x01\x00"
        with self.assertRaises(ValueError):
            eap_parse_hdr(eap)

    def test_eap_message_reassembles_253_byte_chunks_in_order(self):
        eap = bytes(range(256)) * 2
        attrs = [(radius.USER_NAME, b"alice")] + radius.eap_attributes(eap)
        self.assertEqual(collect_eap_message(attrs), eap)

    def test_eap_message_rejects_non_consecutive_attributes(self):
        """EAP-Message attributes must be consecutive (RFC 3579 3.1)."""
        eap = radius.eap_tls_ack(1)
        attrs = [(radius.EAP_MESSAGE, eap[:3]), (radius.STATE, b"\x01"),
                 (radius.EAP_MESSAGE, eap[3:])]
        with self.assertRaises(ValueError):
            collect_eap_message(attrs)

    def test_eap_message_zero_length_is_eap_start(self):
        """An EAP-Message attribute with a zero-length value starts EAP."""
        self.assertEqual(collect_eap_message([(radius.EAP_MESSAGE, b"")]), b"")

    def test_eap_message_rejects_oversized_concatenation(self):
        attrs = radius.eap_attributes(bytes(300))
        with self.assertRaises(ValueError):
            collect_eap_message(attrs, max_message=256)

    def test_eap_state_returns_first_attribute(self):
        attrs = [(radius.STATE, b"\x01\x02"), (radius.STATE, b"\x03\x04")]
        self.assertEqual(eap_get_state(attrs), b"\x01\x02")

    def test_eap_state_absent_returns_none(self):
        self.assertIsNone(eap_get_state([(radius.USER_NAME, b"alice")]))

    def test_eap_state_rejects_zero_length(self):
        with self.assertRaises(ValueError):
            eap_get_state([(radius.STATE, b"")])

    def test_eap_state_rejects_overlong_state(self):
        with self.assertRaises(ValueError):
            eap_get_state([(radius.STATE, bytes(EAP_STATE_LEN + 1))])

    def test_eap_tls_response_rejects_s_bit(self):
        """RFC 5216 3.2: the S bit MUST NOT be set in an EAP-Response."""
        eap = radius.eap_tls_packet(radius.EAP_RESPONSE, 2, radius.EAP_TLS_S)
        with self.assertRaises(ValueError):
            eap_parse_hdr(eap)

    def test_eap_tls_reserved_bits_ignored_on_receive(self):
        """Reserved bits are ignored, not rejected (RFC 5216 3.2)."""
        eap = radius.eap_tls_packet(radius.EAP_RESPONSE, 2, radius.EAP_TLS_M | 0x01)
        parsed = eap_parse_hdr(eap)
        self.assertEqual(parsed["flags"], radius.EAP_TLS_M)

    def test_eap_tls_request_s_bit_accepted(self):
        """The S bit is valid in EAP-Request/EAP-TLS Start (RFC 5216 3.1)."""
        eap = radius.eap_tls_packet(radius.EAP_REQUEST, 1, radius.EAP_TLS_S)
        self.assertEqual(eap_parse_hdr(eap)["flags"], radius.EAP_TLS_S)


class TlsProfile(unittest.TestCase):
    @unittest.skipUnless("openssl" in features(), "tac_plus-ng built without OpenSSL")
    @unittest.skipUnless(tls.openssl_available(), "no openssl command to make certificates")
    def test_context_pins_tls12_minimum_and_maximum(self):
        """EAP-TLS uses TLS 1.2 only: CA.context() must accept and keep both bounds."""
        ca = tls.CA("eap-tls12")
        self.addCleanup(ca.remove)
        ctx = ca.context(minimum=ssl.TLSVersion.TLSv1_2, maximum=ssl.TLSVersion.TLSv1_2)
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(ctx.maximum_version, ssl.TLSVersion.TLSv1_2)


EAP_POLICY = """
\tinclude = "%s"
\teap {
\t\teap-method = tls
\t\tcert-file = %s
\t\tkey-file = %s
\t\tca-file = %s
\t\tverify-client = yes
\t\teap-identity-source = cert-cn
\t}
\tdevice radius-nas {
\t\taddress = 127.0.0.6
\t\tkey = tactest
\t\tradius.key = radsecret
\t}
\tprofile eap-profile {
\t\tscript { permit }
\t}
\tuser cert-user {
\t\tprofile = eap-profile
\t}
"""


class EapTlsPeer:
    """An EAP-TLS peer over ssl.SSLObject and memory BIOs (TLS 1.2 only).

    Sends EAP-Response packets in RADIUS Access-Requests and feeds the EAP
    data of the server's EAP-Requests to the SSLObject. Server fragments are
    reassembled; each fragment with M set is ACKed with an empty
    EAP-Response/EAP-TLS (six bytes, flags 0).
    """

    def __init__(self, client, ca, identity, cert=None):
        self.client = client
        self.identity = identity
        self.state = None
        self.identifier = 1
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.ctx = ca.context(cert=cert,
                              minimum=ssl.TLSVersion.TLSv1_2,
                              maximum=ssl.TLSVersion.TLSv1_2)
        self.sslobj = self.ctx.wrap_bio(self.incoming, self.outgoing,
                                        server_hostname="localhost")
        self.tls_requests = 0
        self.fragment_acks = 0
        self.client_fragment_acks = 0
        self.last_request = None
        self.last_reply = None

    def send_eap(self, eap):
        attrs = [(radius.USER_NAME, self.identity.encode())]
        attrs += radius.eap_attributes(eap)
        if self.state:
            attrs.append((radius.STATE, self.state))
        req = radius.Packet(radius.ACCESS_REQUEST, attributes=attrs)
        self.last_request = req
        r = self.client.exchange(req, message_authenticator=True)
        self.last_reply = r
        self.state = (r.get(radius.STATE) or [None])[0]
        return r

    def send_eap_state(self, eap, state):
        """Send eap with an explicit State, without touching self.state."""
        attrs = [(radius.USER_NAME, self.identity.encode())] + radius.eap_attributes(eap)
        attrs.append((radius.STATE, state))
        req = radius.Packet(radius.ACCESS_REQUEST, attributes=attrs)
        return self.client.exchange(req, message_authenticator=True)

    def start(self):
        """Identity -> EAP-Request/EAP-TLS Start; leaves peer.identifier at the Start id."""
        identity = radius.eap_packet(radius.EAP_RESPONSE, 1, radius.EAP_TYPE_IDENTITY,
                                     self.identity.encode())
        reply = self.send_eap(identity)
        _, data = self.receive_request(reply)
        if data:
            raise AssertionError("EAP-TLS Start carried data: %r" % data)

    def expect_fragment_ack(self, reply):
        """Expect an empty EAP-Request/EAP-TLS ACK (flags 0) for a client fragment."""
        if reply.code_name != "Access-Challenge":
            raise AssertionError("expected Access-Challenge fragment ACK, got %s: %r"
                                 % (reply.code_name, radius.eap_from_reply(reply)))
        identifier, flags, data, _ = self.parse_request(radius.eap_from_reply(reply))
        if flags or data:
            raise AssertionError("fragment ACK carried flags %#x and %d data bytes"
                                 % (flags, len(data)))
        self.client_fragment_acks += 1
        self.identifier = identifier

    def send_tls_flight(self, out):
        """Send a client TLS flight, fragmenting it when it exceeds EAP_MAX_FRAGMENT.

        RFC 5216 2.1.5: the first fragment carries L and the 4-byte total, M is
        set on all but the last fragment, and each fragment with M is answered
        by an empty EAP-Request/EAP-TLS ACK whose identifier the next fragment
        echoes. Returns the reply to the last fragment.
        """
        if len(out) <= EAP_MAX_FRAGMENT:
            return self.send_eap(radius.eap_tls_packet(radius.EAP_RESPONSE,
                                                       self.identifier, 0, out))
        total = len(out)
        offset = 0
        while True:
            chunk = out[offset:offset + EAP_MAX_FRAGMENT]
            first = offset == 0
            offset += len(chunk)
            more = offset < total
            flags = radius.EAP_TLS_L if first else 0
            if more:
                flags |= radius.EAP_TLS_M
            packet = radius.eap_tls_packet(radius.EAP_RESPONSE, self.identifier,
                                           flags, chunk, total=total)
            reply = self.send_eap(packet)
            if not more:
                return reply
            self.expect_fragment_ack(reply)

    @staticmethod
    def parse_request(eap):
        """(identifier, flags, data, announced total) of an EAP-Request/EAP-TLS."""
        if len(eap) < 4:
            raise AssertionError("EAP-Request shorter than 4 bytes: %r" % eap)
        code, identifier, length = struct.unpack("!BBH", eap[:4])
        if code != radius.EAP_REQUEST:
            raise AssertionError("expected EAP-Request, got EAP code %d: %r" % (code, eap))
        if length < 6 or length > len(eap):
            raise AssertionError("bad EAP length %d in %r" % (length, eap))
        if eap[4] != radius.EAP_TYPE_TLS:
            raise AssertionError("expected EAP-TLS, got EAP type %d" % eap[4])
        flags = eap[5]
        off = 6
        total = None
        if flags & radius.EAP_TLS_L:
            if length < 10:
                raise AssertionError("EAP-TLS L flag without a 4-byte length")
            total = struct.unpack("!I", eap[6:10])[0]
            off = 10
        return identifier, flags, eap[off:length], total

    def receive_request(self, reply):
        """One EAP-Request/EAP-TLS, reassembling fragments; returns (identifier, data)."""
        chunks = []
        total = None
        while True:
            if reply.code_name != "Access-Challenge":
                raise AssertionError("expected Access-Challenge, got %s: %r"
                                     % (reply.code_name, radius.eap_from_reply(reply)))
            identifier, flags, data, announced = self.parse_request(radius.eap_from_reply(reply))
            if announced is not None:
                total = announced
            if data:
                self.tls_requests += 1
            chunks.append(data)
            if not flags & radius.EAP_TLS_M:
                break
            self.fragment_acks += 1
            reply = self.send_eap(radius.eap_tls_ack(identifier))
        data = b"".join(chunks)
        if total is not None and len(data) != total:
            raise AssertionError("reassembled %d bytes, server announced %d" % (len(data), total))
        self.identifier = identifier
        return identifier, data

    def handshake(self, max_rounds=10):
        """Identity -> TLS Start, then run the client handshake to completion.

        RFC 5216 2.1.3: after the server's final TLS flight the peer sends an
        empty EAP-Response/EAP-TLS ACK, and only then may the server answer
        with EAP-Success. Returns the number of server TLS flights.
        """
        identity = radius.eap_packet(radius.EAP_RESPONSE, 1, radius.EAP_TYPE_IDENTITY,
                                     self.identity.encode())
        reply = self.send_eap(identity)
        _, data = self.receive_request(reply)
        if data:
            raise AssertionError("EAP-TLS Start carried data: %r" % data)

        for _ in range(max_rounds):
            try:
                self.sslobj.do_handshake()
            except ssl.SSLWantReadError:
                out = self.outgoing.read()
                if not out:
                    raise AssertionError("SSLObject wants to read but has no output for the server")
                reply = self.send_tls_flight(out)
                _, data = self.receive_request(reply)
                self.incoming.write(data)
                continue
            except ssl.SSLWantWriteError:
                # A memory BIO has no fixed size; retry after draining it.
                self.outgoing.read()
                continue
            # do_handshake() returned None: the client handshake is complete.
            # The server's final flight was received in the previous round;
            # ACK it with an empty EAP-Response/EAP-TLS (RFC 5216 2.1.3).
            ack_identifier = self.identifier
            reply = self.send_eap(radius.eap_tls_ack(ack_identifier))
            if reply.code_name != "Access-Accept":
                raise AssertionError("expected Access-Accept after the final ACK, got %s: %r"
                                     % (reply.code_name, radius.eap_from_reply(reply)))
            eap = radius.eap_from_reply(reply)
            if len(eap) != 4:
                raise AssertionError("EAP-Success must be a 4-byte packet, got %r" % eap)
            code, identifier, length = struct.unpack("!BBH", eap)
            if code != radius.EAP_SUCCESS:
                raise AssertionError("expected EAP-Success (3), got EAP code %d: %r" % (code, eap))
            if identifier != ack_identifier:
                raise AssertionError("EAP-Success identifier %d, ACK identifier %d"
                                     % (identifier, ack_identifier))
            if reply.get(radius.STATE):
                raise AssertionError("Access-Accept carries State: %r" % reply.get(radius.STATE))
            return self.tls_requests
        raise AssertionError("TLS handshake did not complete in %d rounds" % max_rounds)

    def handshake_until_alert(self, max_rounds=10):
        """Run the client handshake until the server sends a TLS alert.

        Returns (identifier, alert) of the EAP-Request/EAP-TLS carrying the
        alert. The caller answers it with an empty EAP-Response/EAP-TLS and
        expects EAP-Failure (RFC 5216 2.1.3). The server must not send
        EAP-Failure before that response; receive_request() would reject an
        Access-Reject here.
        """
        identity = radius.eap_packet(radius.EAP_RESPONSE, 1, radius.EAP_TYPE_IDENTITY,
                                     self.identity.encode())
        reply = self.send_eap(identity)
        _, data = self.receive_request(reply)
        if data:
            raise AssertionError("EAP-TLS Start carried data: %r" % data)

        for _ in range(max_rounds):
            try:
                self.sslobj.do_handshake()
            except ssl.SSLWantReadError:
                out = self.outgoing.read()
                if not out:
                    raise AssertionError("SSLObject wants to read but has no output for the server")
                reply = self.send_tls_flight(out)
                identifier, data = self.receive_request(reply)
                if len(data) >= 5 and data[0] == 21:      # TLS alert record
                    return identifier, data
                self.incoming.write(data)
                continue
            except ssl.SSLWantWriteError:
                self.outgoing.read()
                continue
            raise AssertionError("TLS handshake completed without a server alert")
        raise AssertionError("no TLS alert in %d rounds" % max_rounds)


@unittest.skipUnless("openssl" in features(), "EAP needs a build with OpenSSL")
@unittest.skipUnless(tls.openssl_available(), "no openssl command to make certificates")
class EapTlsTestCase(DaemonTestCase):
    """An EAP realm with TLS credentials from a throw-away CA.

    CONFIG is the EAP policy with the CA's server certificate/key and root
    certificate; client certificates are issued by the same CA.
    """

    UDP = True

    @classmethod
    def server_certificate(cls):
        """(certificate, key) for the EAP TLS server; subclasses may override."""
        return cls.ca.server

    @classmethod
    def client_certificate(cls):
        """Client certificate presented by EapTlsPeer; subclasses may override."""
        return cls.ca.issue("cert-user", "/CN=cert-user")

    @classmethod
    def setUpClass(cls):
        cls.ca = tls.CA(cls.__name__ + "-ca")
        try:
            cls.client_cert = cls.client_certificate()
            server = cls.server_certificate()
            cls.CONFIG = EAP_POLICY % (DICTIONARY, server[0], server[1], cls.ca.cert)
            super().setUpClass()
        except Exception:
            cls.ca.remove()
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            super().tearDownClass()
        finally:
            if not cls._failed:
                cls.ca.remove()

    def radius(self, secret, **kw):
        kw.setdefault("source", "127.0.0.6")
        return super().radius(secret, **kw)


class EapIdentity(EapTlsTestCase):
    """EAP-Response/Identity without State: a new session, EAP-Request/EAP-TLS Start."""

    def test_identity_gets_tls_start(self):
        c = self.radius("radsecret")
        eap = radius.eap_packet(radius.EAP_RESPONSE, 1, radius.EAP_TYPE_IDENTITY, b"cert-user")
        req = radius.Packet(radius.ACCESS_REQUEST, attributes=[
            (radius.USER_NAME, b"cert-user")] + radius.eap_attributes(eap))
        r = c.exchange(req, message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Challenge", r)
        reply_eap = radius.eap_from_reply(r)
        self.assertGreaterEqual(len(reply_eap), 6, reply_eap)
        self.assertEqual(reply_eap[0], radius.EAP_REQUEST, reply_eap)
        self.assertEqual(reply_eap[4], radius.EAP_TYPE_TLS, reply_eap)
        self.assertTrue(reply_eap[5] & radius.EAP_TLS_S, reply_eap)
        self.assertTrue(r.get(radius.STATE), "Access-Challenge without State")


class EapTlsHandshake(EapTlsTestCase):
    """The TLS handshake itself: the server's flights go through EAP-TLS."""

    def test_client_handshake_completes(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        server_flights = peer.handshake()

        # The server sent at least one EAP-Request/EAP-TLS with TLS records.
        self.assertGreater(server_flights, 0, "no EAP-Request/EAP-TLS carried TLS data")
        # The client finished its side of the TLS 1.2 handshake.
        self.assertEqual(peer.sslobj.version(), "TLSv1.2")
        self.assertIsNotNone(peer.sslobj.getpeercert())


class EapTlsFragmentedServerFlight(EapTlsTestCase):
    """A server flight over EAP_MAX_FRAGMENT: L/M flags and one fragment per ACK."""

    @classmethod
    def server_certificate(cls):
        # A certificate with ~4 KB of SANs makes the Certificate message
        # exceed EAP_MAX_FRAGMENT (3000 bytes) and forces fragmentation.
        long_san = ", ".join("DNS:host%03d.%s.example" % (i, "x" * 180) for i in range(20))
        return cls.ca.issue("server-big", "/O=tactest/CN=localhost", server=True,
                            san="IP:127.0.0.1, IP:::1, DNS:localhost, " + long_san)

    def test_fragmented_server_flight_is_acked_per_fragment(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.handshake()
        self.assertGreater(peer.fragment_acks, 0, "server flight was not fragmented")
        self.assertEqual(peer.sslobj.version(), "TLSv1.2")


class EapTlsPeerAuthFailure(EapTlsTestCase):
    """Peer authentication failure: TLS alert first, EAP-Failure only after the peer answers."""

    def test_client_certificate_from_other_ca_gets_alert_then_failure(self):
        other_ca = tls.CA(self.__class__.__name__ + "-other-ca")
        self.addCleanup(other_ca.remove)
        cert = other_ca.issue("intruder", "/CN=cert-user")

        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=cert)
        identifier, alert = peer.handshake_until_alert()
        self.assertEqual(alert[0], 21, "expected a TLS alert record, got %r" % alert)

        # RFC 5216 2.1.3: the peer answers the alert with an empty
        # EAP-Response/EAP-TLS; only then does the server send EAP-Failure.
        reply = peer.send_eap(radius.eap_tls_ack(identifier))
        self.assertEqual(reply.code_name, "Access-Reject", reply)
        eap = radius.eap_from_reply(reply)
        self.assertEqual(len(eap), 4, eap)
        self.assertEqual(struct.unpack("!BBH", eap),
                         (radius.EAP_FAILURE, identifier, 4))


class EapTlsMissingClientCert(EapTlsTestCase):
    """verify-client = yes rejects a peer without a certificate, alert first."""

    def test_missing_client_certificate_gets_alert_then_failure(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=None)
        identifier, alert = peer.handshake_until_alert()
        self.assertEqual(alert[0], 21, "expected a TLS alert record, got %r" % alert)

        reply = peer.send_eap(radius.eap_tls_ack(identifier))
        self.assertEqual(reply.code_name, "Access-Reject", reply)
        eap = radius.eap_from_reply(reply)
        self.assertEqual(len(eap), 4, eap)
        self.assertEqual(struct.unpack("!BBH", eap),
                         (radius.EAP_FAILURE, identifier, 4))


class EapTlsFragmentedClientFlight(EapTlsTestCase):
    """A client Certificate flight over EAP_MAX_FRAGMENT: server reassembles it."""

    @classmethod
    def client_certificate(cls):
        # ~4 KB of SANs make the client Certificate message exceed
        # EAP_MAX_FRAGMENT (3000 bytes) and force client-side fragmentation.
        long_san = ", ".join("DNS:host%03d.%s.example" % (i, "x" * 180) for i in range(20))
        return cls.ca.issue("client-big", "/CN=cert-user", san=long_san)

    def test_client_fragments_are_acked_and_reassembled(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.handshake()
        self.assertGreater(peer.client_fragment_acks, 0, "client flight was not fragmented")
        self.assertEqual(peer.sslobj.version(), "TLSv1.2")
        self.assertIsNotNone(peer.sslobj.getpeercert())


class EapTlsRetransmission(EapTlsTestCase):
    """A retransmitted Access-Request gets the cached reply, not a state advance."""

    def test_retransmitted_request_gets_cached_reply(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.start()

        try:
            peer.sslobj.do_handshake()
        except ssl.SSLWantReadError:
            clienthello = peer.outgoing.read()
        else:
            raise AssertionError("client handshake finished before the server flight")
        reply = peer.send_eap(radius.eap_tls_packet(radius.EAP_RESPONSE,
                                                    peer.identifier, 0, clienthello))
        self.assertEqual(reply.code_name, "Access-Challenge", reply)

        # The exact same Access-Request (same EAP packet, identifier and
        # State) must return the same EAP bytes and State from the cache.
        request = peer.last_request
        assert request is not None
        resent = c.exchange(request, message_authenticator=True)
        self.assertEqual(resent.code_name, reply.code_name)
        self.assertEqual(radius.eap_from_reply(resent), radius.eap_from_reply(reply))
        self.assertEqual(resent.get(radius.STATE), reply.get(radius.STATE))
        # A cached replay, not a fresh TLS Start.
        self.assertFalse(radius.eap_from_reply(resent)[5] & radius.EAP_TLS_S)


class EapTlsFinalAckRetransmission(EapTlsTestCase):
    """After EAP-Success, a retransmitted final ACK gets the cached Access-Accept."""

    def test_retransmitted_final_ack_gets_cached_success(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.handshake()

        ack = peer.last_request
        assert ack is not None
        ack_eap = b"".join(v for t, v in ack.attributes if t == radius.EAP_MESSAGE)
        self.assertEqual(ack_eap[0], radius.EAP_RESPONSE)
        resent = c.exchange(ack, message_authenticator=True)
        self.assertEqual(resent.code_name, "Access-Accept", resent)
        self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(resent)),
                         (radius.EAP_SUCCESS, ack_eap[1], 4))
        self.assertFalse(resent.get(radius.STATE))


class EapTlsInvalidIdentifier(EapTlsTestCase):
    """An EAP-Response whose identifier does not match gets EAP-Failure."""

    def test_invalid_identifiers_get_eap_failure(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.start()
        state = peer.state
        self.assertTrue(state)

        for i in range(EAP_INVALID_LIMIT + 1):
            identifier = 0x80 + i
            reply = peer.send_eap_state(radius.eap_tls_ack(identifier), state)
            self.assertEqual(reply.code_name, "Access-Reject", reply)
            self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(reply)),
                             (radius.EAP_FAILURE, identifier, 4))


class EapTlsMalformedReassembly(EapTlsTestCase):
    """Malformed client-to-server fragment sequences are rejected."""

    def test_l_flag_on_non_first_fragment_is_rejected(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.start()
        state = peer.state

        first = radius.eap_tls_packet(radius.EAP_RESPONSE, peer.identifier,
                                      radius.EAP_TLS_L | radius.EAP_TLS_M,
                                      b"\x16\x03\x03" + bytes(97), total=200)
        peer.expect_fragment_ack(peer.send_eap_state(first, state))

        # L is only allowed on the first fragment (RFC 5216 2.1.5).
        second = radius.eap_tls_packet(radius.EAP_RESPONSE, peer.identifier,
                                       radius.EAP_TLS_L | radius.EAP_TLS_M,
                                       b"\x16\x03\x03" + bytes(97), total=200)
        reply = peer.send_eap_state(second, state)
        self.assertEqual(reply.code_name, "Access-Reject", reply)
        self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(reply)),
                         (radius.EAP_FAILURE, peer.identifier, 4))

    def test_announced_total_mismatch_is_rejected(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.start()

        # 50 bytes of data but L announces 100: the reassembled length does
        # not match the announced total.
        frag = radius.eap_tls_packet(radius.EAP_RESPONSE, peer.identifier,
                                     radius.EAP_TLS_L, b"\x16\x03\x03" + bytes(47), total=100)
        reply = peer.send_eap_state(frag, peer.state)
        self.assertEqual(reply.code_name, "Access-Reject", reply)
        self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(reply)),
                         (radius.EAP_FAILURE, peer.identifier, 4))
