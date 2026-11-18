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

import ssl
import struct
import unittest

from tactest import radius, tls
from tactest.daemon import features


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
