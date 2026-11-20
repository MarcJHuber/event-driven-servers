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

import hashlib
import os
import socket
import ssl
import struct
import time
import unittest

from tactest import SOURCE, DaemonTestCase, features, radius, tls

DICTIONARY = os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")

VENDOR_SPECIFIC = 26
VID_CISCO = 9
CISCO_AVPAIR = 1
VID_MICROSOFT = 311
MS_MPPE_ENCRYPTION_POLICY = 7
MS_MPPE_ENCRYPTION_TYPES = 8
MS_MPPE_SEND_KEY = 16
MS_MPPE_RECV_KEY = 17


def cisco_avpairs(packet):
    """Cisco-AVPair values (vendor 9, sub-type 1) in a RADIUS reply."""
    values = []
    for value in packet.get(VENDOR_SPECIFIC):
        if len(value) < 8 or struct.unpack("!I", value[:4])[0] != VID_CISCO:
            continue
        p = 4
        while p + 2 <= len(value):
            sub_type, sub_len = value[p], value[p + 1]
            if sub_len < 2 or p + sub_len > len(value):
                break
            if sub_type == CISCO_AVPAIR:
                values.append(value[p + 2:p + sub_len])
            p += sub_len
    return values


def mppe_vsa_values(packet, vendor_type):
    """Values of Microsoft vendor-specific attribute 311:vendor_type.

    The vendor value of MS-MPPE keys is salt (2 bytes) plus ciphertext; the
    policy/types values are a 4-byte integer.
    """
    values = []
    for value in packet.get(VENDOR_SPECIFIC):
        if len(value) < 6 or struct.unpack("!I", value[:4])[0] != VID_MICROSOFT:
            continue
        p = 4
        while p + 2 <= len(value):
            vtype, vlen = value[p], value[p + 1]
            if vlen < 2 or p + vlen > len(value):
                break
            if vtype == vendor_type:
                values.append(value[p + 2:p + vlen])
            p += vlen
    return values


def mppe_decrypt(value, secret, request_authenticator):
    """Decrypt an MS-MPPE key attribute (RFC 2548 2.4.2).

    value is salt (2 bytes, high bit set) plus ciphertext, a multiple of 16
    bytes. b(1) = MD5(secret + Request-Authenticator + salt),
    c(1) = p(1) xor b(1); b(i) = MD5(secret + c(i-1)). The first plaintext
    byte is the key length, followed by the key and zero padding.
    Returns (key, salt).
    """
    if len(value) < 18 or (len(value) - 2) % 16:
        raise ValueError("bad MS-MPPE value length %d" % len(value))
    salt = value[:2]
    if not salt[0] & 0x80:
        raise ValueError("MS-MPPE salt high bit not set")
    ciphertext = value[2:]
    plaintext = b""
    prev = request_authenticator + salt
    for i in range(0, len(ciphertext), 16):
        digest = hashlib.md5(secret + prev).digest()
        block = bytes(a ^ b for a, b in zip(ciphertext[i:i + 16], digest))
        plaintext += block
        prev = ciphertext[i:i + 16]
    key_len = plaintext[0]
    if key_len < 1 or key_len > len(plaintext) - 1:
        raise ValueError("bad MS-MPPE key length %d" % key_len)
    if any(plaintext[1 + key_len:]):
        raise ValueError("nonzero MS-MPPE padding")
    return plaintext[1:1 + key_len], salt


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


def eap_policy(identity_source="cert-cn", verify_client="yes", dictionary="", users="", extra=""):
    """An EAP realm policy; leaves %s placeholders for server cert, key and CA.

    users adds user (and extra profile) blocks to the shared eap-profile,
    which sets a RADIUS attribute so an Access-Accept proves that the
    profile was evaluated. dictionary is prepended to the included
    dictionary, for tests that need a different type for an attribute.
    extra adds directives (timeout, max-message, max-sessions) to the
    eap block.
    """
    return """
%s\tinclude = "%s"
\teap {
\t\teap-method = tls
\t\tcert-file = %%s
\t\tkey-file = %%s
\t\tca-file = %%s
\t\tverify-client = %s
\t\teap-identity-source = %s
%s\t}
\tdevice radius-nas {
\t\taddress = 127.0.0.6
\t\tkey = tactest
\t\tradius.key = radsecret
\t}
\tprofile eap-profile {
\t\tscript {
\t\t\tset radius[Cisco:Cisco-AVPair] = "shell:priv-lvl=15"
\t\t\tpermit
\t\t}
\t}
%s""" % (dictionary, DICTIONARY, verify_client, identity_source, extra, users)


EAP_USERS = """
\tprofile eap-deny {
\t\tscript { deny }
\t}
\tprofile eap-message {
\t\tscript {
\t\t\tset radius[Reply-Message] = "welcome"
\t\t\tpermit
\t\t}
\t}
\tprofile eap-state {
\t\tscript {
\t\t\tset radius[Cisco:Cisco-AVPair] = "shell:priv-lvl=15"
\t\t\tset radius[State] = "profile-state"
\t\t\tpermit
\t\t}
\t}
\tuser cert-user {
\t\tprofile = eap-profile
\t}
\tuser deny-user {
\t\tprofile = eap-deny
\t}
\tuser message-user {
\t\tprofile = eap-message
\t}
\tuser state-user {
\t\tprofile = eap-state
\t}
\tuser mfa-user {
\t\tmfa = yes
\t}
\tuser deny-login-user {
\t\tpassword login = deny
\t}
\tuser error-login-user {
\t\tpassword login = error
\t}
\tuser mavis-login-user {
\t\tpassword login = mavis
\t}
"""

EAP_POLICY = eap_policy(users=EAP_USERS)

# The test dictionary makes State (24) a string so a profile can add it;
# the included dictionary would make rad_attr_add() skip an octets value.
EAP_STATE_DICTIONARY = """\tradius.dictionary {
\t\tattribute State 24 string
\t}
"""

EAP_STATE_POLICY = eap_policy(dictionary=EAP_STATE_DICTIONARY, users=EAP_USERS)

EAP_SAN_USERS = """
\tuser san-user {
\t\tprofile = eap-profile
\t}
\tuser cert-user {
\t\tprofile = eap-profile
\t}
"""

EAP_SAN_POLICY = eap_policy(identity_source="cert-san", users=EAP_SAN_USERS)

EAP_LAB_USERS = """
\tuser lab-user {
\t\tprofile = eap-profile
\t}
"""

EAP_LAB_POLICY = eap_policy(identity_source="eap-identity", verify_client="no", users=EAP_LAB_USERS)

# A second NAS in the same realm: EAP State must not be replayable from it.
OTHER_NAS_DEVICE = """
\tdevice other-nas {
\t\taddress = 127.0.0.7
\t\tkey = tactest
\t\tradius.key = radsecret2
\t}
"""

EAP_CLIENT_BINDING_POLICY = eap_policy(users=EAP_USERS + OTHER_NAS_DEVICE)

# A device host script that permits every user, including one without an
# account: EAP must not turn that permit into an Access-Accept.
EAP_HOST_PERMIT_POLICY = """
\tinclude = "%s"
\teap {
\t\teap-method = tls
\t\tcert-file = %%s
\t\tkey-file = %%s
\t\tca-file = %%s
\t\tverify-client = yes
\t\teap-identity-source = cert-cn
\t}
\tdevice radius-nas {
\t\taddress = 127.0.0.6
\t\tkey = tactest
\t\tradius.key = radsecret
\t\tscript { permit }
\t}
\tprofile eap-profile {
\t\tscript {
\t\t\tset radius[Cisco:Cisco-AVPair] = "shell:priv-lvl=15"
\t\t\tpermit
\t\t}
\t}
\tuser cert-user {
\t\tprofile = eap-profile
\t}
""" % DICTIONARY

# The parent realm is a lab setup (verify-client = no); the child has its
# own eap {} block and must get the method defaults, not the lab values.
EAP_CHILD_REALM_POLICY = """
\tinclude = "%s"
\teap {
\t\teap-method = tls
\t\tcert-file = %%s
\t\tkey-file = %%s
\t\tca-file = %%s
\t\tverify-client = no
\t\teap-identity-source = eap-identity
\t}
\trealm child {
\t\teap {
\t\t\teap-method = tls
\t\t}
\t\tdevice radius-nas {
\t\t\taddress = 127.0.0.6
\t\t\tkey = tactest
\t\t\tradius.key = radsecret
\t\t}
\t\tprofile eap-profile {
\t\t\tscript {
\t\t\t\tset radius[Cisco:Cisco-AVPair] = "shell:priv-lvl=15"
\t\t\t\tpermit
\t\t\t}
\t\t}
\t\tuser cert-user {
\t\t\tprofile = eap-profile
\t\t}
\t\tuser lab-user {
\t\t\tprofile = eap-profile
\t\t}
\t}
""" % DICTIONARY

# bug compatibility 32 must not waive the Message-Authenticator for EAP.
EAP_BUG_COMPAT_POLICY = """
\tinclude = "%s"
\teap {
\t\teap-method = tls
\t\tcert-file = %%s
\t\tkey-file = %%s
\t\tca-file = %%s
\t\tverify-client = yes
\t\teap-identity-source = cert-cn
\t}
\tdevice radius-nas {
\t\taddress = 127.0.0.6
\t\tkey = tactest
\t\tradius.key = radsecret
\t\tbug compatibility = 32
\t}
\tprofile eap-profile {
\t\tscript {
\t\t\tset radius[Cisco:Cisco-AVPair] = "shell:priv-lvl=15"
\t\t\tpermit
\t\t}
\t}
\tuser cert-user {
\t\tprofile = eap-profile
\t}
""" % DICTIONARY

# A DNS server that never answers keeps the reverse lookup pending.
EAP_DNS_POLICY_TEMPLATE = """
\tinclude = "%s"
\tdns servers = "127.0.0.1:%d"
\tdns reverse-lookup = yes
\tdns timeout = 1
\teap {
\t\teap-method = tls
\t\tcert-file = %%s
\t\tkey-file = %%s
\t\tca-file = %%s
\t\tverify-client = yes
\t\teap-identity-source = cert-cn
\t}
\tdevice radius-nas {
\t\taddress = 127.0.0.6
\t\tkey = tactest
\t\tradius.key = radsecret
\t}
\tprofile eap-profile {
\t\tscript {
\t\t\tset radius[Cisco:Cisco-AVPair] = "shell:priv-lvl=15"
\t\t\tpermit
\t\t}
\t}
\tuser cert-user {
\t\tprofile = eap-profile
\t}
"""


def eap_dns_policy(port):
    return EAP_DNS_POLICY_TEMPLATE % (DICTIONARY, port)


class EapTlsPeer:
    """An EAP-TLS peer over ssl.SSLObject and memory BIOs (TLS 1.2 only).

    Sends EAP-Response packets in RADIUS Access-Requests and feeds the EAP
    data of the server's EAP-Requests to the SSLObject. Server fragments are
    reassembled; each fragment with M set is ACKed with an empty
    EAP-Response/EAP-TLS (six bytes, flags 0).
    """

    def __init__(self, client, ca, identity, cert=None, versions=None, message_authenticator=True):
        self.client = client
        self.identity = identity
        self.state = None
        self.identifier = 1
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        if versions is None:
            versions = (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
        self.ctx = ca.context(cert=cert, minimum=versions[0], maximum=versions[1])
        self.message_authenticator = message_authenticator
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
        r = self.client.exchange(req, message_authenticator=self.message_authenticator)
        self.last_reply = r
        self.state = (r.get(radius.STATE) or [None])[0]
        return r

    def send_eap_state(self, eap, state):
        """Send eap with an explicit State, without touching self.state."""
        attrs = [(radius.USER_NAME, self.identity.encode())] + radius.eap_attributes(eap)
        attrs.append((radius.STATE, state))
        req = radius.Packet(radius.ACCESS_REQUEST, attributes=attrs)
        return self.client.exchange(req, message_authenticator=self.message_authenticator)

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

    def handshake_reply(self, max_rounds=10):
        """Run the client handshake and return (ACK identifier, reply to the final ACK).

        RFC 5216 2.1.3: after the server's final TLS flight the peer sends an
        empty EAP-Response/EAP-TLS ACK. The reply may be EAP-Success or
        EAP-Failure; the caller decides which one is expected.
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
            return ack_identifier, reply
        raise AssertionError("TLS handshake did not complete in %d rounds" % max_rounds)

    def handshake(self, max_rounds=10):
        """Identity -> TLS Start, then run the client handshake to EAP-Success.

        Returns the number of server TLS flights. Raises AssertionError when
        the server does not answer the final ACK with an Access-Accept
        carrying a matching 4-byte EAP-Success.
        """
        ack_identifier, reply = self.handshake_reply(max_rounds)
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

    POLICY is the EAP policy with the CA's server certificate/key and root
    certificate; client certificates are issued by the same CA.
    """

    UDP = True
    POLICY = EAP_POLICY
    TLS_TRANSPORT = False

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
            if cls.TLS_TRANSPORT:
                # TLS listener and EAP TLS both use the CA's server credentials.
                cls.CONFIG = cls.POLICY % (server[0], server[1], cls.ca.cert,
                                           server[0], server[1], cls.ca.cert)
            else:
                cls.CONFIG = cls.POLICY % (server[0], server[1], cls.ca.cert)
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

    def assert_eap_failure(self, peer):
        """The final ACK gets an Access-Reject carrying EAP-Failure and its identifier."""
        ack_identifier, reply = peer.handshake_reply()
        self.assertEqual(reply.code_name, "Access-Reject", reply)
        eap = radius.eap_from_reply(reply)
        self.assertEqual(len(eap), 4, eap)
        self.assertEqual(struct.unpack("!BBH", eap),
                         (radius.EAP_FAILURE, ack_identifier, 4))


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


class EapStart(EapTlsTestCase):
    """EAP-Start: empty EAP-Message -> Identity Challenge -> State Identity -> TLS Start."""

    def test_eap_start_identity_with_state_gets_tls_start(self):
        c = self.radius("radsecret")
        req = radius.Packet(radius.ACCESS_REQUEST, attributes=[
            (radius.USER_NAME, b"cert-user"), (radius.EAP_MESSAGE, b"")])
        r = c.exchange(req, message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Challenge", r)
        eap = radius.eap_from_reply(r)
        self.assertGreaterEqual(len(eap), 5, eap)
        self.assertEqual(eap[0], radius.EAP_REQUEST, eap)
        self.assertEqual(eap[4], radius.EAP_TYPE_IDENTITY, eap)
        identifier = eap[1]
        state = (r.get(radius.STATE) or [None])[0]
        self.assertTrue(state, "EAP-Start challenge without State")

        identity = radius.eap_packet(radius.EAP_RESPONSE, identifier,
                                     radius.EAP_TYPE_IDENTITY, b"cert-user")
        r2 = c.exchange(access_request(identity, state), message_authenticator=True)
        self.assertEqual(r2.code_name, "Access-Challenge", r2)
        reply_eap = radius.eap_from_reply(r2)
        self.assertEqual(reply_eap[0], radius.EAP_REQUEST, reply_eap)
        self.assertEqual(reply_eap[4], radius.EAP_TYPE_TLS, reply_eap)
        self.assertTrue(reply_eap[5] & radius.EAP_TLS_S, reply_eap)
        self.assertEqual(r2.get(radius.STATE), [state], "State must stay the same")


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


class EapTlsMppeKeys(EapTlsTestCase):
    """RFC 5216 2.3 / RFC 2548 2.4.2: MS-MPPE keys in a successful Access-Accept."""

    def test_access_accept_carries_encrypted_ms_mppe_keys(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.handshake()
        reply, request = peer.last_reply, peer.last_request
        assert request is not None and reply is not None
        self.assertEqual(reply.code_name, "Access-Accept", reply)

        recv_values = mppe_vsa_values(reply, MS_MPPE_RECV_KEY)
        send_values = mppe_vsa_values(reply, MS_MPPE_SEND_KEY)
        self.assertEqual(len(recv_values), 1, reply)
        self.assertEqual(len(send_values), 1, reply)

        recv_key, recv_salt = mppe_decrypt(recv_values[0], b"radsecret",
                                           request.authenticator)
        send_key, send_salt = mppe_decrypt(send_values[0], b"radsecret",
                                           request.authenticator)
        self.assertEqual(len(recv_key), 32)
        self.assertEqual(len(send_key), 32)
        self.assertNotEqual(recv_key, bytes(32))
        self.assertNotEqual(send_key, bytes(32))
        self.assertNotEqual(recv_key, send_key)
        self.assertNotEqual(recv_salt, send_salt)
        self.assertEqual(mppe_vsa_values(reply, MS_MPPE_ENCRYPTION_POLICY),
                         [struct.pack("!I", 1)])
        self.assertEqual(mppe_vsa_values(reply, MS_MPPE_ENCRYPTION_TYPES),
                         [struct.pack("!I", 6)])

    def test_retransmitted_access_request_reencrypts_keys(self):
        """A retransmission has a new Request Authenticator; the MSK is re-encrypted."""
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.handshake()
        first_request, first_reply = peer.last_request, peer.last_reply
        assert first_request is not None and first_reply is not None
        self.assertEqual(first_reply.code_name, "Access-Accept", first_reply)
        self.assertEqual(cisco_avpairs(first_reply), [b"shell:priv-lvl=15"])

        first_recv = mppe_decrypt(mppe_vsa_values(first_reply, MS_MPPE_RECV_KEY)[0],
                                  b"radsecret", first_request.authenticator)[0]

        # Same EAP packet, attributes and State, but a new Request Authenticator.
        resent_request = radius.Packet(radius.ACCESS_REQUEST,
                                       identifier=first_request.identifier,
                                       attributes=first_request.attributes)
        self.assertNotEqual(resent_request.authenticator, first_request.authenticator)
        resent = c.exchange(resent_request, message_authenticator=True)
        self.assertEqual(resent.code_name, "Access-Accept", resent)

        ack_eap = b"".join(v for t, v in first_request.attributes
                           if t == radius.EAP_MESSAGE)
        eap = radius.eap_from_reply(resent)
        self.assertEqual(len(eap), 4, eap)
        self.assertEqual(struct.unpack("!BBH", eap),
                         (radius.EAP_SUCCESS, ack_eap[1], 4))
        self.assertFalse(resent.get(radius.STATE))
        self.assertEqual(cisco_avpairs(resent), [b"shell:priv-lvl=15"],
                         "retransmitted Access-Accept lost the profile AVPs")

        recv_values = mppe_vsa_values(resent, MS_MPPE_RECV_KEY)
        send_values = mppe_vsa_values(resent, MS_MPPE_SEND_KEY)
        self.assertEqual(len(recv_values), 1, resent)
        self.assertEqual(len(send_values), 1, resent)
        recv_key, recv_salt = mppe_decrypt(recv_values[0], b"radsecret",
                                           resent_request.authenticator)
        send_key, send_salt = mppe_decrypt(send_values[0], b"radsecret",
                                           resent_request.authenticator)
        self.assertEqual(recv_key, first_recv)
        self.assertEqual(len(send_key), 32)
        self.assertNotEqual(recv_salt, send_salt)
        self.assertEqual(mppe_vsa_values(resent, MS_MPPE_ENCRYPTION_POLICY),
                         [struct.pack("!I", 1)])
        self.assertEqual(mppe_vsa_values(resent, MS_MPPE_ENCRYPTION_TYPES),
                         [struct.pack("!I", 6)])


class EapTlsFragmentedServerFlight(EapTlsTestCase):
    """A server flight over EAP_MAX_FRAGMENT: L/M flags and one fragment per ACK."""

    @classmethod
    def server_certificate(cls):
        # A certificate with ~4 KB of SANs makes the Certificate message
        # exceed EAP_MAX_FRAGMENT (3000 bytes) and forces fragmentation.
        # DNS labels are limited to 60 characters so LibreSSL's openssl
        # accepts them too.
        long_san = ", ".join("DNS:host%03d.%s.example" % (i, "x" * 60) for i in range(40))
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
        # DNS labels are limited to 60 characters so LibreSSL's openssl
        # accepts them too.
        long_san = ", ".join("DNS:host%03d.%s.example" % (i, "x" * 60) for i in range(40))
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


class EapTlsAuthorization(EapTlsTestCase):
    """The certificate identity is mapped to the existing authorization path."""

    def test_mixed_case_cert_cn_is_lowercased_and_profile_attributes_added(self):
        """CN Cert-User maps to user cert-user; the profile's Cisco-AVPair is in the Accept."""
        cert = self.ca.issue("mixed-case", "/CN=Cert-User")
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "Cert-User", cert=cert)
        peer.handshake()
        self.assertEqual(peer.last_reply.code_name, "Access-Accept", peer.last_reply)
        self.assertEqual(cisco_avpairs(peer.last_reply), [b"shell:priv-lvl=15"])

    def test_unknown_certificate_identity_is_rejected(self):
        cert = self.ca.issue("unknown", "/CN=unknown-user")
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "unknown-user", cert=cert)
        self.assert_eap_failure(peer)

    def test_profile_deny_is_rejected(self):
        cert = self.ca.issue("deny", "/CN=deny-user")
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "deny-user", cert=cert)
        self.assert_eap_failure(peer)

    def test_mfa_required_is_rejected(self):
        """MFA cannot be challenged inside EAP-TLS, so it must not be bypassed."""
        cert = self.ca.issue("mfa", "/CN=mfa-user")
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "mfa-user", cert=cert)
        self.assert_eap_failure(peer)

    def test_empty_certificate_cn_is_rejected(self):
        cert = self.ca.issue("no-cn", "/O=tactest")
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "no-cn", cert=cert)
        self.assert_eap_failure(peer)

    def test_profile_reply_message_is_stripped_from_accept(self):
        """RFC 3579 2.6.5: no Reply-Message in a packet carrying EAP-Message."""
        cert = self.ca.issue("message", "/CN=message-user")
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "message-user", cert=cert)
        peer.handshake()
        self.assertEqual(peer.last_reply.code_name, "Access-Accept", peer.last_reply)
        self.assertFalse(peer.last_reply.get(radius.REPLY_MESSAGE),
                         peer.last_reply.get(radius.REPLY_MESSAGE))
        # Removing the profile's Reply-Message must not leave its bytes in
        # the Message-Authenticator slot (RFC 3579 3.2).
        self.assertIs(peer.last_reply.message_authenticator, True,
                      "Message-Authenticator is wrong after stripping Reply-Message")


class EapTlsLoginCredentialParity(EapTlsTestCase):
    """login = deny/error and MAVIS-only login credentials are rejected."""

    def assert_login_denied(self, user):
        cert = self.ca.issue(user, "/CN=%s" % user)
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, user, cert=cert)
        self.assert_eap_failure(peer)

    def test_login_deny_is_rejected(self):
        self.assert_login_denied("deny-login-user")

    def test_login_error_is_rejected(self):
        self.assert_login_denied("error-login-user")

    def test_mavis_login_is_rejected(self):
        self.assert_login_denied("mavis-login-user")


class EapTlsProfileStateStripped(EapTlsTestCase):
    """A profile-added State must not appear in an Access-Accept (only Access-Challenge)."""

    POLICY = EAP_STATE_POLICY

    def test_profile_state_is_stripped_from_accept(self):
        cert = self.ca.issue("state", "/CN=state-user")
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "state-user", cert=cert)
        peer.handshake()
        self.assertEqual(peer.last_reply.code_name, "Access-Accept", peer.last_reply)
        # The Cisco-AVPair proves the profile ran; the State it also added is gone.
        self.assertEqual(cisco_avpairs(peer.last_reply), [b"shell:priv-lvl=15"])
        self.assertFalse(peer.last_reply.get(radius.STATE), peer.last_reply.get(radius.STATE))


class EapTlsCertSan(EapTlsTestCase):
    """eap-identity-source = cert-san uses the first DNS SAN and falls back to CN."""

    POLICY = EAP_SAN_POLICY

    def test_first_dns_san_is_used_and_cn_is_ignored(self):
        cert = self.ca.issue("san-client", "/CN=cn-user", san="DNS:san-user")
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "san-user", cert=cert)
        peer.handshake()
        self.assertEqual(peer.last_reply.code_name, "Access-Accept", peer.last_reply)
        self.assertEqual(cisco_avpairs(peer.last_reply), [b"shell:priv-lvl=15"])

    def test_no_dns_san_falls_back_to_cn(self):
        cert = self.ca.issue("san-fallback", "/CN=cert-user")
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=cert)
        peer.handshake()
        self.assertEqual(peer.last_reply.code_name, "Access-Accept", peer.last_reply)
        self.assertEqual(cisco_avpairs(peer.last_reply), [b"shell:priv-lvl=15"])


class EapTlsEapIdentityLab(EapTlsTestCase):
    """verify-client = no with eap-identity-source = eap-identity (lab mode, no client cert)."""

    POLICY = EAP_LAB_POLICY

    @classmethod
    def client_certificate(cls):
        return None

    def test_eap_identity_without_client_certificate(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "lab-user", cert=None)
        peer.handshake()
        self.assertEqual(peer.last_reply.code_name, "Access-Accept", peer.last_reply)
        self.assertEqual(cisco_avpairs(peer.last_reply), [b"shell:priv-lvl=15"])


def access_request(eap, state=None, user="cert-user"):
    """An Access-Request with an EAP-Message (and optional State) from the test NAS."""
    attrs = [(radius.USER_NAME, user.encode())] + radius.eap_attributes(eap)
    if state is not None:
        attrs.append((radius.STATE, state))
    return radius.Packet(radius.ACCESS_REQUEST, attributes=attrs)


def tls11_client_hello():
    """A ClientHello of a client that speaks TLS 1.1 at most (no supported_versions extension)."""
    body = b"\x03\x02" + os.urandom(32) + b"\x00" + b"\x00\x04\xc0\x13\x00\x2f" + b"\x01\x00"
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


EAP_SHORT_TIMEOUT_POLICY = eap_policy(users=EAP_USERS, extra="\t\ttimeout = 1\n")
EAP_SMALL_MAX_MESSAGE_POLICY = eap_policy(users=EAP_USERS, extra="\t\tmax-message = 64\n")
EAP_SMALL_MAX_SESSIONS_POLICY = eap_policy(users=EAP_USERS, extra="\t\tmax-sessions = 2\n")

# A profile that fills the reply buffer with Cisco-AVPair values: 15
# attributes of 237 bytes and one of 232 bytes are 3787 bytes of values and
# 3915 bytes encoded. That is just below the old eap_add_mppe() check
# (3915 + 178 <= 4096) but above the corrected one (3915 + 164 > 4076), so
# EAP-Success plus MS-MPPE keys no longer fit in a 4096-byte RADIUS packet.
# Reply-Message is not used because the EAP reply path strips it.
EAP_OVERSIZED_REPLY_USERS = (
    "\tprofile eap-big {\n"
    "\t\tscript {\n"
    + "".join('\t\t\tset radius[Cisco:Cisco-AVPair] = "%s"\n' % ("y" * length)
              for length in [237] * 15 + [232])
    + "\t\t\tpermit\n"
    "\t\t}\n"
    "\t}\n"
    "\tuser big-user {\n"
    "\t\tprofile = eap-big\n"
    "\t}\n"
)

EAP_OVERSIZED_REPLY_POLICY = eap_policy(users=EAP_OVERSIZED_REPLY_USERS)


def eap_tls_transport_policy(users=EAP_USERS):
    """EAP over RADIUS/TLS: a TLS listener plus the EAP realm credentials.

    The six %s placeholders are the TLS listener certificate/key/CA and the
    EAP TLS certificate/key/CA; EapTlsTestCase formats them from its CA.
    """
    return """
\tinclude = "%s"
\ttls cert-file = %%s
\ttls key-file = %%s
\ttls ca-file = %%s
\teap {
\t\teap-method = tls
\t\tcert-file = %%s
\t\tkey-file = %%s
\t\tca-file = %%s
\t\tverify-client = yes
\t\teap-identity-source = cert-cn
\t}
\tdevice radius-nas {
\t\taddress = 127.0.0.6
\t\tkey = tactest
\t\tradius.key = radsecret
\t}
\tprofile eap-profile {
\t\tscript {
\t\t\tset radius[Cisco:Cisco-AVPair] = "shell:priv-lvl=15"
\t\t\tpermit
\t\t}
\t}
%s""" % (DICTIONARY, users)


EAP_TLS_TRANSPORT_POLICY = eap_tls_transport_policy()


class EapMessageAuthenticator(EapTlsTestCase):
    """Message-Authenticator on UDP: missing or wrong is a silent discard (RFC 3579 3.2)."""

    def request(self):
        eap = radius.eap_packet(radius.EAP_RESPONSE, 1, radius.EAP_TYPE_IDENTITY, b"cert-user")
        return access_request(eap)

    def test_missing_message_authenticator_gets_no_reply(self):
        c = self.radius("radsecret", timeout=1.0)
        c.send_raw(self.request().encode("radsecret"))
        with self.assertRaises(TimeoutError):
            c.recv_raw()
        # The daemon is alive: the same request with the attribute is answered.
        r = c.exchange(self.request(), message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Challenge", r)

    def test_wrong_message_authenticator_gets_no_reply(self):
        c = self.radius("radsecret", timeout=1.0)
        c.send_raw(self.request().encode("radsecret", message_authenticator=b"\x01" * 16))
        with self.assertRaises(TimeoutError):
            c.recv_raw()
        r = c.exchange(self.request(), message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Challenge", r)


class EapState(EapTlsTestCase):
    """State handling: unknown and overlong State are rejected with EAP-Failure."""

    def test_unknown_state_is_rejected(self):
        c = self.radius("radsecret")
        eap = radius.eap_tls_ack(1)
        r = c.exchange(access_request(eap, b"\xaa" * EAP_STATE_LEN),
                       message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Reject", r)
        self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(r)),
                         (radius.EAP_FAILURE, 1, 4))

    def test_state_longer_than_eap_state_len_is_rejected(self):
        c = self.radius("radsecret")
        eap = radius.eap_tls_ack(1)
        r = c.exchange(access_request(eap, b"\xbb" * (EAP_STATE_LEN + 1)),
                       message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Reject", r)
        self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(r)),
                         (radius.EAP_FAILURE, 1, 4))


class EapExpiredState(EapTlsTestCase):
    """An expired State is rejected; the periodic handler purges it (timeout = 1)."""

    POLICY = EAP_SHORT_TIMEOUT_POLICY

    def test_expired_state_is_rejected(self):
        c = self.radius("radsecret")
        eap = radius.eap_packet(radius.EAP_RESPONSE, 1, radius.EAP_TYPE_IDENTITY, b"cert-user")
        r = c.exchange(access_request(eap), message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Challenge", r)
        identifier = radius.eap_from_reply(r)[1]
        state = (r.get(radius.STATE) or [None])[0]
        self.assertTrue(state, "Access-Challenge without State")

        time.sleep(3.0)     # timeout = 1, the periodic handler runs every 2 s

        nak = radius.eap_packet(radius.EAP_RESPONSE, identifier, radius.EAP_TYPE_NAK,
                                bytes([radius.EAP_TYPE_TLS]))
        reply = c.exchange(access_request(nak, state), message_authenticator=True)
        self.assertEqual(reply.code_name, "Access-Reject", reply)
        self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(reply)),
                         (radius.EAP_FAILURE, identifier, 4))


class EapSessionCap(EapTlsTestCase):
    """max-sessions = 2: the oldest session by last_activity is evicted."""

    POLICY = EAP_SMALL_MAX_SESSIONS_POLICY

    def identity(self, c):
        eap = radius.eap_packet(radius.EAP_RESPONSE, 1, radius.EAP_TYPE_IDENTITY, b"cert-user")
        r = c.exchange(access_request(eap), message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Challenge", r)
        return radius.eap_from_reply(r)[1], (r.get(radius.STATE) or [None])[0]

    def nak(self, c, identifier, state):
        eap = radius.eap_packet(radius.EAP_RESPONSE, identifier, radius.EAP_TYPE_NAK,
                                bytes([radius.EAP_TYPE_TLS]))
        return c.exchange(access_request(eap, state), message_authenticator=True)

    def test_oldest_session_is_evicted(self):
        c = self.radius("radsecret")
        ident1, state1 = self.identity(c)
        time.sleep(1.1)
        _, state2 = self.identity(c)
        time.sleep(1.1)
        ident3, state3 = self.identity(c)
        self.assertTrue(state1 and state2 and state3)

        # The first session is the oldest by last_activity and was evicted
        # when the third was created, even if its State sorts first.
        reply = self.nak(c, ident1, state1)
        self.assertEqual(reply.code_name, "Access-Reject", reply)
        self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(reply)),
                         (radius.EAP_FAILURE, ident1, 4))

        # The newest session is still there and answers a Nak with TLS Start.
        reply = self.nak(c, ident3, state3)
        self.assertEqual(reply.code_name, "Access-Challenge", reply)
        eap = radius.eap_from_reply(reply)
        self.assertEqual(eap[4], radius.EAP_TYPE_TLS, eap)
        self.assertTrue(eap[5] & radius.EAP_TLS_S, eap)


class EapOversizedMessage(EapTlsTestCase):
    """EAP-Message over max-message (64) is rejected before reassembly."""

    POLICY = EAP_SMALL_MAX_MESSAGE_POLICY

    def test_oversized_eap_message_is_rejected(self):
        c = self.radius("radsecret")
        eap = radius.eap_packet(radius.EAP_RESPONSE, 1, radius.EAP_TYPE_IDENTITY, b"x" * 100)
        r = c.exchange(access_request(eap), message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Reject", r)
        self.assertEqual(radius.eap_from_reply(r)[0], radius.EAP_FAILURE, r)


class EapTlsOversizedReply(EapTlsTestCase):
    """A profile that cannot fit with EAP-Success/MS-MPPE gets EAP-Failure, not Accept."""

    POLICY = EAP_OVERSIZED_REPLY_POLICY

    def test_oversized_profile_gets_reject_with_real_identifier(self):
        cert = self.ca.issue("big", "/CN=big-user")
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "big-user", cert=cert)
        ack_identifier, reply = peer.handshake_reply()
        self.assertEqual(reply.code_name, "Access-Reject", reply)
        self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(reply)),
                         (radius.EAP_FAILURE, ack_identifier, 4))
        self.assertFalse(reply.get(radius.STATE), reply.get(radius.STATE))
        self.assertFalse(reply.get(radius.REPLY_MESSAGE), reply.get(radius.REPLY_MESSAGE))
        self.assertEqual(cisco_avpairs(reply), [], "profile AVPs rode on the Access-Reject")

        # A retransmission of the final ACK must get the cached Reject, not
        # an Access-Accept that was cached before the size check.
        ack = peer.last_request
        assert ack is not None
        resent = c.exchange(ack, message_authenticator=True)
        self.assertEqual(resent.code_name, "Access-Reject", resent)
        self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(resent)),
                         (radius.EAP_FAILURE, ack_identifier, 4))
        self.assertEqual(cisco_avpairs(resent), [])


class EapProtocol(EapTlsTestCase):
    """Role reversal, Nak handling, malformed EAP lengths and retransmission."""

    def test_eap_request_from_nas_gets_nak(self):
        """RADIUS role reversal (RFC 3579 2.6.2): Nak proposing EAP-TLS."""
        c = self.radius("radsecret")
        eap = radius.eap_packet(radius.EAP_REQUEST, 7, radius.EAP_TYPE_IDENTITY, b"cert-user")
        r = c.exchange(access_request(eap), message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Reject", r)
        self.assertEqual(radius.eap_from_reply(r),
                         struct.pack("!BBH", radius.EAP_RESPONSE, 7, 6) + bytes([3, 13]))

    def test_nak_without_tls_gets_failure(self):
        c = self.radius("radsecret")
        eap = radius.eap_packet(radius.EAP_RESPONSE, 5, radius.EAP_TYPE_NAK,
                                bytes([4]))      # EAP-MD5, not TLS
        r = c.exchange(access_request(eap), message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Reject", r)
        self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(r)),
                         (radius.EAP_FAILURE, 5, 4))

    def test_malformed_eap_length_is_rejected(self):
        c = self.radius("radsecret")
        for length in (0, 1, 3, 100):
            with self.subTest(length=length):
                eap = struct.pack("!BBH", radius.EAP_RESPONSE, 1, length) + b"\x0d\x00"
                r = c.exchange(access_request(eap), message_authenticator=True)
                self.assertEqual(r.code_name, "Access-Reject", r)
                self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(r)),
                                 (radius.EAP_FAILURE, 1, 4))

    def test_trailing_padding_is_accepted(self):
        """Octets beyond the declared EAP Length are padding (RFC 5216 3.1/3.2)."""
        c = self.radius("radsecret")
        eap = radius.eap_packet(radius.EAP_RESPONSE, 1, radius.EAP_TYPE_IDENTITY, b"alice")
        eap += b"\xff\x00"           # declared length 10, two padding bytes
        r = c.exchange(access_request(eap), message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Challenge", r)
        reply = radius.eap_from_reply(r)
        self.assertEqual(reply[0], radius.EAP_REQUEST, reply)
        self.assertEqual(reply[4], radius.EAP_TYPE_TLS, reply)
        self.assertTrue(reply[5] & radius.EAP_TLS_S, reply)
        self.assertTrue(r.get(radius.STATE), "Access-Challenge without State")

    def test_eap_tls_response_with_s_bit_is_rejected(self):
        """RFC 5216 3.2: the S bit MUST NOT be set in an EAP-Response."""
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.start()
        eap = radius.eap_tls_packet(radius.EAP_RESPONSE, peer.identifier, radius.EAP_TLS_S)
        reply = peer.send_eap_state(eap, peer.state)
        self.assertEqual(reply.code_name, "Access-Reject", reply)
        self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(reply)),
                         (radius.EAP_FAILURE, peer.identifier, 4))

    def test_reserved_bits_are_ignored(self):
        """Reserved bits are ignored on receive; the TLS data is processed."""
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.start()
        try:
            peer.sslobj.do_handshake()
        except ssl.SSLWantReadError:
            clienthello = peer.outgoing.read()
        else:
            raise AssertionError("client handshake finished before the server flight")
        eap = radius.eap_tls_packet(radius.EAP_RESPONSE, peer.identifier, 0x01, clienthello)
        reply = peer.send_eap(eap)
        self.assertEqual(reply.code_name, "Access-Challenge", reply)
        _, _, data, _ = peer.parse_request(radius.eap_from_reply(reply))
        self.assertTrue(data, "server sent no TLS data")
        self.assertEqual(data[0], 22, "expected a TLS handshake record, got %r" % data[:8])

    def test_initial_identity_retransmission_gets_fresh_challenge(self):
        """A repeated no-State Identity creates a new session with a new State."""
        c = self.radius("radsecret")
        eap = radius.eap_packet(radius.EAP_RESPONSE, 1, radius.EAP_TYPE_IDENTITY, b"cert-user")
        request = access_request(eap)
        first = c.exchange(request, message_authenticator=True)
        second = c.exchange(request, message_authenticator=True)
        for reply in (first, second):
            self.assertEqual(reply.code_name, "Access-Challenge", reply)
            reply_eap = radius.eap_from_reply(reply)
            self.assertEqual(reply_eap[0], radius.EAP_REQUEST, reply_eap)
            self.assertEqual(reply_eap[4], radius.EAP_TYPE_TLS, reply_eap)
            self.assertTrue(reply_eap[5] & radius.EAP_TLS_S, reply_eap)
            self.assertEqual(len(reply.get(radius.STATE)[0]), EAP_STATE_LEN)
        self.assertNotEqual(first.get(radius.STATE), second.get(radius.STATE),
                            "retransmitted Identity reused the old session")


class EapTlsFragmentConformance(EapTlsTestCase):
    """RFC 5216 2.1.5: the first fragment of a fragmented TLS message needs L."""

    def test_first_fragment_with_m_and_without_l_is_rejected(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.start()
        fragment = radius.eap_tls_packet(radius.EAP_RESPONSE, peer.identifier,
                                         radius.EAP_TLS_M, b"\x16\x03\x03" + bytes(97))
        reply = peer.send_eap_state(fragment, peer.state)
        self.assertEqual(reply.code_name, "Access-Reject", reply)
        self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(reply)),
                         (radius.EAP_FAILURE, peer.identifier, 4))


class EapTlsProfile(EapTlsTestCase):
    """The server pins TLS 1.2: TLS 1.0/1.1 and TLS 1.3-only clients fail."""

    def answer_alert(self, reply, peer):
        """If the server sent its TLS alert in a Challenge, answer it with the final ACK."""
        if reply.code_name != "Access-Challenge":
            return reply
        identifier, _, data, _ = peer.parse_request(radius.eap_from_reply(reply))
        self.assertTrue(data and data[0] == 21, "expected a TLS alert, got %r" % data[:8])
        return peer.send_eap(radius.eap_tls_ack(identifier))

    def test_tls11_only_client_is_rejected(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.start()
        reply = peer.send_eap(radius.eap_tls_packet(radius.EAP_RESPONSE, peer.identifier,
                                                    0, tls11_client_hello()))
        reply = self.answer_alert(reply, peer)
        self.assertEqual(reply.code_name, "Access-Reject", reply)
        self.assertEqual(radius.eap_from_reply(reply)[0], radius.EAP_FAILURE, reply)

    def test_tls13_only_client_is_rejected(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert,
                          versions=(ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3))
        peer.start()
        try:
            peer.sslobj.do_handshake()
        except ssl.SSLWantReadError:
            clienthello = peer.outgoing.read()
        else:
            raise AssertionError("TLS 1.3-only client handshake completed")
        self.assertTrue(clienthello, "client sent no ClientHello")
        reply = peer.send_eap(radius.eap_tls_packet(radius.EAP_RESPONSE, peer.identifier,
                                                    0, clienthello))
        reply = self.answer_alert(reply, peer)
        self.assertEqual(reply.code_name, "Access-Reject", reply)
        self.assertEqual(radius.eap_from_reply(reply)[0], radius.EAP_FAILURE, reply)


class EapPeerServerAuthFailure(EapTlsTestCase):
    """A peer-reported server-authentication failure gets EAP-Failure immediately."""

    def test_peer_reported_server_authentication_failure_gets_immediate_failure(self):
        other_ca = tls.CA(self.__class__.__name__ + "-other-ca")
        self.addCleanup(other_ca.remove)

        c = self.radius("radsecret")
        peer = EapTlsPeer(c, other_ca, "cert-user", cert=self.client_cert)
        peer.start()
        try:
            peer.sslobj.do_handshake()
        except ssl.SSLWantReadError:
            clienthello = peer.outgoing.read()
        else:
            raise AssertionError("client handshake finished before the server flight")

        reply = peer.send_eap(radius.eap_tls_packet(radius.EAP_RESPONSE, peer.identifier,
                                                    0, clienthello))
        _, data = peer.receive_request(reply)
        peer.incoming.write(data)
        with self.assertRaises(ssl.SSLCertVerificationError):
            peer.sslobj.do_handshake()
        alert = peer.outgoing.read()
        self.assertTrue(alert, "client sent no TLS alert")
        self.assertEqual(alert[0], 21, alert[:8])

        # RFC 5216 2.1.3: answer the peer's alert with EAP-Failure, not
        # another alert in an Access-Challenge.
        reply = peer.send_eap(radius.eap_tls_packet(radius.EAP_RESPONSE, peer.identifier,
                                                    0, alert))
        self.assertEqual(reply.code_name, "Access-Reject", reply)
        self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(reply)),
                         (radius.EAP_FAILURE, peer.identifier, 4))


class EapUdpSingleProcess(EapTlsTestCase):
    """UDP EAP with spawnd's single process mode (local state, no broker)."""

    SPAWND = "\tsingle process = yes\n"

    def test_udp_handshake_with_single_process(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.handshake()
        self.assertEqual(peer.sslobj.version(), "TLSv1.2")


class EapUdpMultiWorker(EapTlsTestCase):
    """UDP EAP with multiple spawnd workers: the connected DGRAM socket keeps
    each source flow on one worker, so no broker is needed."""

    SPAWND = "\tspawn { instances min = 4 instances max = 4 }\n"

    def test_udp_handshake_with_four_workers(self):
        daemon = self.daemon
        assert daemon is not None
        self.assertGreaterEqual(len(daemon.workers()), 4)
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.handshake()
        reply = peer.last_reply
        assert reply is not None
        self.assertEqual(reply.code_name, "Access-Accept", reply)


class EapTcpTransport(EapTlsTestCase):
    """RADIUS/TCP (RFC 6613) EAP uses local state and completes the handshake."""

    def test_radius_over_tcp_completes_handshake(self):
        c = self.radius("radsecret", tcp=True)
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.handshake()
        self.assertEqual(peer.last_reply.code_name, "Access-Accept", peer.last_reply)
        self.assertIs(peer.last_reply.message_authenticator, True)


class EapTlsTransport(EapTlsTestCase):
    """RADIUS/TLS (RFC 6614) EAP uses local state; absent Message-Authenticator is accepted."""

    LISTEN = {"tls": "tls = yes"}
    UDP = False
    TLS_TRANSPORT = True
    POLICY = EAP_TLS_TRANSPORT_POLICY

    def radsec(self):
        return self.radius("radsec", listener="tls", tls=self.ca.context(self.client_cert))

    def test_radius_over_tls_completes_handshake(self):
        c = self.radsec()
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.handshake()
        self.assertEqual(peer.last_reply.code_name, "Access-Accept", peer.last_reply)
        self.assertIs(peer.last_reply.message_authenticator, True)

    def test_missing_message_authenticator_over_tls_is_accepted(self):
        """RFC 6614 relaxes RFC 3579: no Message-Authenticator in the request is fine."""
        c = self.radsec()
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert,
                          message_authenticator=False)
        peer.handshake()
        self.assertEqual(peer.last_reply.code_name, "Access-Accept", peer.last_reply)
        self.assertIs(peer.last_reply.message_authenticator, True,
                      "replies over RADIUS/TLS must carry a Message-Authenticator")


class EapClientBinding(EapTlsTestCase):
    """RFC 4962 3: an EAP State belongs to the RADIUS client that created it."""

    POLICY = EAP_CLIENT_BINDING_POLICY

    def start_session(self, c):
        eap = radius.eap_packet(radius.EAP_RESPONSE, 1, radius.EAP_TYPE_IDENTITY, b"cert-user")
        r = c.exchange(access_request(eap), message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Challenge", r)
        return radius.eap_from_reply(r)[1], (r.get(radius.STATE) or [None])[0]

    def assert_failure(self, reply, identifier):
        self.assertEqual(reply.code_name, "Access-Reject", reply)
        self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(reply)),
                         (radius.EAP_FAILURE, identifier, 4))

    def test_state_from_another_nas_is_rejected(self):
        c = self.radius("radsecret")
        identifier, state = self.start_session(c)
        self.assertTrue(state)
        other = self.radius("radsecret2", source="127.0.0.7")
        reply = other.exchange(access_request(radius.eap_tls_ack(identifier), state),
                               message_authenticator=True)
        self.assert_failure(reply, identifier)

    def test_state_from_another_transport_is_rejected(self):
        c = self.radius("radsecret")
        identifier, state = self.start_session(c)
        self.assertTrue(state)
        tcp = self.radius("radsecret", tcp=True)
        reply = tcp.exchange(access_request(radius.eap_tls_ack(identifier), state),
                             message_authenticator=True)
        self.assert_failure(reply, identifier)


class EapCompletedGrace(EapTlsTestCase):
    """A completed EAP session lives for EAP_COMPLETED_GRACE, not eap_timeout."""

    POLICY = EAP_SHORT_TIMEOUT_POLICY

    def test_completed_session_answers_retransmission_after_timeout(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.handshake()
        ack = peer.last_request
        self.assertIsNotNone(ack)
        time.sleep(3.0)     # eap_timeout = 1
        resent = c.exchange(ack, message_authenticator=True)
        self.assertEqual(resent.code_name, "Access-Accept", resent)
        eap = radius.eap_from_reply(resent)
        self.assertEqual(len(eap), 4, eap)
        self.assertEqual(eap[0], radius.EAP_SUCCESS, eap)


class EapHostPermitNoUser(EapTlsTestCase):
    """A host script permit must not authorize an EAP identity without a user."""

    POLICY = EAP_HOST_PERMIT_POLICY

    def test_host_permit_without_user_account_is_rejected(self):
        cert = self.ca.issue("unknown", "/CN=unknown-user")
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "unknown-user", cert=cert)
        self.assert_eap_failure(peer)

    def test_host_permit_with_user_account_is_accepted(self):
        c = self.radius("radsecret")
        peer = EapTlsPeer(c, self.ca, "cert-user", cert=self.client_cert)
        peer.handshake()
        self.assertEqual(peer.last_reply.code_name, "Access-Accept", peer.last_reply)


class EapChildRealmEapBlock(EapTlsTestCase):
    """A child realm with its own eap {} block does not inherit lab settings."""

    POLICY = EAP_CHILD_REALM_POLICY
    LISTEN = {"eap": "protocol = UDP realm = child"}

    def radius_child(self):
        return self.radius("radsecret", listener="eap")

    def test_child_block_defaults_to_cert_cn(self):
        cert = self.ca.issue("child-cert", "/CN=cert-user")
        c = self.radius_child()
        peer = EapTlsPeer(c, self.ca, "other-user", cert=cert)
        peer.handshake()
        self.assertEqual(peer.last_reply.code_name, "Access-Accept", peer.last_reply)
        self.assertEqual(cisco_avpairs(peer.last_reply), [b"shell:priv-lvl=15"])

    def test_child_block_defaults_to_verify_client(self):
        c = self.radius_child()
        peer = EapTlsPeer(c, self.ca, "lab-user", cert=None)
        identifier, alert = peer.handshake_until_alert()
        self.assertEqual(alert[0], 21, alert[:8])
        reply = peer.send_eap(radius.eap_tls_ack(identifier))
        self.assertEqual(reply.code_name, "Access-Reject", reply)
        self.assertEqual(struct.unpack("!BBH", radius.eap_from_reply(reply)),
                         (radius.EAP_FAILURE, identifier, 4))


class EapMessageAuthenticatorBugCompat(EapTlsTestCase):
    """Bug compatibility 32 must not accept EAP without Message-Authenticator."""

    POLICY = EAP_BUG_COMPAT_POLICY

    def request(self):
        eap = radius.eap_packet(radius.EAP_RESPONSE, 1, radius.EAP_TYPE_IDENTITY, b"cert-user")
        return access_request(eap)

    def test_missing_ma_with_bug_compatibility_is_dropped_over_udp(self):
        c = self.radius("radsecret", timeout=1.0)
        c.send_raw(self.request().encode("radsecret"))
        with self.assertRaises(TimeoutError):
            c.recv_raw()
        r = c.exchange(self.request(), message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Challenge", r)

    def test_missing_ma_with_bug_compatibility_is_dropped_over_tcp(self):
        c = self.radius("radsecret", tcp=True, timeout=1.0)
        c.send_raw(self.request().encode("radsecret"))
        with self.assertRaises(ConnectionError):
            c.recv_raw()
        r = self.radius("radsecret", tcp=True).exchange(self.request(), message_authenticator=True)
        self.assertEqual(r.code_name, "Access-Challenge", r)


class EapDnsResumeUseAfterFree(EapTlsTestCase):
    """A PAP session waiting on reverse DNS must not resume after EAP replaced it."""

    CONFIG = None

    @unittest.skipUnless("ares" in features(), "the reverse lookup needs a build with c-ares")
    def test_eap_replacement_cancels_pending_resume_timer(self):
        dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_socket.bind(("127.0.0.1", 0))
        self.addCleanup(dns_socket.close)
        body = eap_dns_policy(dns_socket.getsockname()[1]) % (
            self.ca.server[0], self.ca.server[1], self.ca.cert)
        d = self.start_daemon(body, name="eap-dns-uaf")
        c = self.radius("radsecret", daemon=d, tcp=True, timeout=2.0)

        # PAP request with Calling-Station-Id: the NAC reverse lookup stays
        # pending, so rad_authen() schedules resume_session().
        pap = radius.Packet(radius.ACCESS_REQUEST, identifier=7)
        pap.attributes = [
            (radius.USER_NAME, b"cert-user"),
            (radius.USER_PASSWORD, radius.encrypt_password(b"pw", b"radsecret", pap.authenticator)),
            (31, b"127.0.0.9"),     # Calling-Station-Id
        ]
        c.send_raw(pap.encode(b"radsecret", message_authenticator=True))

        # The EAP request with the same RADIUS identifier replaces the PAP
        # session; cleanup_session_internal() must cancel its resume timer.
        eap = radius.eap_packet(radius.EAP_RESPONSE, 7, radius.EAP_TYPE_IDENTITY, b"cert-user")
        req = radius.Packet(radius.ACCESS_REQUEST, identifier=7,
                            attributes=[(radius.USER_NAME, b"cert-user")] + radius.eap_attributes(eap))
        reply = c.exchange(req, message_authenticator=True)
        self.assertEqual(reply.code_name, "Access-Challenge", reply)

        # dns timeout = 1: a stale timer would fire (and read the freed
        # session) well within this wait.
        time.sleep(2.5)
        again = self.radius("radsecret", daemon=d, tcp=True).exchange(
            req, message_authenticator=True)
        self.assertEqual(again.code_name, "Access-Challenge", again)
