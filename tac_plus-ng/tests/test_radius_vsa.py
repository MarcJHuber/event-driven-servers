"""RADIUS: vendor-specific attributes of a dictionary with "format = <type bytes>, <length bytes>".

RFC 2865 5.26 recommends 1 byte type and 1 byte length for the
sub-attributes of a VSA. A dictionary can declare another format, for
example "format = 4, 0" (4 bytes type, no length field: the sub-attribute
fills the rest of the VSA) or "format = 2, 1".

The daemon walked every VSA as 1 byte type plus 1 byte length. It dropped
a request with a sub-attribute in any other format, radius[...] conditions
on such a sub-attribute never matched, and the attribute dump (${args},
${rargs}) lost sub-attributes or showed bytes from outside the VSA.
"""

import os
import struct
import unittest

from tactest import SOURCE, DaemonTestCase, radius

DICTIONARY = os.path.join(SOURCE, "tac_plus-ng", "sample", "radius-dict.cfg")
SECRET = "radsecret"
NAS = "127.0.0.6"

VENDOR_SPECIFIC = 26
VID_WIDE = 64999            # format = 4, 0
VID_SHORT = 64998           # format = 2, 1
VID_BIG = 256               # format = 4, 1; the old dump read the vendor id byte 0x01 as a length
VID_JUNIPER = 2636          # no format: 1 byte type, 1 byte length
VID_UNKNOWN = 64997         # no dictionary

POLICY = """
	include = "@DICTIONARY@"
	radius.dictionary Wide @VID_WIDE@ format = 4, 0 {
		attribute Wide-Role		70000	string
		attribute Wide-Reply		70001	string
	}
	radius.dictionary Short @VID_SHORT@ format = 2, 1 {
		attribute Short-Role		300	string
		attribute Short-Group		301	string
		attribute Short-Reply		302	string
	}
	radius.dictionary Big @VID_BIG@ format = 4, 1 {
		attribute Big-Count		70000	integer
	}
	log radargs {
		destination = "$tmp/radargs.log"
		radius.access format = "ARGS $${args}"
	}
	log radrargs {
		destination = "$tmp/radrargs.log"
		radius.access format = "RARGS $${rargs}"
	}
	radius.access log = radargs
	radius.access log = radrargs
	device radius-nas {
		address = @NAS@
		key = tactest
		radius.key = @SECRET@
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile admin {
		script {
			if (radius[Wide:Wide-Role] =~ "^ops$$") { set radius[Reply-Message] = "wide ops" }
			if (radius[Short:Short-Group] =~ "^ops$$") { set radius[Reply-Message] = "short ops" }
			if (radius[Juniper:Juniper-Local-User-Name] =~ "^ops$$") { set radius[Reply-Message] = "juniper ops" }
			set radius[Wide:Wide-Reply] = "w"
			set radius[Short:Short-Reply] = "s"
			set radius[Big:Big-Count] = 1
			permit
		}
	}
	ruleset {
		rule { script { profile = admin permit } }
	}
"""
for key, value in (("DICTIONARY", DICTIONARY), ("VID_WIDE", VID_WIDE), ("VID_SHORT", VID_SHORT),
                   ("VID_BIG", VID_BIG), ("NAS", NAS), ("SECRET", SECRET)):
    POLICY = POLICY.replace("@" + key + "@", str(value))


def vsa(vendor_id, payload):
    """A Vendor-Specific attribute: the vendor id, then the sub-attributes as given."""
    return (VENDOR_SPECIFIC, struct.pack("!I", vendor_id) + payload)


class VendorFormat(DaemonTestCase):
    CONFIG = POLICY
    UDP = True

    def login(self, *attributes, timeout=5.0):
        c = self.radius(SECRET, source=NAS, timeout=timeout)
        return c.access_request("alice", "alicepw", message_authenticator=True, attributes=attributes)

    def assert_dropped(self, *attributes):
        with self.assertRaises(TimeoutError):
            self.login(*attributes, timeout=2.0)

    def wait_new_log(self, name, text, offset):
        """The harness baseline does not cover the logs of this policy: read from offset."""
        return self.daemon.wait_log(name, text, offset=offset)

    def test_format_4_0_sub_attribute_matches(self):
        offset = self.daemon.log_size("radargs")
        r = self.login(vsa(VID_WIDE, struct.pack("!I", 70000) + b"ops"))
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(r.get(radius.REPLY_MESSAGE), [b"wide ops"])
        self.wait_new_log("radargs", "Wide:Wide-Role=ops", offset)

    def test_format_2_1_sub_attribute_matches(self):
        offset = self.daemon.log_size("radargs")
        r = self.login(vsa(VID_SHORT, struct.pack("!HB", 301, 6) + b"ops"))
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(r.get(radius.REPLY_MESSAGE), [b"short ops"])
        self.wait_new_log("radargs", "Short:Short-Group=ops", offset)

    def test_format_2_1_second_sub_attribute_in_one_vsa_matches(self):
        offset = self.daemon.log_size("radargs")
        r = self.login(vsa(VID_SHORT, struct.pack("!HB", 300, 8) + b"admin" + struct.pack("!HB", 301, 6) + b"ops"))
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(r.get(radius.REPLY_MESSAGE), [b"short ops"])
        self.wait_new_log("radargs", "Short:Short-Role=admin Short:Short-Group=ops", offset)

    def test_format_1_1_sub_attribute_still_matches(self):
        """Control: a vendor without a format keeps the RFC 2865 layout."""
        r = self.login(vsa(VID_JUNIPER, bytes([1, 5]) + b"ops"))
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertEqual(r.get(radius.REPLY_MESSAGE), [b"juniper ops"])

    def test_format_1_1_vsa_with_two_sub_attributes_is_dumped(self):
        """The dump read the length of the next sub-attribute from the VSA header, not from the sub-attribute."""
        offset = self.daemon.log_size("radargs")
        r = self.login(vsa(VID_JUNIPER, bytes([1, 5]) + b"ops" + bytes([2, 6]) + b"show"))
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.wait_new_log("radargs", "Juniper:Juniper-Local-User-Name=ops Juniper:Juniper-Allow-Commands=show", offset)

    def test_format_4_1_reply_sub_attribute_is_dumped_once(self):
        """The dump took a vendor id byte as a length and dumped bytes from after the VSA."""
        offset = self.daemon.log_size("radrargs")
        r = self.login()
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertIn(struct.pack("!I", VID_BIG) + struct.pack("!IBI", 70000, 9, 1), r.get(VENDOR_SPECIFIC))
        text = self.wait_new_log("radrargs", "Big:Big-Count=1", offset)
        self.assertEqual(text.count("Big:"), 1, text)

    def test_reply_sub_attributes_use_the_vendor_format(self):
        """Control: the reply builder already honored the format."""
        r = self.login()
        self.assertEqual(r.code_name, "Access-Accept", r)
        vsas = r.get(VENDOR_SPECIFIC)
        self.assertIn(struct.pack("!I", VID_WIDE) + struct.pack("!I", 70001) + b"w", vsas)
        self.assertIn(struct.pack("!I", VID_SHORT) + struct.pack("!HB", 302, 4) + b"s", vsas)

    def test_malformed_format_4_0_sub_attribute_is_dropped(self):
        """Two bytes are valid as 1+1, but shorter than the 4 bytes type of the vendor."""
        self.assert_dropped(vsa(VID_WIDE, bytes([1, 2])))

    def test_malformed_format_2_1_sub_attribute_is_dropped(self):
        """Valid as 1+1, but as 2+1 the first sub-attribute has a length of 0, below its header."""
        self.assert_dropped(vsa(VID_SHORT, bytes([1, 3, 0, 0, 2])))

    def test_format_2_1_sub_attribute_overrunning_the_vsa_is_dropped(self):
        self.assert_dropped(vsa(VID_SHORT, struct.pack("!HB", 301, 7) + b"ops"))

    def test_vsa_of_a_vendor_without_a_dictionary_is_ignored(self):
        """RFC 2865 5.26: a server MUST ignore vendor-specific information that it cannot interpret."""
        r = self.login(vsa(VID_UNKNOWN, bytes([1, 0, 0, 2])))
        self.assertEqual(r.code_name, "Access-Accept", r)


CISCO_POLICY = """
	include = "@DICTIONARY@"
	radius.dictionary Cisco 9 format = 1, 0 { }
	dacl demoacl { data = "permit ip any any" }
	device radius-nas {
		address = @NAS@
		key = tactest
		radius.key = @SECRET@
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	profile admin { script { if (aaa.protocol == radius) permit } }
	ruleset { rule { script { profile = admin permit } } }
"""
for key, value in (("DICTIONARY", DICTIONARY), ("NAS", NAS), ("SECRET", SECRET)):
    CISCO_POLICY = CISCO_POLICY.replace("@" + key + "@", str(value))


class CiscoFormat(DaemonTestCase):
    """rad_check_dacl() walked Cisco VSAs as 1+1 after the validator had checked them in the dictionary format."""

    CONFIG = CISCO_POLICY
    UDP = True

    def test_dacl_marker_outside_the_vsa_is_not_a_dacl_request(self):
        # As 1+1, the value byte 24 is a length: the walker reads type "a", length "a" (97) and the value.
        marker = b"a:event=acl-download" + bytes(75)
        c = self.radius(SECRET, source=NAS)
        r = c.access_request("alice", "alicepw", message_authenticator=True,
                             attributes=[vsa(9, bytes([1, 24])), (0x61, marker)])
        self.assertEqual(r.code_name, "Access-Accept", r)

    def test_dacl_marker_in_the_cisco_format_is_a_dacl_request(self):
        """Positive control: the device downloads the ACL of the user name #ACSACL#<name>-<version>."""
        c = self.radius(SECRET, source=NAS)
        r = c.access_request("#ACSACL#demoacl-00000000", "", message_authenticator=True,
                             attributes=[vsa(9, bytes([1]) + b"aaa:event=acl-download")])
        self.assertEqual(r.code_name, "Access-Accept", r)
        self.assertIn(b"ip:inacl#1=permit ip any any", b"".join(r.get(VENDOR_SPECIFIC)), r)


if __name__ == "__main__":
    unittest.main()
