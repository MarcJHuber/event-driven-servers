#!/usr/bin/python3
# $Id$
#
# mavis_tacplus_demo_database.py
# (C)2025 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# Skeleton code for implementing a database backend.
# Suitable for tac_plus-ng only.
#
# Sample configuration:

"""
#!/usr/bin/env -S /usr/local/bin/tactrace.pl --user demo --conf
#
# Sample config file for tac_plus-ng database backend

id = spawnd {
	background = no
	listen { port = 4949 }
}

id = tac_plus-ng {
	include "$CONFDIR/radius-dict.cfg"
	mavis module = external {
		exec = ../../mavis/python/mavis_tacplus-demo-database.py
	}
	user backend = mavis
	login backend = mavis
	pap password = login
	host world {
		address = 0.0.0.0/0
		mavis backend = yes
	}
}
"""

import os, sys, re, time
from mavis import ( Mavis,
	MAVIS_DOWN, MAVIS_FINAL,
	AV_V_RESULT_OK, AV_V_RESULT_ERROR, AV_V_RESULT_FAIL,
	AV_V_RESULT_NOTFOUND
)

while True:
	D = Mavis()

	if not D.is_tacplus():
		D.write(MAVIS_DOWN, None, None)
		continue

	if not D.valid():
		D.write(MAVIS_FINAL, AV_V_RESULT_ERROR, "Invalid input.")
		continue

	if D.is_tacplus_host:
		# return a profile based on device IP address, realm, cert data
# XXX Add your host lookup code here.
		D.set_tacprofile("""
{
	key = demo
	radius.key = demo
	tag = cust001,cust-ro # the "profile" rules from the user definition might use this
	welcome banner = "Hi! :-)"
	mavis backend = yes
}
""")
		D.write(MAVIS_FINAL, AV_V_RESULT_OK, None)
		continue

	if D.is_tacplus_dacl:
		# return a downloadble acl
# XXX Add your DACL lookup code here. Sample profile:
		D.set_tacprofile("""
{
	#prefix = "ip:inacl" # the default, actually
	#version = 423 # internal version number from database
	data = "
		permit ip host 1.2.3.4 host 4.5.6.7
		permit tcp any any eq 443
		deny ip any any
	"
}
""")
		D.write(MAVIS_FINAL, AV_V_RESULT_OK, None)
		continue

# XXX Add your user lookup, password checking and attributes here.
	if (D.is_tacplus_authc and D.password == "demo") or D.is_tacplus_authz:
		D.set_tacprofile("""
{
	# This demo uses a profile defined in user context. Other possibilities
	# include refering to an existing profile or using a rule set.
	#
	# Do NOT put comments here in real live, it's just wasting CPU.

	tag = cust001,ro # this will be evaluated in the profile, see below

	profile {
		script {
			if (device.tag != user.tag)
				deny
			if (aaa.protocol == tacacs) {
				if (service == shell) {
					if (cmd == "") {
						set priv-lvl = 15
						permit
					}
					if (user.tag == ro) {
						if (cmd =~ /^show /) permit
						if (cmd =~ /^ping /) permit
						if (cmd =~ /^traceroute /) permit
						deny
					}
					if (user.tag == rw)
						permit
				}
				deny
			}
			if (aaa.protocol == radius) {
				set radius[Cisco:Cisco-AVPair] = "shell:priv-lvl=15"
				set radius[Cisco:Cisco-AVPair] = "ACS:CiscoSecure-Defined-ACL=${dacl:demoacl}"
				permit
			}
			deny
		}
	}
}
""")
		D.write(MAVIS_FINAL, AV_V_RESULT_OK, None)
		continue

	D.write(MAVIS_DOWN, AV_V_RESULT_NOTFOUND, None)

# EOF
