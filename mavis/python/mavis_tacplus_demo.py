#!/usr/bin/python3
# $Id$
#
# mavis_tacplus_demo.py
# (C)2023 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# Demo TACACS+ backend for libmavis_external.so
# Authenticates/authorizes user "demo" with password "demo".
#

"""
Test input for authentication:
0 TACPLUS
4 $USER
8 $PASS
49 AUTH
=

printf "0 TACPLUS\n4 $USER\n8 $PASS\n49 AUTH\n=\n" | this_script.py

"""

import os, sys, re, ldap3
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

	if D.is_tacplus_authc and D.user == "demo" and D.password == "demo":
		D.set_dbpassword(D.password)
		D.set_memberof("\"cn=Demo,dc=demo\",\"cn=Sample,dc=demo\"")
		D.set_tacmember("demogroup")
		D.write(MAVIS_FINAL, AV_V_RESULT_OK, None)
		continue

	if D.is_tacplus_authz and D.user == "demo":
		D.set_memberof("\"cn=Demo,dc=demo\",\"cn=Sample,dc=demo\"")
		D.set_tacmember("demogroup")
		D.write(MAVIS_FINAL, AV_V_RESULT_OK, None)
		continue

	D.write(MAVIS_DOWN, AV_V_RESULT_NOTFOUND, None)

# EOF
