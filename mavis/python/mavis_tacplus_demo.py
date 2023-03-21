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

import mavis
import re

while True:
	av_pairs = mavis.read()

	if av_pairs[mavis.AV_A_TYPE] != mavis.AV_V_TYPE_TACPLUS:
		mavis.write(av_pairs, mavis.MAVIS_DOWN)
		continue

	if not mavis.AV_A_USER in av_pairs:
		av_pairs[mavis.AV_A_USER_RESPONSE] = "User not set."
		av_pairs[mavis.AV_A_RESULT] = mavis.AV_V_RESULT_ERROR
		mavis.write(av_pairs, mavis.MAVIS_FINAL)
		continue

	if re.match('\(|\)|,|\||&|\*', av_pairs[mavis.AV_A_USER]):
		av_pairs[mavis.AV_A_USER_RESPONSE] = "Username not valid."
		av_pairs[mavis.AV_A_RESULT] = mavis.AV_V_RESULT_ERROR;
		mavis.write(av_pairs, mavis.MAVIS_FINAL)
		continue

	if av_pairs[mavis.AV_A_TACTYPE] == mavis.AV_V_TACTYPE_AUTH and not mavis.AV_A_PASSWORD in av_pairs:
		av_pairs[mavis.AV_A_USER_RESPONSE] = "Password not set."
		av_pairs[mavis.AV_A_RESULT] = mavis.AV_V_RESULT_ERROR;
		mavis.write(av_pairs, mavis.MAVIS_FINAL)
		continue

	if av_pairs[mavis.AV_A_TACTYPE] == mavis.AV_V_TACTYPE_AUTH and av_pairs[mavis.AV_A_USER] == "demo" and av_pairs[mavis.AV_A_PASSWORD] == "demo":
		av_pairs[mavis.AV_A_DBPASSWORD] = av_pairs[mavis.AV_A_PASSWORD]
		av_pairs[mavis.AV_A_MEMBEROF] = "\"cn=Demo,dc=demo\",\"cn=Sample,dc=demo\""
		av_pairs[mavis.AV_A_TACMEMBER] = "demogroup"
		av_pairs[mavis.AV_A_USER_RESPONSE] = "Authentication passed."
		av_pairs[mavis.AV_A_RESULT] = mavis.AV_V_RESULT_OK
		mavis.write(av_pairs, mavis.MAVIS_FINAL)
		continue

	if av_pairs[mavis.AV_A_TACTYPE] == mavis.AV_V_TACTYPE_INFO and av_pairs[mavis.AV_A_USER] == "demo":
		av_pairs[mavis.AV_A_MEMBEROF] = "\"cn=Demo,dc=demo\",\"cn=Sample,dc=demo\""
		av_pairs[mavis.AV_A_TACMEMBER] = "demogroup"
		av_pairs[mavis.AV_A_USER_RESPONSE] = "Authorization passed."
		av_pairs[mavis.AV_A_RESULT] = mavis.AV_V_RESULT_OK
		mavis.write(av_pairs, mavis.MAVIS_FINAL)
		continue

	av_pairs[mavis.AV_A_RESULT] = mavis.AV_V_RESULT_NOTFOUND
	mavis.write(av_pairs, mavis.MAVIS_DOWN)

# EOF
