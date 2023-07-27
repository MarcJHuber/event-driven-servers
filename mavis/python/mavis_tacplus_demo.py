#!/usr/bin/python3
# $Id$
#
# mavis_tacplus_demo.py
# (C)2023 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# Customizable TACACS+ backend for testing MAVIS functionality.
#

"""
Test input for authentication:
0 TACPLUS
4 $USERNAME
8 $PASSWORD
49 AUTH
=

printf "0 TACPLUS\n4 demo\n8 demo\n49 AUTH\n=\n" | ./mavis_tacplus_demo.py

#######

Environment variables:

USERNAME
	Handled username.
	Datault: "demo"

PASSWORD
	Handled password.
	Datault: "demo"

MEMBEROF
	MEMBEROF attribute to return.
	Datault: None

TACMEMBER
	TACMEMBER attribute to return.
	Datault: None

DELAY
	Number of seconds a request will be delayed.
	Default: 0

ERROR
	If set, the script will indicate an internal processing error.
	Default: unset

FAULT
	If set, the script will exit during request processing.
	Default: unset

"""

import os, sys, re, time
from mavis import ( Mavis,
	MAVIS_DOWN, MAVIS_FINAL,
	AV_V_RESULT_OK, AV_V_RESULT_ERROR, AV_V_RESULT_FAIL,
	AV_V_RESULT_NOTFOUND
)

# A helper function to evaluate environment variables: #######################
def eval_env(var, dflt):
	globals()[var] = os.getenv(var) or dflt
	return globals()[var]


eval_env('USERNAME', 'demo')
eval_env('PASSWORD', 'demo')
eval_env('MEMBEROF', None)
eval_env('TACMEMBER', None)
eval_env('DELAY', '0')
eval_env('ERROR', None)
eval_env('FAULT', None)

while True:
	D = Mavis()

	if not D.is_tacplus():
		D.write(MAVIS_DOWN, None, None)
		continue

	if not D.valid():
		D.write(MAVIS_FINAL, AV_V_RESULT_ERROR, "Invalid input.")
		continue

	time.sleep(float(DELAY))

	if ERROR != None:
		D.write(MAVIS_FINAL, AV_V_RESULT_ERROR, None)
		continue

	if FAULT != None:
		sys.stderr.write("Pretended application fault.\n")
		sys.exit(-1)

	if D.user == USERNAME:
		if (D.is_tacplus_authc and D.password == PASSWORD) or D.is_tacplus_authz:
			if MEMBEROF != None:
				D.set_memberof(MEMBEROF)
			if TACMEMBER != None:
				D.set_tacmember(TACMEMBER)
			D.write(MAVIS_FINAL, AV_V_RESULT_OK, None)
			continue

	D.write(MAVIS_DOWN, AV_V_RESULT_NOTFOUND, None)

# EOF
