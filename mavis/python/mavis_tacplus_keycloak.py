#!/usr/bin/python3
#
# mavis_tacplus_keycloak.py
#
# TACACS+ NG backend for libmavis_external.so
# Authenticates against Keycloak using Resource Owner Password Credentials
# (ROPC) grant and maps Keycloak group memberships to TACACS+ groups.
# Password changes are not supported.
#
# Keycloak client setup:
#   - Create a client with "Direct Access Grants" (ROPC) enabled
#   - Add a "Group Membership" protocol mapper to include groups in the token:
#     Client > Client scopes > dedicated scope > Add mapper > By type >
#     "Group Membership" (set Token Claim Name to "groups", Full group path OFF)
#

"""
Test input for authentication:
0 TACPLUS
4 $USER
8 $PASS
49 AUTH
=

printf "0 TACPLUS\\n4 user\\n8 pass\\n49 AUTH\\n=\\n" | \\
  KEYCLOAK_URL=https://keycloak.example.com \\
  KEYCLOAK_REALM=myrealm \\
  KEYCLOAK_CLIENT_ID=tacacs \\
  python3 mavis_tacplus_keycloak.py

#######

Environment variables:

KEYCLOAK_URL
	Base URL of the Keycloak server.
	Example: "https://keycloak.example.com"

KEYCLOAK_REALM
	Keycloak realm name.
	Default: "master"

KEYCLOAK_CLIENT_ID
	Client ID. The client must have Direct Access Grants (ROPC) enabled.
	Default: "tacacs"

KEYCLOAK_CLIENT_SECRET
	Client secret. Required for confidential clients, omit for public clients.
	Default: unset

KEYCLOAK_VERIFY_TLS
	Set to "0" to disable TLS certificate verification.
	Default: "1" (verify)

KEYCLOAK_TIMEOUT
	HTTP request timeout in seconds.
	Default: 5

KEYCLOAK_GROUP_CLAIM
	JWT claim name containing group memberships. Must match the Token Claim
	Name configured in the Keycloak "Group Membership" protocol mapper.
	Default: "groups"

KEYCLOAK_REQUIRE_GROUP
	If set, authentication will fail unless the user is a member of this
	group. Useful to restrict TACACS+ access to a specific Keycloak group.
	Default: unset (no restriction)
"""

import os, sys, json, base64
import requests
from mavis import (Mavis,
	MAVIS_DOWN, MAVIS_FINAL,
	AV_V_RESULT_OK, AV_V_RESULT_ERROR, AV_V_RESULT_FAIL,
	AV_V_RESULT_NOTFOUND,
	AV_A_TYPE, AV_V_TYPE_TACPLUS, AV_A_IDENTITY_SOURCE
)

# Environment variable helpers ################################################
def env(var, default=None):
	return os.getenv(var) or default

KEYCLOAK_URL       = env('KEYCLOAK_URL')
KEYCLOAK_REALM     = env('KEYCLOAK_REALM', 'master')
KEYCLOAK_CLIENT_ID = env('KEYCLOAK_CLIENT_ID', 'tacacs')
KEYCLOAK_CLIENT_SECRET = env('KEYCLOAK_CLIENT_SECRET')
KEYCLOAK_VERIFY_TLS    = env('KEYCLOAK_VERIFY_TLS', '1') != '0'
KEYCLOAK_TIMEOUT       = int(env('KEYCLOAK_TIMEOUT', '5'))
KEYCLOAK_GROUP_CLAIM   = env('KEYCLOAK_GROUP_CLAIM', 'groups')
KEYCLOAK_REQUIRE_GROUP = env('KEYCLOAK_REQUIRE_GROUP')

if not KEYCLOAK_URL:
	raise RuntimeError(
		"KEYCLOAK_URL is required. Set it via 'setenv KEYCLOAK_URL = https://...' "
		"in the mavis module configuration.")

TOKEN_URL = (KEYCLOAK_URL.rstrip('/')
	+ '/realms/' + KEYCLOAK_REALM
	+ '/protocol/openid-connect/token')

print("mavis_tacplus_keycloak: ROPC endpoint " + TOKEN_URL, file=sys.stderr)

# Reusable HTTP session ########################################################
http = requests.Session()
http.verify = KEYCLOAK_VERIFY_TLS

# JWT helpers ##################################################################
def decode_jwt_payload(token):
	"""Decode the payload of a JWT without signature verification."""
	parts = token.split('.')
	if len(parts) != 3:
		raise ValueError("Malformed JWT: expected three dot-separated parts, got " + str(len(parts)))
	payload = parts[1]
	padding = 4 - len(payload) % 4
	if padding != 4:
		payload += '=' * padding
	return json.loads(base64.urlsafe_b64decode(payload))

def decode_token_claims(token_data):
	"""Decode access token JWT and return claims dict, or None on failure."""
	try:
		return decode_jwt_payload(token_data['access_token'])
	except Exception as e:
		print("mavis_tacplus_keycloak: failed to decode JWT: " + str(e), file=sys.stderr)
		return None

def extract_groups(claims):
	"""Extract group names from decoded JWT claims."""
	if claims is None:
		return []
	groups = claims.get(KEYCLOAK_GROUP_CLAIM, [])
	# Keycloak may return full paths like "/admin" — strip leading slash
	return [g.lstrip('/') for g in groups if g]

# Main loop ####################################################################
while True:
	D = Mavis()

	if D.av_pairs.get(AV_A_TYPE) != AV_V_TYPE_TACPLUS:
		D.write(MAVIS_DOWN, None, None)
		continue

	if not D.valid():
		continue

	# We only handle authentication — pass authorization/host/dacl down
	if not D.is_tacplus_authc:
		D.write(MAVIS_DOWN, AV_V_RESULT_NOTFOUND, None)
		continue

	# Password changes are not supported
	if D.is_tacplus_chpw:
		D.write(MAVIS_FINAL, AV_V_RESULT_FAIL,
			"Password change is not supported via Keycloak ROPC.")
		continue

	# Authenticate via ROPC ####################################################
	post_data = {
		'grant_type': 'password',
		'client_id': KEYCLOAK_CLIENT_ID,
		'username': D.user,
		'password': D.password,
	}
	if KEYCLOAK_CLIENT_SECRET:
		post_data['client_secret'] = KEYCLOAK_CLIENT_SECRET

	try:
		resp = http.post(TOKEN_URL, data=post_data, timeout=KEYCLOAK_TIMEOUT)
	except Exception as e:
		print("mavis_tacplus_keycloak: " + str(e), file=sys.stderr)
		D.write(MAVIS_FINAL, AV_V_RESULT_ERROR,
			"Keycloak connection error.")
		continue

	if resp.status_code != 200:
		try:
			err = resp.json()
			error_code = err.get('error', '')
			detail = err.get('error_description', error_code)
		except Exception:
			error_code = ''
			detail = "HTTP " + str(resp.status_code)
		if error_code == 'invalid_grant':
			D.write(MAVIS_FINAL, AV_V_RESULT_FAIL, "Permission denied.")
		else:
			D.write(MAVIS_FINAL, AV_V_RESULT_ERROR,
				"Keycloak error: " + detail)
		continue

	try:
		token_data = resp.json()
	except (json.JSONDecodeError, ValueError):
		print("mavis_tacplus_keycloak: non-JSON 200 response: "
			+ str(resp.status_code) + " " + resp.text[:200], file=sys.stderr)
		D.write(MAVIS_FINAL, AV_V_RESULT_ERROR,
			"Keycloak returned non-JSON response.")
		continue

	# Decode access token and extract groups ###################################
	claims = decode_token_claims(token_data)
	groups = extract_groups(claims)

	# Enforce required group membership
	if KEYCLOAK_REQUIRE_GROUP and KEYCLOAK_REQUIRE_GROUP not in groups:
		D.write(MAVIS_FINAL, AV_V_RESULT_FAIL,
			"Permission denied: not a member of required group.")
		continue

	# Build MAVIS response #####################################################
	D.set_dn(claims.get('sub', D.user) if claims else D.user)

	D.av_pairs[AV_A_IDENTITY_SOURCE] = "keycloak"
	D.remember_password(False)

	if groups:
		D.set_tacmember('"' + '","'.join(groups) + '"')

	D.write(MAVIS_FINAL, AV_V_RESULT_OK, None)

# End
