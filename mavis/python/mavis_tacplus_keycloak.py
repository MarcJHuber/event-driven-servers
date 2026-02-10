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

REDIS_URL
	Redis/Valkey connection URL for cross-process group caching. On AUTH
	success, groups are cached so that subsequent INFO/HOST requests (which
	lack a password) can return group membership without re-authenticating.
	Default: "redis://localhost:6379/0"

KEYCLOAK_CACHE_TTL
	Time-to-live in seconds for cached group entries in Redis.
	Default: 600
"""

import base64
import binascii
import json
import os
import sys

import redis
import requests
from requests.exceptions import RequestException

from mavis import (
	AV_A_IDENTITY_SOURCE,
	AV_A_TYPE,
	AV_V_RESULT_ERROR,
	AV_V_RESULT_FAIL,
	AV_V_RESULT_NOTFOUND,
	AV_V_RESULT_OK,
	AV_V_TYPE_TACPLUS,
	MAVIS_DOWN,
	MAVIS_FINAL,
	Mavis,
)


# Environment variable helpers ################################################
def env(var, default=None):
	return os.getenv(var) or default


KEYCLOAK_URL = env("KEYCLOAK_URL")
KEYCLOAK_REALM = env("KEYCLOAK_REALM", "master")
KEYCLOAK_CLIENT_ID = env("KEYCLOAK_CLIENT_ID", "tacacs")
KEYCLOAK_CLIENT_SECRET = env("KEYCLOAK_CLIENT_SECRET")
KEYCLOAK_VERIFY_TLS = env("KEYCLOAK_VERIFY_TLS", "1") != "0"
_timeout_raw = env("KEYCLOAK_TIMEOUT", "5")
try:
	KEYCLOAK_TIMEOUT = int(_timeout_raw)
except ValueError:
	raise RuntimeError(
		"Invalid KEYCLOAK_TIMEOUT value: '" + _timeout_raw + "'; must be an integer"
	) from None
KEYCLOAK_GROUP_CLAIM = env("KEYCLOAK_GROUP_CLAIM", "groups")
KEYCLOAK_REQUIRE_GROUP = env("KEYCLOAK_REQUIRE_GROUP")
if KEYCLOAK_REQUIRE_GROUP:
	KEYCLOAK_REQUIRE_GROUP = KEYCLOAK_REQUIRE_GROUP.strip().lstrip("/")

REDIS_URL = env("REDIS_URL", "redis://localhost:6379/0")
_cache_ttl_raw = env("KEYCLOAK_CACHE_TTL", "600")
try:
	KEYCLOAK_CACHE_TTL = int(_cache_ttl_raw)
except ValueError:
	raise RuntimeError(
		"Invalid KEYCLOAK_CACHE_TTL value: '" + _cache_ttl_raw + "'; must be an integer"
	) from None

if not KEYCLOAK_URL:
	raise RuntimeError(
		"KEYCLOAK_URL is required. Set it via 'setenv KEYCLOAK_URL = https://...' "
		"in the mavis module configuration."
	)

TOKEN_URL = (
	KEYCLOAK_URL.rstrip("/")
	+ "/realms/"
	+ KEYCLOAK_REALM
	+ "/protocol/openid-connect/token"
)

print("mavis_tacplus_keycloak: ROPC endpoint " + TOKEN_URL, file=sys.stderr)

# Reusable HTTP session ########################################################
http = requests.Session()
http.verify = KEYCLOAK_VERIFY_TLS
if not KEYCLOAK_VERIFY_TLS:
	import urllib3

	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Shared Redis/Valkey cache for cross-process group persistence ################
_redis = None
try:
	_redis = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=2)
	_redis.ping()
	print("mavis_tacplus_keycloak: connected to Redis at " + REDIS_URL, file=sys.stderr)
except Exception as e:
	print(
		"mavis_tacplus_keycloak: Redis unavailable (" + str(e) + "); "
		"INFO requests will return OK without groups",
		file=sys.stderr,
	)
	_redis = None


def cache_put(username, groups, dn):
	"""Store user groups in Redis. Non-fatal on failure."""
	if _redis is None:
		return
	try:
		_redis.setex(
			"tacplus:keycloak:" + username,
			KEYCLOAK_CACHE_TTL,
			json.dumps({"groups": groups, "dn": dn}),
		)
	except Exception as e:
		print("mavis_tacplus_keycloak: cache write failed: " + str(e), file=sys.stderr)


def cache_get(username):
	"""Retrieve cached groups from Redis. Returns (groups, dn) or (None, None)."""
	if _redis is None:
		return None, None
	try:
		raw = _redis.get("tacplus:keycloak:" + username)
		if raw is None:
			return None, None
		data = json.loads(raw)
		return data.get("groups", []), data.get("dn", username)
	except Exception as e:
		print("mavis_tacplus_keycloak: cache read failed: " + str(e), file=sys.stderr)
		return None, None


# JWT helpers ##################################################################
def decode_jwt_payload(token):
	"""Decode the payload of a JWT without signature verification.

	Signature verification is intentionally skipped: the token is obtained
	directly from Keycloak over a TLS-protected channel with no untrusted
	intermediaries, so payload inspection is safe. If tokens were received
	from untrusted sources (e.g. client-supplied), full signature verification
	against Keycloak's JWKS endpoint would be required instead.
	"""
	parts = token.split(".")
	if len(parts) != 3:
		raise ValueError(
			"Malformed JWT: expected three dot-separated parts, got " + str(len(parts))
		)
	payload = parts[1]
	padding = 4 - len(payload) % 4
	if padding != 4:
		payload += "=" * padding
	return json.loads(base64.urlsafe_b64decode(payload))


def decode_token_claims(token_data):
	"""Decode access token JWT and return claims dict, or None on failure."""
	if not isinstance(token_data, dict) or "access_token" not in token_data:
		print(
			"mavis_tacplus_keycloak: token response missing 'access_token' key",
			file=sys.stderr,
		)
		return None
	try:
		return decode_jwt_payload(token_data["access_token"])
	except (ValueError, json.JSONDecodeError, binascii.Error) as e:
		print(
			"mavis_tacplus_keycloak: failed to decode JWT: " + str(e), file=sys.stderr
		)
		return None


def extract_groups(claims):
	"""Extract group names from decoded JWT claims."""
	if claims is None:
		return []
	groups = claims.get(KEYCLOAK_GROUP_CLAIM, [])
	if isinstance(groups, str):
		groups = [groups]
	elif not isinstance(groups, (list, tuple, set)):
		return []
	# Keycloak may return full paths like "/admin" — strip leading slash
	return [g.lstrip("/") for g in groups if g]


# Main loop ####################################################################
while True:
	D = Mavis()

	# Check AV_A_TYPE directly instead of calling Mavis.is_tacplus() which has
	# an upstream bug: it passes self.av_pairs (a dict) as the verdict arg to
	# D.write(), producing garbage output. This is a deliberate workaround.
	if D.av_pairs.get(AV_A_TYPE) != AV_V_TYPE_TACPLUS:
		D.write(MAVIS_DOWN, None, None)
		continue

	if not D.valid():
		continue

	# Pass DACL to next module (future: Vault integration)
	if not D.is_tacplus_authc and not D.is_tacplus_authz and not D.is_tacplus_host:
		D.write(MAVIS_DOWN, AV_V_RESULT_NOTFOUND, None)
		continue

	# Password changes are not supported
	if D.is_tacplus_chpw:
		D.write(
			MAVIS_FINAL,
			AV_V_RESULT_FAIL,
			"Password change is not supported via Keycloak ROPC.",
		)
		continue

	# Handle authorization (INFO) and host authorization (HOST) from cache.
	# Both need the same data: user identity + group membership.
	# tac_plus-ng config maps groups to authorization rules and host access.
	if D.is_tacplus_authz or D.is_tacplus_host:
		cached_groups, cached_dn = cache_get(D.user)
		D.av_pairs[AV_A_IDENTITY_SOURCE] = "keycloak"
		if cached_groups is not None:
			D.set_dn(cached_dn)
			sanitized = [g for g in cached_groups if '"' not in g and "\\" not in g]
			if sanitized:
				D.set_tacmember('"' + '","'.join(sanitized) + '"')
		else:
			D.set_dn(D.user)
		D.write(MAVIS_FINAL, AV_V_RESULT_OK, None)
		continue

	# Authenticate via ROPC ####################################################
	post_data = {
		"grant_type": "password",
		"client_id": KEYCLOAK_CLIENT_ID,
		"username": D.user,
		"password": D.password,
	}
	if KEYCLOAK_CLIENT_SECRET:
		post_data["client_secret"] = KEYCLOAK_CLIENT_SECRET

	try:
		resp = http.post(TOKEN_URL, data=post_data, timeout=KEYCLOAK_TIMEOUT)
	except RequestException as e:
		print("mavis_tacplus_keycloak: " + str(e), file=sys.stderr)
		D.write(MAVIS_FINAL, AV_V_RESULT_ERROR, "Keycloak connection error.")
		continue

	if resp.status_code != 200:
		try:
			err = resp.json()
			error_code = err.get("error", "")
			detail = err.get("error_description", error_code)
		except (json.JSONDecodeError, ValueError):
			error_code = ""
			detail = "HTTP " + str(resp.status_code)
		if error_code == "invalid_grant":
			D.write(MAVIS_FINAL, AV_V_RESULT_FAIL, "Permission denied.")
		else:
			D.write(MAVIS_FINAL, AV_V_RESULT_ERROR, "Keycloak error: " + detail)
		continue

	try:
		token_data = resp.json()
	except (json.JSONDecodeError, ValueError):
		print(
			"mavis_tacplus_keycloak: non-JSON 200 response: "
			+ str(resp.status_code)
			+ " "
			+ resp.text[:200],
			file=sys.stderr,
		)
		D.write(MAVIS_FINAL, AV_V_RESULT_ERROR, "Keycloak returned non-JSON response.")
		continue

	# Decode access token and extract groups ###################################
	claims = decode_token_claims(token_data)
	if claims is None:
		D.write(
			MAVIS_FINAL,
			AV_V_RESULT_ERROR,
			"Failed to decode access token claims.",
		)
		continue
	groups = extract_groups(claims)

	# Enforce required group membership
	if KEYCLOAK_REQUIRE_GROUP and KEYCLOAK_REQUIRE_GROUP not in groups:
		D.write(
			MAVIS_FINAL,
			AV_V_RESULT_FAIL,
			"Permission denied: not a member of required group.",
		)
		continue

	# Build MAVIS response #####################################################
	D.set_dn(claims.get("sub", D.user))

	D.av_pairs[AV_A_IDENTITY_SOURCE] = "keycloak"
	D.remember_password(False)  # noqa: FBT003

	if groups:
		# Reject group names containing double quotes or backslashes to prevent
		# malformed tacmember strings (the AV protocol uses quoted CSV format).
		sanitized = []
		for g in groups:
			if '"' in g or "\\" in g:
				print(
					"mavis_tacplus_keycloak: skipping group with unsafe chars: "
					+ repr(g),
					file=sys.stderr,
				)
				continue
			sanitized.append(g)
		if sanitized:
			D.set_tacmember('"' + '","'.join(sanitized) + '"')

	cache_put(D.user, groups, claims.get("sub", D.user))
	D.write(MAVIS_FINAL, AV_V_RESULT_OK, None)

# End
