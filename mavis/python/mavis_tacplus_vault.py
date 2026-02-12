#!/usr/bin/python3
#
# mavis_tacplus_vault.py
#
# TACACS+ NG backend for libmavis_external.so
# Authenticates against HashiCorp Vault KV v2 secrets engine using AppRole
# auth. Each user has a secret at {mount}/data/{path_prefix}/{username} with
# "password" and "groups" keys. Intended as a break-glass/fallback backend
# behind a primary provider (e.g. Keycloak) in the MAVIS module chain.
#
# Vault secret setup:
#   vault kv put secret/tacacs/users/admin password=s3cret groups=admin,noc
#   vault kv put secret/tacacs/users/breakglass password=emergency groups=admin
#

"""
Test input for authentication:
0 TACPLUS
4 $USER
8 $PASS
49 AUTH
=

printf "0 TACPLUS\\n4 admin\\n8 s3cret\\n49 AUTH\\n=\\n" | \\
  VAULT_ADDR=http://127.0.0.1:8200 \\
  VAULT_ROLE_ID=<role-id> VAULT_SECRET_ID=<secret-id> \\
  PYTHONPATH=mavis/python python3 mavis/python/mavis_tacplus_vault.py

#######

Environment variables:

VAULT_ADDR
	Base URL of the Vault server.
	Example: "https://vault.example.com:8200"

VAULT_ROLE_ID
	AppRole role ID for authentication.

VAULT_SECRET_ID
	AppRole secret ID for authentication.

VAULT_MOUNT
	KV v2 mount point.
	Default: "secret"

VAULT_PATH_PREFIX
	Path prefix under the KV mount where user secrets are stored.
	Default: "tacacs/users"

VAULT_VERIFY_TLS
	Set to "0" to disable TLS certificate verification.
	Default: "1" (verify)

VAULT_TIMEOUT
	HTTP request timeout in seconds.
	Default: 5

VAULT_CACHE_TTL
	In-process cache TTL in seconds for Vault secret reads. Each forked
	worker process maintains its own cache. This avoids hitting Vault on
	every AUTH request — acceptable for the small number of break-glass
	users this backend is designed for (1-10 users).
	Default: 300

REDIS_URL
	Redis/Valkey connection URL for cross-process group caching. On AUTH
	success, groups are cached so that subsequent INFO/HOST requests (which
	lack a password) can return group membership without re-reading Vault.
	Default: "redis://localhost:6379/0"

VAULT_REDIS_CACHE_TTL
	Time-to-live in seconds for cached group entries in Redis.
	Default: 600
"""

import json
import os
import sys
import time

try:
	import redis
except ImportError:
	redis = None

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


def env_int(var, default, label=None):
	raw = env(var, str(default))
	name = label or var
	try:
		val = int(raw)
	except ValueError:
		raise RuntimeError(
			"Invalid " + name + " value: '" + raw + "'; must be an integer"
		) from None
	return val


VAULT_ADDR = env("VAULT_ADDR")
VAULT_ROLE_ID = env("VAULT_ROLE_ID")
VAULT_SECRET_ID = env("VAULT_SECRET_ID")
VAULT_MOUNT = env("VAULT_MOUNT", "secret")
VAULT_PATH_PREFIX = env("VAULT_PATH_PREFIX", "tacacs/users").strip("/")
VAULT_VERIFY_TLS = env("VAULT_VERIFY_TLS", "1") != "0"
VAULT_TIMEOUT = env_int("VAULT_TIMEOUT", 5)
VAULT_CACHE_TTL = env_int("VAULT_CACHE_TTL", 300)
if VAULT_CACHE_TTL <= 0:
	raise RuntimeError(
		"Invalid VAULT_CACHE_TTL value: must be a positive integer"
	)

REDIS_URL = env("REDIS_URL", "redis://localhost:6379/0")
VAULT_REDIS_CACHE_TTL = env_int("VAULT_REDIS_CACHE_TTL", 600)
if VAULT_REDIS_CACHE_TTL <= 0:
	raise RuntimeError(
		"Invalid VAULT_REDIS_CACHE_TTL value: must be a positive integer"
	)

if not VAULT_ADDR:
	raise RuntimeError(
		"VAULT_ADDR is required. Set it via 'setenv VAULT_ADDR = https://...' "
		"in the mavis module configuration or via container environment."
	)
if not VAULT_ROLE_ID:
	raise RuntimeError(
		"VAULT_ROLE_ID is required. Set it via 'setenv VAULT_ROLE_ID = ...' "
		"in the mavis module configuration or via container environment."
	)
if not VAULT_SECRET_ID:
	raise RuntimeError(
		"VAULT_SECRET_ID is required. Set it via 'setenv VAULT_SECRET_ID = ...' "
		"in the mavis module configuration or via container environment."
	)

VAULT_BASE = VAULT_ADDR.rstrip("/")
VAULT_LOGIN_URL = VAULT_BASE + "/v1/auth/approle/login"
VAULT_KV_URL = VAULT_BASE + "/v1/" + VAULT_MOUNT + "/data/" + VAULT_PATH_PREFIX + "/"

print(
	"mavis_tacplus_vault: Vault KV at " + VAULT_KV_URL + "<username>",
	file=sys.stderr,
)

# Reusable HTTP session ########################################################
http = requests.Session()
http.verify = VAULT_VERIFY_TLS
if not VAULT_VERIFY_TLS:
	import urllib3

	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Vault AppRole auth ###########################################################
_vault_token = None
_vault_token_expires_at = 0.0


def _vault_login():
	"""Authenticate to Vault via AppRole. Sets module-level token state."""
	global _vault_token, _vault_token_expires_at
	_vault_token = None
	_vault_token_expires_at = 0.0
	try:
		resp = http.post(
			VAULT_LOGIN_URL,
			json={"role_id": VAULT_ROLE_ID, "secret_id": VAULT_SECRET_ID},
			timeout=VAULT_TIMEOUT,
		)
	except RequestException as e:
		print("mavis_tacplus_vault: Vault login failed: " + str(e), file=sys.stderr)
		return False
	if resp.status_code != 200:
		print(
			"mavis_tacplus_vault: Vault login HTTP " + str(resp.status_code)
			+ ": " + resp.text[:200],
			file=sys.stderr,
		)
		return False
	try:
		auth = resp.json().get("auth", {})
	except (json.JSONDecodeError, ValueError):
		print("mavis_tacplus_vault: Vault login returned non-JSON response", file=sys.stderr)
		return False
	_vault_token = auth.get("client_token")
	lease_duration = auth.get("lease_duration", 0)
	# Schedule renewal at ~50% of the lease TTL
	if lease_duration > 0:
		_vault_token_expires_at = time.monotonic() + lease_duration * 0.5
	else:
		# No explicit TTL — renew in 5 minutes as a safe default
		_vault_token_expires_at = time.monotonic() + 300
	if _vault_token:
		print("mavis_tacplus_vault: Vault login successful", file=sys.stderr)
		return True
	print("mavis_tacplus_vault: Vault login response missing client_token", file=sys.stderr)
	return False


def _vault_ensure_token():
	"""Ensure we have a valid Vault token, logging in or renewing as needed."""
	global _vault_token, _vault_token_expires_at
	if _vault_token and time.monotonic() < _vault_token_expires_at:
		return True
	if _vault_token:
		# Try to renew the token
		try:
			resp = http.post(
				VAULT_BASE + "/v1/auth/token/renew-self",
				headers={"X-Vault-Token": _vault_token},
				json={},
				timeout=VAULT_TIMEOUT,
			)
			if resp.status_code == 200:
				auth = resp.json().get("auth", {})
				lease_duration = auth.get("lease_duration", 0)
				if lease_duration > 0:
					_vault_token_expires_at = time.monotonic() + lease_duration * 0.5
				else:
					_vault_token_expires_at = time.monotonic() + 300
				print("mavis_tacplus_vault: Vault token renewed", file=sys.stderr)
				return True
		except (RequestException, json.JSONDecodeError, ValueError):
			pass
		# Renewal failed — fall through to fresh login
	return _vault_login()


# Initial login at startup
_vault_login()


# In-process cache for Vault reads ############################################
# Simple dict keyed by username. Each entry: {"password": ..., "groups": ...,
# "fetched_at": monotonic_time}. Each forked worker has its own cache.
_user_cache = {}


def _cache_get_user(username):
	"""Return (password, groups) from in-process cache, or (None, None) if
	expired or missing."""
	entry = _user_cache.get(username)
	if entry is None:
		return None, None
	if time.monotonic() - entry["fetched_at"] > VAULT_CACHE_TTL:
		del _user_cache[username]
		return None, None
	return entry["password"], entry["groups"]


def _cache_put_user(username, password, groups):
	"""Store user data in in-process cache."""
	_user_cache[username] = {
		"password": password,
		"groups": groups,
		"fetched_at": time.monotonic(),
	}


# Vault KV read ###############################################################
def _vault_read_user(username):
	"""Read a user secret from Vault KV v2.

	Returns (password, groups_list) on success, (None, None) if the user
	does not exist, or raises RuntimeError on Vault errors.
	"""
	# Check in-process cache first
	cached_pw, cached_groups = _cache_get_user(username)
	if cached_pw is not None:
		return cached_pw, cached_groups

	if not _vault_ensure_token():
		raise RuntimeError("Unable to authenticate to Vault")

	url = VAULT_KV_URL + username
	try:
		resp = http.get(
			url,
			headers={"X-Vault-Token": _vault_token},
			timeout=VAULT_TIMEOUT,
		)
	except RequestException as e:
		raise RuntimeError("Vault connection error: " + str(e)) from e

	if resp.status_code == 404:
		return None, None

	if resp.status_code in (401, 403):
		# Token may have been revoked — re-login and retry once
		if _vault_login():
			try:
				resp = http.get(
					url,
					headers={"X-Vault-Token": _vault_token},
					timeout=VAULT_TIMEOUT,
				)
			except RequestException as e:
				raise RuntimeError("Vault connection error: " + str(e)) from e
			if resp.status_code == 404:
				return None, None
			if resp.status_code in (401, 403):
				raise RuntimeError("Vault auth failed after re-login: HTTP " + str(resp.status_code))
		else:
			raise RuntimeError("Vault re-login failed after HTTP " + str(resp.status_code))

	if resp.status_code != 200:
		raise RuntimeError("Vault read error: HTTP " + str(resp.status_code))

	try:
		data = resp.json().get("data", {}).get("data", {})
	except (json.JSONDecodeError, ValueError) as e:
		raise RuntimeError("Vault returned non-JSON response: " + str(e)) from e

	password = data.get("password")
	groups_raw = data.get("groups", "")
	if isinstance(groups_raw, list):
		groups = groups_raw
	elif isinstance(groups_raw, str) and groups_raw:
		groups = [g.strip() for g in groups_raw.split(",") if g.strip()]
	else:
		groups = []

	# Store in in-process cache
	_cache_put_user(username, password, groups)
	return password, groups


# Shared Redis/Valkey cache for cross-process group persistence ################
_redis_client = None
_redis_fail_count = 0
_last_redis_attempt = 0.0
_REDIS_BACKOFF_SECONDS = 10
_CACHE_KEY_PREFIX = "tacplus:vault:" + VAULT_PATH_PREFIX.replace("/", ":") + ":"


def _get_redis():
	"""Return a Redis client, reconnecting only when _redis_client is None."""
	global _redis_client, _redis_fail_count, _last_redis_attempt
	if redis is None:
		return None
	if _redis_client is not None:
		return _redis_client
	# Avoid hammering Redis with reconnect attempts
	now = time.monotonic()
	if now - _last_redis_attempt < _REDIS_BACKOFF_SECONDS:
		return None
	_last_redis_attempt = now
	try:
		client = redis.Redis.from_url(
			REDIS_URL, decode_responses=True, socket_timeout=2
		)
		client.ping()
		_redis_client = client
		_redis_fail_count = 0
		print(
			"mavis_tacplus_vault: connected to Redis at " + REDIS_URL,
			file=sys.stderr,
		)
		return _redis_client
	except redis.RedisError as e:
		_redis_fail_count += 1
		# Log first failure and then every 50th to avoid flooding stderr
		if _redis_fail_count == 1 or _redis_fail_count % 50 == 0:
			print(
				"mavis_tacplus_vault: Redis unavailable (" + str(e) + "); "
				"INFO/HOST requests will defer without groups",
				file=sys.stderr,
			)
		return None


def _invalidate_redis():
	"""Mark the current Redis connection as dead so _get_redis() reconnects."""
	global _redis_client
	_redis_client = None


# Attempt initial connection at startup
if redis is None:
	print(
		"mavis_tacplus_vault: python3-redis not installed; "
		"caching disabled, INFO/HOST requests will defer",
		file=sys.stderr,
	)
else:
	_get_redis()


def cache_put(username, groups, dn):
	"""Store user groups in Redis. Non-fatal on failure."""
	r = _get_redis()
	if r is None:
		return
	try:
		r.setex(
			_CACHE_KEY_PREFIX + username,
			VAULT_REDIS_CACHE_TTL,
			json.dumps({"groups": groups, "dn": dn}),
		)
	except redis.RedisError as e:
		_invalidate_redis()
		print(
			"mavis_tacplus_vault: cache write failed: " + str(e),
			file=sys.stderr,
		)


def cache_get(username):
	"""Retrieve cached groups from Redis. Returns (groups, dn) or (None, None)."""
	r = _get_redis()
	if r is None:
		return None, None
	try:
		raw = r.get(_CACHE_KEY_PREFIX + username)
	except redis.RedisError as e:
		_invalidate_redis()
		print(
			"mavis_tacplus_vault: cache read failed (redis): " + str(e),
			file=sys.stderr,
		)
		return None, None
	if raw is None:
		return None, None
	try:
		data = json.loads(raw)
		return data.get("groups", []), data.get("dn", username)
	except json.JSONDecodeError as e:
		print(
			"mavis_tacplus_vault: cache read failed (json decode): " + str(e),
			file=sys.stderr,
		)
		return None, None


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

	# Unsupported request type (e.g. DACL) — pass to next module
	if not D.is_tacplus_authc and not D.is_tacplus_authz and not D.is_tacplus_host:
		D.write(MAVIS_DOWN, AV_V_RESULT_NOTFOUND, None)
		continue

	# Password changes are not supported
	if D.is_tacplus_chpw:
		D.write(
			MAVIS_FINAL,
			AV_V_RESULT_FAIL,
			"Password change is not supported via Vault backend.",
		)
		continue

	# Handle authorization (INFO) and host authorization (HOST) from cache.
	if D.is_tacplus_authz or D.is_tacplus_host:
		cached_groups, cached_dn = cache_get(D.user)
		if cached_groups is None:
			# No cached session — user must authenticate first
			D.write(MAVIS_DOWN, AV_V_RESULT_NOTFOUND, None)
			continue
		D.av_pairs[AV_A_IDENTITY_SOURCE] = "vault"
		D.set_dn(cached_dn)
		# Groups are stored pre-sanitized by the AUTH path
		if cached_groups:
			D.set_tacmember('"' + '","'.join(cached_groups) + '"')
		D.write(MAVIS_FINAL, AV_V_RESULT_OK, None)
		continue

	# Authenticate via Vault KV v2 #############################################
	try:
		vault_pw, vault_groups = _vault_read_user(D.user)
	except RuntimeError as e:
		print("mavis_tacplus_vault: " + str(e), file=sys.stderr)
		D.write(MAVIS_FINAL, AV_V_RESULT_ERROR, "Vault error.")
		continue

	# User not found in Vault — pass to next module in chain
	if vault_pw is None:
		D.write(MAVIS_DOWN, AV_V_RESULT_NOTFOUND, None)
		continue

	# Password mismatch — this is a final deny (user exists in Vault)
	if D.password != vault_pw:
		D.write(MAVIS_FINAL, AV_V_RESULT_FAIL, "Permission denied.")
		continue

	# Authentication success ###################################################
	D.set_dn(D.user)
	D.av_pairs[AV_A_IDENTITY_SOURCE] = "vault"
	D.remember_password(False)  # noqa: FBT003

	# Sanitize group names — reject those with double quotes or backslashes
	sanitized = []
	for g in vault_groups:
		if '"' in g or "\\" in g:
			print(
				"mavis_tacplus_vault: skipping group with unsafe chars: " + repr(g),
				file=sys.stderr,
			)
			continue
		sanitized.append(g)
	if sanitized:
		D.set_tacmember('"' + '","'.join(sanitized) + '"')

	# Cache sanitized groups so INFO/HOST reads don't need re-sanitization
	cache_put(D.user, sanitized, D.user)
	D.write(MAVIS_FINAL, AV_V_RESULT_OK, None)

# End
