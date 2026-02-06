# CLAUDE.md — tac_plus-ng (forked)

## Project Overview

This is a fork of [MarcJHuber/event-driven-servers](https://github.com/MarcJHuber/event-driven-servers) — a collection of event-driven server implementations. Our fork lives at `git@github.com:marcinpsk/tacplus-ng.git`.

We only care about **tac_plus-ng** — a modern TACACS+ daemon. The rest of the repo (ftpd, tcprelay, etc.) is upstream baggage.

## Repository Structure

```
├── tac_plus-ng/         # TACACS+ NG server (our focus)
│   ├── mavis.c          # TAC+ <-> MAVIS integration (auth dispatch)
│   ├── sample/          # Example configs
│   └── ...
├── mavis/               # MAVIS framework — pluggable auth backend system
│   ├── mavis.h          # Core interface (API v6, 56 AV attributes)
│   ├── libmavis.c       # Module loader and chain management
│   ├── mavis_glue.c     # Boilerplate glue for C modules
│   ├── libmavis_external.c   # Spawns external scripts (Perl/Python)
│   ├── libmavis_cache.c      # Caching layer
│   ├── libmavis_groups.c     # Group resolution
│   ├── perl/            # Perl backend scripts
│   │   ├── Mavis.pm
│   │   ├── mavis_tacplus-ng_ldap.pl
│   │   └── ...
│   └── python/          # Python backend scripts
│       ├── mavis.py     # Python MAVIS helper (AV constants, Mavis class)
│       ├── mavis_tacplus_ldap.py  # LDAP backend reference implementation
│       └── ...
├── mavisd/              # MAVIS standalone daemon
├── spawnd/              # Spawn daemon (network listener, forks workers)
├── misc/                # Shared utilities (io, buffer, net, etc.)
├── configure            # Perl-based configure script
├── GNUmakefile          # Top-level build (requires GNU make)
└── PREREQUISITES.txt    # Build deps: clang/gcc, libpcre2, libc-ares, openssl 3.x
```

## Build System

```bash
./configure              # Generates build/Makefile.inc.<OS>
make                     # GNU make required (calls GNUmakefile)
make install             # Installs to /usr/local by default
```

Build prerequisites: GNU make, C compiler (clang preferred), libpcre2-dev, libc-ares-dev, libssl-dev (OpenSSL 3.x).

## MAVIS Architecture (Auth Backend System)

MAVIS = **Modular Attribute-Value Interchange System**. It's a plugin chain for authentication/authorization.

### How it works
- Modules form a **chain** — each gets a chance to handle the request
- Communication uses **56 standardized AV (attribute-value) pairs** defined in `mavis/mavis.h`
- A module returns: `MAVIS_FINAL` (done), `MAVIS_DOWN` (pass to next), `MAVIS_DEFERRED` (async)
- Config can stack modules: cache -> groups -> external (script)

### Key AV attributes for TACACS+
| Attribute | Description |
|---|---|
| `AV_A_TYPE` | Request type (`TACPLUS`) |
| `AV_A_USER` | Username |
| `AV_A_PASSWORD` | Password |
| `AV_A_TACTYPE` | Operation: `AUTH`, `INFO`, `CHPW`, `CHAL`, `HOST`, `DACL`, `MSCH` |
| `AV_A_RESULT` | `ACK` (ok), `NAK` (fail), `ERR` (error), `NFD` (not found) |
| `AV_A_TACMEMBER` | Group membership (quoted, comma-separated) |
| `AV_A_TACPROFILE` | Dynamic user profile |
| `AV_A_MEMBEROF` | Raw memberOf data |
| `AV_A_DN` | Distinguished name / user identifier |
| `AV_A_IDENTITY_SOURCE` | Source of authentication |

### External script protocol (stdin/stdout)
```
# Input (one AV pair per line, terminated by "="):
0 TACPLUS
4 username
8 password
49 AUTH
=

# Output (AV pairs + "=<verdict>"):
47 "group1","group2"
6 ACK
=0
```

### Writing a Python MAVIS backend
Use `mavis/python/mavis.py` — provides the `Mavis` class and all AV_* constants.
Reference implementation: `mavis/python/mavis_tacplus_ldap.py`.

Pattern (see `mavis/python/mavis_tacplus_keycloak.py` for the full example):
```python
from mavis import (Mavis, MAVIS_DOWN, MAVIS_FINAL, AV_V_RESULT_OK,
    AV_A_TYPE, AV_V_TYPE_TACPLUS, ...)

while True:
    D = Mavis()                    # Reads AV pairs from stdin
    # NOTE: Do NOT use D.is_tacplus() — upstream Mavis.is_tacplus() has a bug
    # where it passes self.av_pairs (a dict) as the verdict arg to D.write(),
    # producing garbage output. Check AV_A_TYPE directly instead.
    if D.av_pairs.get(AV_A_TYPE) != AV_V_TYPE_TACPLUS:
        D.write(MAVIS_DOWN, None, None)
        continue
    if not D.valid():              # Validate required fields
        continue
    # ... authenticate, lookup groups ...
    D.set_tacmember('"group1","group2"')
    D.write(MAVIS_FINAL, AV_V_RESULT_OK, None)
```

### Configuration pattern for external backends
```
mavis module <name> = external {
    exec = /path/to/script.py
    setenv VAR = value
    childs min = 4
    childs max = 64
}

user backend = mavis
login backend = mavis
pap backend = mavis
```

## Our Additions (Keycloak Backend)

### Goal
Add a Python MAVIS external script that authenticates users against **Keycloak** using ROPC (Resource Owner Password Credentials) grant and maps Keycloak groups to TACACS+ group membership.

### Scope
- Authentication only (AUTH) — no password changes (CHPW)
- ROPC flow: `POST /realms/{realm}/protocol/openid-connect/token`
- Group lookup via JWT group claims from access token (decoded by mavis_tacplus_keycloak.py)
- Keycloak groups -> `AV_A_TACMEMBER`
- Dockerized build of tac_plus-ng with the Keycloak script included
- GitHub Actions CI for building the Docker image

### Config will look like
```
mavis module keycloak = external {
    exec = /path/to/mavis_tacplus_keycloak.py
    setenv KEYCLOAK_URL = https://keycloak.example.com
    setenv KEYCLOAK_REALM = myrealm
    setenv KEYCLOAK_CLIENT_ID = tacacs-client
    setenv KEYCLOAK_CLIENT_SECRET = <secret>
}
```

## Conventions

- Upstream code style: C with tabs, no trailing whitespace
- Python scripts: follow the pattern in `mavis/python/mavis_tacplus_ldap.py`
- MAVIS scripts are long-running processes (while True loop), not invoked per-request
- Group membership format: `'"group1","group2"'` (quoted, comma-separated)
- Test with: `printf "0 TACPLUS\n4 user\n8 pass\n49 AUTH\n=\n" | ./script.py`
