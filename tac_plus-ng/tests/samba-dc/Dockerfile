# A Samba AD DC for test_ldapmavis_ad.py; ./start builds and runs it.
ARG BASE=debian:trixie
FROM $BASE
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba samba-ad-dc samba-ad-provision openssl \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint /entrypoint
ENTRYPOINT ["/entrypoint"]
