FROM debian:trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    perl \
    libpcre2-dev \
    libc-ares-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

ENV CC=clang
RUN ./configure --prefix=/usr/local && make

# Install to a staging root
RUN make install INSTALLROOT=/staging

# --------------------------------------------------------------------------- #
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcre2-8-0 \
    libc-ares2 \
    libssl3t64 \
    libcrypt1 \
    python3 \
    python3-redis \
    python3-requests \
    && rm -rf /var/lib/apt/lists/*

# Copy installed files from builder
COPY --from=builder /staging/usr/local/sbin/tac_plus-ng /usr/local/sbin/tac_plus-ng
COPY --from=builder /staging/usr/local/lib/ /usr/local/lib/

# Add the Keycloak and Vault MAVIS scripts (not in upstream install targets)
COPY mavis/python/mavis_tacplus_keycloak.py /usr/local/lib/mavis/mavis_tacplus_keycloak.py
COPY mavis/python/mavis_tacplus_vault.py /usr/local/lib/mavis/mavis_tacplus_vault.py

# Ensure the dynamic linker can find libmavis.so
RUN ldconfig

# MAVIS Python modules live here
ENV PYTHONPATH=/usr/local/lib/mavis

# Non-root runtime user
# Port 49 requires CAP_NET_BIND_SERVICE: run with --cap-add=NET_BIND_SERVICE
# or use a port > 1024 in the config and map it with -p 49:<high-port>.
RUN groupadd -r tacplus && useradd -r -g tacplus -s /usr/sbin/nologin tacplus

# Config and log directories
RUN mkdir -p /etc/tac_plus-ng /var/log/tac_plus-ng \
    && chown tacplus:tacplus /etc/tac_plus-ng /var/log/tac_plus-ng
VOLUME ["/etc/tac_plus-ng"]

EXPOSE 49/tcp

USER tacplus
ENTRYPOINT ["/usr/local/sbin/tac_plus-ng"]
CMD ["/etc/tac_plus-ng/tac_plus-ng.cfg"]
