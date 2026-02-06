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
    python3-requests \
    && rm -rf /var/lib/apt/lists/*

# Copy installed files from builder
COPY --from=builder /staging/usr/local/sbin/tac_plus-ng /usr/local/sbin/tac_plus-ng
COPY --from=builder /staging/usr/local/lib/ /usr/local/lib/

# Add the Keycloak MAVIS script (not in upstream install targets)
COPY mavis/python/mavis_tacplus_keycloak.py /usr/local/lib/mavis/mavis_tacplus_keycloak.py

# Ensure the dynamic linker can find libmavis.so
RUN ldconfig

# MAVIS Python modules live here
ENV PYTHONPATH=/usr/local/lib/mavis

# Config mount point
RUN mkdir -p /etc/tac_plus-ng
VOLUME ["/etc/tac_plus-ng"]

EXPOSE 49/tcp

ENTRYPOINT ["/usr/local/sbin/tac_plus-ng"]
CMD ["/etc/tac_plus-ng/tac_plus-ng.cfg"]
