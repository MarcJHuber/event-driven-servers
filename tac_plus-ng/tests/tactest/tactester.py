"""The tactester client (tactester/ in the tree), installed by run-tests next to the daemon."""

import os

from .daemon import features, prefix


def binary():
    """Path of tactester in the prefix under test, or None: its Makefile builds it only with OpenSSL."""
    path = os.path.join(prefix(), "sbin", "tactester")
    # make install keeps a tactester of an earlier build with OpenSSL
    return path if "openssl" in features() and os.access(path, os.X_OK) else None
