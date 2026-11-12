"""A DNS server for the reverse lookups of the daemon: it answers every query with one PTR record."""

import select
import socket
import struct
import threading


def ptr_reply(query, name):
    """A DNS reply to query with one PTR record for name."""
    end = 12
    while query[end]:
        end += 1 + query[end]
    question = query[12:end + 5]
    rdata = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 60, len(rdata)) + rdata
    return query[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 1, 0, 0) + question + answer


class Server:
    """A UDP server on (address, port) that answers every query with the PTR name; port 0 picks a free port.

    device binds the socket to a network device (SO_BINDTODEVICE), e.g. a VRF. SO_REUSEADDR lets
    a second server use the same address and port in another VRF. queries counts what it got.
    """

    def __init__(self, name, address="127.0.0.1", port=0, device=None):
        self.name, self.queries = name, 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if device:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, device.encode())
        self.sock.bind((address, port))
        self.addr = self.sock.getsockname()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            if select.select([self.sock], [], [], 0.1)[0]:
                query, peer = self.sock.recvfrom(4096)
                self.queries += 1
                self.sock.sendto(ptr_reply(query, self.name), peer)

    def close(self):
        self.stop.set()
        self.thread.join()
        self.sock.close()
