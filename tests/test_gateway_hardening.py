import socket
import struct

import pytest

from gateway.server import DNSGatewayServer


class FragmentedSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = b""
        self.closed = False

    def settimeout(self, _timeout):
        pass

    def recv(self, size):
        if not self.chunks:
            return b""
        return self.chunks.pop(0)[:size]

    def sendall(self, data):
        self.sent += data

    def close(self):
        self.closed = True


class EchoPolicy:
    def process_query(self, data, _client_ip, _client_port):
        return data, {}


def test_tcp_fragmented_prefix_and_payload_are_reassembled():
    query = b"\x12\x34\x00\x00dns"
    framed = struct.pack("!H", len(query)) + query
    sock = FragmentedSocket([framed[:1], framed[1:2], framed[2:4], framed[4:5], framed[5:]])
    server = DNSGatewayServer(policy_engine=EchoPolicy())
    server.running = True

    server._handle_tcp_client(sock, ("127.0.0.1", 1234))

    assert sock.sent == framed
    assert sock.closed


def test_worker_pool_is_bounded():
    server = DNSGatewayServer(policy_engine=EchoPolicy())
    assert server._workers._max_workers == 64
    server.stop()


def test_partial_startup_closes_first_listener():
    occupied = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    occupied.bind(("127.0.0.1", 0))
    port = occupied.getsockname()[1]
    server = DNSGatewayServer(host="127.0.0.1", port=port, policy_engine=EchoPolicy())

    try:
        with pytest.raises(OSError):
            server.start()
        assert not server.running
        assert server.udp_sock is not None
        with pytest.raises(OSError):
            server.udp_sock.getsockname()
    finally:
        occupied.close()
        server.stop()


def test_shutdown_releases_udp_and_tcp_ports():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    server = DNSGatewayServer(host="127.0.0.1", port=port, policy_engine=EchoPolicy())
    server.start()
    server.stop()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(("127.0.0.1", port))
