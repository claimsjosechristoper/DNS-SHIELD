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


def test_normalize_domain_allows_valid_underscores_and_rejects_malformed():
    from gateway.normalization import normalize_domain

    valid_domains = [
        "_dmarc.example.com",
        "_domainkey.example.org",
        "_sip._tcp.example.com",
        "_acme-challenge.secure.net",
        "api-v1.sub_domain.example.com",
    ]
    for d in valid_domains:
        norm, is_valid, err = normalize_domain(d)
        assert is_valid is True, f"Expected {d} to be valid, got error: {err}"
        assert norm == d.lower()

    invalid_domains = [
        "-invalid-leading-hyphen.com",
        "invalid-trailing-hyphen-.com",
        "double..dot.com",
        ("a" * 64) + ".com",
    ]
    for d in invalid_domains:
        _, is_valid, err = normalize_domain(d)
        assert is_valid is False, f"Expected {d} to be rejected"


def test_upstream_validates_transaction_id_and_question():
    from dnslib import DNSRecord, QTYPE, RR, A
    from gateway.upstream import UpstreamResolver

    resolver = UpstreamResolver()
    query = DNSRecord.question("example.com", "A")
    expected_id = 0xABCD
    client_id = 0x1234

    # 1. Valid response with matching ID
    valid_rep = query.reply()
    valid_rep.header.id = expected_id
    valid_rep.add_answer(RR("example.com", QTYPE.A, rdata=A("93.184.216.34"), ttl=300))
    resp_bytes = resolver._validate_upstream_response(
        valid_rep.pack(), expected_id, query.q.qname, query.q.qtype, client_id
    )
    parsed = DNSRecord.parse(resp_bytes)
    assert parsed.header.id == client_id  # Restored client transaction ID
    assert parsed.header.qr == 1

    # 2. Spoofed response with mismatched transaction ID
    spoofed_rep = query.reply()
    spoofed_rep.header.id = 0x9999  # Mismatched!
    with pytest.raises(ValueError, match="Transaction ID mismatch"):
        resolver._validate_upstream_response(
            spoofed_rep.pack(), expected_id, query.q.qname, query.q.qtype, client_id
        )

    # 3. Packet that is not a DNS response (QR=0)
    not_a_response = DNSRecord.question("example.com", "A")
    not_a_response.header.id = expected_id
    with pytest.raises(ValueError, match="not a DNS response"):
        resolver._validate_upstream_response(
            not_a_response.pack(), expected_id, query.q.qname, query.q.qtype, client_id
        )

    # 4. Mismatched question domain in answer
    mismatched_q = DNSRecord.question("evil.com", "A")
    mismatched_rep = mismatched_q.reply()
    mismatched_rep.header.id = expected_id
    with pytest.raises(ValueError, match="Question name mismatch"):
        resolver._validate_upstream_response(
            mismatched_rep.pack(), expected_id, query.q.qname, query.q.qtype, client_id
        )

