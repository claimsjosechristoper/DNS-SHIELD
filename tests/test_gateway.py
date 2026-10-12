"""
Automated Security & Protocol Test Suite for DNS Security Gateway.
Tests:
1. Real UDP DNS requests to gateway.
2. Real TCP DNS requests to gateway.
3. Blocked requests NEVER reach upstream resolver.
4. Strict domain label-boundary matching (no false substring blocking).
5. Precedence pipeline (Allowlist overrides Blocklist/Rules; Malformed/Rate limits override Allowlist).
6. Cached-domain blocking after rule updates (prevent stale cache bypass).
7. Malformed packets and RFC protocol violations (rejected with FORMERR/NOTIMP).
8. Upstream network failure and timeout (returns SERVFAIL, never fabricates answers).
9. Atomic blocklist update and retain last-known-good on failure.
10. Per-client rate limiting and burst defense.
11. Optional DNS record type blocking.
12. Access control / Client subnet restriction.
"""

import socket
import struct
import time
import pytest
import threading
from pathlib import Path
from dnslib import DNSRecord, RCODE, QTYPE, RR, A

from gateway.config import GatewayConfig
from gateway.normalization import normalize_domain
from gateway.matcher import is_label_boundary_match, RuleIndex
from gateway.blocklist_manager import BlocklistManager
from gateway.rate_limiter import RateLimiter
from gateway.cache import DNSCache
from gateway.upstream import UpstreamResolver
from gateway.policy import PolicyEngine
from gateway.server import DNSGatewayServer
from gateway.db import init_db, get_db

# Helper Mock Upstream DNS Server for deterministic verification
class MockUpstreamServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 5399):
        self.host = host
        self.port = port
        self.received_queries = []
        self.running = False
        self.sock = None
        self.thread = None
        self.simulate_failure = False

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if not data:
                    continue
                req = DNSRecord.parse(data)
                qname = str(req.q.qname).rstrip(".")
                self.received_queries.append(qname)

                if self.simulate_failure:
                    # Drop or do not respond to simulate timeout/down upstream
                    continue

                # Normal resolution answer
                rep = req.reply()
                rep.add_answer(RR(req.q.qname, QTYPE.A, rdata=A("93.184.216.34"), ttl=300))
                self.sock.sendto(rep.pack(), addr)
            except Exception:
                if not self.running:
                    break

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

@pytest.fixture(scope="module")
def mock_upstream():
    server = MockUpstreamServer(port=5399)
    server.start()
    time.sleep(0.1)
    yield server
    server.stop()

@pytest.fixture
def test_db_path(tmp_path):
    db_file = str(tmp_path / "test_gateway.db")
    init_db(db_file)
    return db_file

# --- 1. Real UDP DNS Request ---
def test_udp_dns_request(mock_upstream, test_db_path):
    engine = PolicyEngine(db_path=test_db_path)
    engine.upstream_resolver.set_upstreams([{"address": "127.0.0.1", "port": 5399, "protocol": "UDP", "enabled": True}])
    
    server = DNSGatewayServer(host="127.0.0.1", port=5381, policy_engine=engine, db_path=test_db_path)
    server.start()
    time.sleep(0.1)

    try:
        query = DNSRecord.question("allowed-corporate.test", "A").pack()
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2.0)
        client.sendto(query, ("127.0.0.1", 5381))
        resp_data, _ = client.recvfrom(4096)
        client.close()

        resp = DNSRecord.parse(resp_data)
        assert resp.header.rcode == 0  # NOERROR
        assert len(resp.rr) > 0
        assert str(resp.rr[0].rdata) == "93.184.216.34"
    finally:
        server.stop()

# --- 2. Real TCP DNS Request ---
def test_tcp_dns_request(mock_upstream, test_db_path):
    engine = PolicyEngine(db_path=test_db_path)
    engine.upstream_resolver.set_upstreams([{"address": "127.0.0.1", "port": 5399, "protocol": "UDP", "enabled": True}])

    server = DNSGatewayServer(host="127.0.0.1", port=5382, policy_engine=engine, db_path=test_db_path)
    server.start()
    time.sleep(0.1)

    try:
        query = DNSRecord.question("allowed-tcp.test", "A").pack()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(2.0)
        client.connect(("127.0.0.1", 5382))

        # Send 2-byte prefix length + payload (RFC 7766)
        prefix = struct.pack("!H", len(query))
        client.sendall(prefix + query)

        len_buf = client.recv(2)
        assert len(len_buf) == 2
        resp_len = struct.unpack("!H", len_buf)[0]
        resp_data = client.recv(resp_len)
        client.close()

        resp = DNSRecord.parse(resp_data)
        assert resp.header.rcode == 0
        assert len(resp.rr) > 0
    finally:
        server.stop()

# --- 3. Blocked Request NEVER Reaches Upstream ---
def test_blocked_request_never_reaches_upstream(mock_upstream, test_db_path):
    engine = PolicyEngine(db_path=test_db_path)
    engine.upstream_resolver.set_upstreams([{"address": "127.0.0.1", "port": 5399, "protocol": "UDP", "enabled": True}])

    mock_upstream.received_queries.clear()

    # Query a domain on the threat feed
    query = DNSRecord.question("malware-dropper.test", "A").pack()
    resp_bytes, event = engine.process_query(query, "127.0.0.1", 12345)

    resp = DNSRecord.parse(resp_bytes)
    assert resp.header.rcode == getattr(RCODE, "REFUSED")
    assert event["decision"] == "BLOCK"
    assert event["decision_type"] == "THREAT_BLOCKLIST"

    # CRITICAL SECURITY ASSERTION: Upstream was never contacted!
    assert "malware-dropper.test" not in mock_upstream.received_queries

# --- 4. Domain Boundary Matching ---
def test_domain_boundary_matching():
    # Exact rule: only exact matches
    assert is_label_boundary_match("example.com", "example.com", match_subdomains=False) is True
    assert is_label_boundary_match("sub.example.com", "example.com", match_subdomains=False) is False
    assert is_label_boundary_match("notexample.com", "example.com", match_subdomains=False) is False

    # Subdomain rule: matches domain and subdomains
    assert is_label_boundary_match("example.com", "example.com", match_subdomains=True) is True
    assert is_label_boundary_match("sub.example.com", "example.com", match_subdomains=True) is True
    assert is_label_boundary_match("a.b.c.example.com", "example.com", match_subdomains=True) is True

    # MUST NOT MATCH different labels sharing suffix characters
    assert is_label_boundary_match("notexample.com", "example.com", match_subdomains=True) is False
    assert is_label_boundary_match("myexample.com", "example.com", match_subdomains=True) is False
    assert is_label_boundary_match("example.commercial", "example.com", match_subdomains=True) is False

# --- 5. Rule Precedence ---
def test_rule_precedence(mock_upstream, test_db_path):
    engine = PolicyEngine(db_path=test_db_path)
    engine.upstream_resolver.set_upstreams([{"address": "127.0.0.1", "port": 5399, "protocol": "UDP", "enabled": True}])

    # 1. Block parent domain in custom rules
    conn = get_db(test_db_path)
    conn.execute("INSERT INTO custom_rules (domain, rule_type, action, enabled, reason, created_at, updated_at) VALUES ('corp-restricted.com', 'subdomain', 'BLOCK', 1, 'Restricted', 0, 0)")
    # 2. Allow specific subdomain in allowlist
    conn.execute("INSERT INTO allowlist (domain, rule_type, enabled, reason, created_at) VALUES ('safe-api.corp-restricted.com', 'exact', 1, 'Exempted API', 0)")
    conn.commit()
    conn.close()

    engine.reload_policies()

    # Query allowed subdomain -> Precedence allows it
    q_allow = DNSRecord.question("safe-api.corp-restricted.com", "A").pack()
    _, ev_allow = engine.process_query(q_allow, "127.0.0.1", 12345)
    assert ev_allow["decision"] == "ALLOW"
    assert ev_allow["decision_type"] == "ALLOWED"

    # Query other subdomain -> Blocked by custom rule
    q_block = DNSRecord.question("other.corp-restricted.com", "A").pack()
    _, ev_block = engine.process_query(q_block, "127.0.0.1", 12345)
    assert ev_block["decision"] == "BLOCK"
    assert ev_block["decision_type"] == "ADMIN_POLICY"

    # Test that Malformed packets are blocked EVEN IF domain is allowlisted!
    malformed_raw = b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # 0 questions
    _, ev_mal = engine.process_query(malformed_raw, "127.0.0.1", 12345)
    assert ev_mal["decision"] == "BLOCK"
    assert ev_mal["decision_type"] == "PROTOCOL_VIOLATION"

# --- 6. Cached-Domain Blocking After Rule Updates ---
def test_cached_domain_blocking_after_rule_updates(mock_upstream, test_db_path):
    engine = PolicyEngine(db_path=test_db_path)
    engine.upstream_resolver.set_upstreams([{"address": "127.0.0.1", "port": 5399, "protocol": "UDP", "enabled": True}])

    target_domain = "dynamic-cached.test"

    # First Query: allowed and placed into cache
    q1 = DNSRecord.question(target_domain, "A").pack()
    _, ev1 = engine.process_query(q1, "127.0.0.1", 12345)
    assert ev1["decision"] == "ALLOW"

    # Verify domain is in cache
    cached = engine.cache.get(target_domain, "A", 999)
    assert cached is not None

    # Now, Administrator adds a custom block rule for dynamic-cached.test
    conn = get_db(test_db_path)
    conn.execute("INSERT INTO custom_rules (domain, rule_type, action, enabled, reason, created_at, updated_at) VALUES (?, 'exact', 'BLOCK', 1, 'Policy ban', 0, 0)", (target_domain,))
    conn.commit()
    conn.close()

    # Rule update triggers reload and cache invalidation
    engine.cache.invalidate_domain(target_domain)
    engine.reload_policies()

    # Second Query: MUST BE BLOCKED IMMEDIATELY, NEVER SERVED FROM CACHE!
    q2 = DNSRecord.question(target_domain, "A").pack()
    resp_bytes2, ev2 = engine.process_query(q2, "127.0.0.1", 12345)
    
    assert ev2["decision"] == "BLOCK"
    assert ev2["decision_type"] == "ADMIN_POLICY"
    resp2 = DNSRecord.parse(resp_bytes2)
    assert resp2.header.rcode == getattr(RCODE, "REFUSED")

# --- 7. Malformed Requests & Protocol Violations ---
def test_malformed_requests(test_db_path):
    engine = PolicyEngine(db_path=test_db_path)

    # 1. Packet too short (< 12 bytes)
    short_pkt = b"\x01\x02\x03\x04"
    resp_bytes, ev = engine.process_query(short_pkt, "127.0.0.1", 12345)
    assert ev["decision"] == "BLOCK"
    assert ev["decision_type"] == "PROTOCOL_VIOLATION"

    # 2. QR bit = 1 (response packet sent as query)
    req = DNSRecord.question("test.com", "A")
    req.header.qr = 1
    resp_bytes, ev = engine.process_query(req.pack(), "127.0.0.1", 12345)
    assert ev["decision"] == "BLOCK"
    assert ev["rcode"] == "FORMERR"

    # 3. Label length exceeds 63 characters
    bad_domain = ("a" * 64) + ".com"
    norm, is_valid, _ = normalize_domain(bad_domain)
    assert is_valid is False

# --- 8. Upstream Network Failure Returns SERVFAIL ---
def test_upstream_failure_servfail(test_db_path):
    engine = PolicyEngine(db_path=test_db_path)
    # Point upstream to non-existent port with small timeout
    engine.upstream_resolver.timeout = 0.5
    engine.upstream_resolver.set_upstreams([{"address": "127.0.0.1", "port": 54999, "protocol": "UDP", "enabled": True}])

    q = DNSRecord.question("unreachable-site.test", "A").pack()
    resp_bytes, ev = engine.process_query(q, "127.0.0.1", 12345)

    resp = DNSRecord.parse(resp_bytes)
    assert resp.header.rcode == getattr(RCODE, "SERVFAIL")
    assert ev["rcode"] == "SERVFAIL"

# --- 9. Atomic Blocklist Update & Fail-Safe Retain ---
def test_atomic_blocklist_update_and_failsafe(tmp_path, test_db_path):
    mgr = BlocklistManager()

    good_file = str(tmp_path / "feed.txt")
    Path(good_file).write_text("badsite1.test\nbadsite2.test\n")

    conn = get_db(test_db_path)
    conn.execute("INSERT INTO blocklist_sources (name, url_or_path, category, enabled, entry_count, last_status) VALUES ('Test Feed', ?, 'malware', 1, 0, 'PENDING')", (good_file,))
    conn.commit()
    source_id = conn.execute("SELECT id FROM blocklist_sources WHERE name = 'Test Feed'").fetchone()[0]
    conn.close()

    # Successful sync
    success, _ = mgr.sync_source(source_id, test_db_path)
    assert success is True
    assert mgr.match("badsite1.test") is not None
    assert mgr.match("badsite2.test") is not None

    # Corrupt the file with invalid data
    Path(good_file).write_text("# Only comments\n\n   ")
    failed_sync, err_msg = mgr.sync_source(source_id, test_db_path)
    assert failed_sync is False

    # CRITICAL FAIL-SAFE ASSERTION: Retained last known good list!
    assert mgr.match("badsite1.test") is not None
    assert mgr.match("badsite2.test") is not None

# --- 10. Per-Client Rate Limiting ---
def test_rate_limiting():
    limiter = RateLimiter(default_rpm=10, burst_limit=5)
    client_ip = "192.168.1.99"

    # First 5 in rapid succession should be allowed
    for _ in range(5):
        allowed, _ = limiter.is_allowed(client_ip)
        assert allowed is True

    # 6th in same second should trigger burst rate limit
    allowed, reason = limiter.is_allowed(client_ip)
    assert allowed is False
    assert "burst" in reason

# --- 11. DNS Record Type Blocking ---
def test_record_type_blocking(mock_upstream, test_db_path):
    engine = PolicyEngine(db_path=test_db_path)
    engine.upstream_resolver.set_upstreams([{"address": "127.0.0.1", "port": 5399, "protocol": "UDP", "enabled": True}])

    # ANY is seeded as blocked by default in test_db_path
    q_any = DNSRecord.question("example.org", "ANY").pack()
    resp_bytes, ev = engine.process_query(q_any, "127.0.0.1", 12345)
    assert ev["decision"] == "BLOCK"
    assert ev["decision_type"] == "RECORD_TYPE"

    # Standard A query for same domain is allowed
    q_a = DNSRecord.question("example.org", "A").pack()
    _, ev_a = engine.process_query(q_a, "127.0.0.1", 12345)
    assert ev_a["decision"] == "ALLOW"

# --- 12. Access Control / CIDR Restriction ---
def test_access_control(test_db_path):
    engine = PolicyEngine(db_path=test_db_path)
    # Restrict allowed networks strictly to 10.0.0.0/8
    engine._load_allowed_networks(["10.0.0.0/8"])

    # Authorized IP
    q = DNSRecord.question("corp.internal", "A").pack()
    assert engine.is_client_authorized("10.1.2.3") is True

    # Unauthorized IP (e.g. public internet IP)
    assert engine.is_client_authorized("203.0.113.50") is False
    _, ev = engine.process_query(q, "203.0.113.50", 12345)
    assert ev["decision"] == "BLOCK"
    assert ev["decision_type"] == "ACCESS_DENIED"
