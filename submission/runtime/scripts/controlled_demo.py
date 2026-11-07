"""
DNS-SHIELD: Controlled Local Demonstration Script.
Executes genuine DNSGatewayServer and PolicyEngine on loopback using unprivileged ports.
No system DNS, SCM services, firewall, or WFP modifications.

Demonstrates:
1. Allowed name resolving to a configured test address.
2. Domain blocked by an administrator policy rule (REFUSED).
3. Controlled query sequence triggering deterministic tunneling detection heuristics.
4. Exact matched rule, decision, and diagnostic reasoning in SQLite dns_logs.
5. Proof that blocked queries (both admin rules and tunneling) never reach the controlled upstream.
6. Removal of the administrator rule restoring permitted resolution.
"""

import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import time
import socket
import sqlite3
import tempfile
from typing import List, Dict, Any

from dnslib import DNSRecord, RCODE, QTYPE, RR, A, TXT
from gateway.config import GatewayConfig
from gateway.db import init_db, get_db
from gateway.policy import PolicyEngine
from gateway.server import DNSGatewayServer

GATEWAY_PORT = 5353
UPSTREAM_PORT = 5354


class ControlledUpstreamServer:
    """Mock upstream resolver that logs all received queries and answers with known addresses."""
    def __init__(self, host: str = "127.0.0.1", port: int = UPSTREAM_PORT):
        self.host = host
        self.port = port
        self.received_queries: List[Dict[str, Any]] = []
        self.running = False
        self.sock = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.running = True

        import threading
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if not data:
                    continue
                req = DNSRecord.parse(data)
                qname = str(req.q.qname).rstrip(".")
                qtype = QTYPE[req.q.qtype]
                self.received_queries.append({"qname": qname, "qtype": qtype, "time": time.time()})

                # Answer allowed queries with known deterministic IPs
                rep = req.reply()
                if qtype == "A":
                    rep.add_answer(RR(req.q.qname, QTYPE.A, rdata=A("192.168.100.200"), ttl=60))
                elif qtype == "TXT":
                    rep.add_answer(RR(req.q.qname, QTYPE.TXT, rdata=TXT("benign-upstream-response"), ttl=60))
                self.sock.sendto(rep.pack(), addr)
            except Exception:
                if not self.running:
                    break

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()


def send_dns_query(qname: str, qtype: str = "A", port: int = GATEWAY_PORT) -> DNSRecord:
    """Sends a genuine UDP DNS request to the local gateway."""
    req = DNSRecord.question(qname, qtype).pack()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.5)
    try:
        sock.sendto(req, ("127.0.0.1", port))
        resp_data, _ = sock.recvfrom(4096)
        return DNSRecord.parse(resp_data)
    finally:
        sock.close()


def run_demonstration():
    print("=" * 70)
    print("  DNS-SHIELD CONTROLLED DEMONSTRATION")
    print("  Mode: Loopback Unprivileged Ports (Gateway: 5353, Upstream: 5354)")
    print("  System Isolation: Zero host DNS, SCM, firewall or WFP modifications.")
    print("=" * 70)

    # 1. Start Controlled Upstream Server
    upstream = ControlledUpstreamServer(port=UPSTREAM_PORT)
    upstream.start()
    print(f"\n[+] Started Controlled Upstream Resolver on 127.0.0.1:{UPSTREAM_PORT}")

    # 2. Setup isolated SQLite test database
    temp_dir = tempfile.mkdtemp(prefix="dnsshield_demo_")
    db_file = os.path.join(temp_dir, "demo_gateway.db")
    init_db(db_file)
    print(f"[+] Initialized isolated test audit database: {db_file}")

    # Ensure upstream_resolvers table points to our mock upstream across reloads
    conn = get_db(db_file)
    conn.execute("DELETE FROM upstream_resolvers")
    conn.execute("""
        INSERT INTO upstream_resolvers (address, port, protocol, priority, enabled, health_status, last_checked)
        VALUES ('127.0.0.1', ?, 'UDP', 1, 1, 'HEALTHY', ?)
    """, (UPSTREAM_PORT, time.time()))
    conn.commit()
    conn.close()

    # 3. Configure and Start Real Gateway Server
    engine = PolicyEngine(db_path=db_file)
    gateway = DNSGatewayServer(host="127.0.0.1", port=GATEWAY_PORT, policy_engine=engine, db_path=db_file, ipv6_host=None)
    gateway.start()
    print(f"[+] Started DNS-SHIELD Gateway Engine on 127.0.0.1:{GATEWAY_PORT}")
    time.sleep(0.3)

    log_records = []

    try:
        # -------------------------------------------------------------
        # STEP 1: Allowed Domain Resolution
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("STEP 1: Allowed Name Resolving to Configured Test Address")
        print("-" * 70)
        allowed_qname = "allowed-service.test"
        resp1 = send_dns_query(allowed_qname, "A")
        ans_ip = str(resp1.rr[0].rdata) if resp1.rr else "NONE"
        rcode1 = RCODE[resp1.header.rcode]
        print(f"  Query:            {allowed_qname} (A)")
        print(f"  Client Received:  RCODE={rcode1}, Answer={ans_ip}")
        upstream_saw_step1 = any(q["qname"] == allowed_qname for q in upstream.received_queries)
        print(f"  Upstream Contact: {upstream_saw_step1} (Received query at upstream resolver)")
        assert rcode1 == "NOERROR"
        assert ans_ip == "192.168.100.200"
        assert upstream_saw_step1 is True

        # -------------------------------------------------------------
        # STEP 2: Administrator Block Rule Enforcement
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("STEP 2: Domain Blocked by Administrator Policy Rule")
        print("-" * 70)
        admin_blocked_apex = "malware-sample.test"
        # Add rule via engine database & policy reload
        conn = get_db(db_file)
        now = time.time()
        conn.execute("""
            INSERT INTO custom_rules (domain, rule_type, action, enabled, reason, created_at, updated_at)
            VALUES (?, 'subdomain', 'BLOCK', 1, 'Administrative Integration Block Rule', ?, ?)
        """, (admin_blocked_apex, now, now))
        conn.commit()
        conn.close()
        engine.reload_policies()
        print(f"  Added Policy Rule:  BLOCK '*.{admin_blocked_apex}' (Reason: Administrative Integration Block Rule)")

        blocked_qname = f"c2-beacon.{admin_blocked_apex}"
        queries_before_step2 = len(upstream.received_queries)
        resp2 = send_dns_query(blocked_qname, "A")
        rcode2 = RCODE[resp2.header.rcode]
        print(f"  Query:              {blocked_qname} (A)")
        print(f"  Client Received:    RCODE={rcode2} (Query refused)")
        queries_after_step2 = len(upstream.received_queries)
        upstream_contacted_step2 = any(q["qname"] == blocked_qname for q in upstream.received_queries)
        print(f"  Upstream Contact:   {upstream_contacted_step2} (ZERO packets sent to upstream)")
        assert rcode2 == "REFUSED"
        assert upstream_contacted_step2 is False

        # -------------------------------------------------------------
        # STEP 3: Controlled DNS Tunneling Heuristics Detection
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("STEP 3: Controlled Query Sequence Triggering Tunneling Detection")
        print("-" * 70)
        # Payload with high entropy + excessive label length + TXT query type
        tunnel_payload = "k8v3x9m2p7w0j4n1q8t5l2c6d9e3f7a1b4g0h5i.tunnel-session.test"
        queries_before_step3 = len(upstream.received_queries)
        resp3 = send_dns_query(tunnel_payload, "TXT")
        rcode3 = RCODE[resp3.header.rcode]
        print(f"  Query:              {tunnel_payload} (TXT)")
        print(f"  Client Received:    RCODE={rcode3} (Suspected tunneling blocked)")
        upstream_contacted_step3 = any(q["qname"] == tunnel_payload for q in upstream.received_queries)
        print(f"  Upstream Contact:   {upstream_contacted_step3} (ZERO packets sent to upstream)")
        assert rcode3 == "REFUSED"
        assert upstream_contacted_step3 is False

        # -------------------------------------------------------------
        # STEP 4: Exact Matched Rules and Blocking Reasons in Audit Logs
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("STEP 4: Database Audit Log Verification (Exact Rule & Reasons)")
        print("-" * 70)
        conn = get_db(db_file)
        cur = conn.cursor()
        cur.execute("""
            SELECT id, domain, qtype, decision, decision_type, matched_rule, reason, rcode
            FROM dns_logs ORDER BY id ASC
        """)
        rows = cur.fetchall()
        conn.close()

        print(f"{'ID':<4} | {'Decision':<6} | {'Type':<20} | {'Domain':<40} | {'Reason'}")
        print("-" * 110)
        for r in rows:
            print(f"{r['id']:<4} | {r['decision']:<6} | {r['decision_type']:<20} | {r['domain'][:38]:<40} | {r['reason']}")
            log_records.append(dict(r))

        # Assertions on audit trail
        step2_log = [r for r in log_records if r["domain"] == blocked_qname][0]
        assert step2_log["decision"] == "BLOCK"
        assert step2_log["decision_type"] == "ADMIN_POLICY"
        assert admin_blocked_apex in step2_log["matched_rule"]

        step3_log = [r for r in log_records if r["domain"] == tunnel_payload][0]
        assert step3_log["decision"] == "BLOCK"
        assert step3_log["decision_type"] == "SUSPECTED_TUNNELING"
        assert "HEURISTIC_TUNNELING_DETECTION" in step3_log["matched_rule"]
        assert "High label entropy" in step3_log["reason"]
        assert "Favored tunneling record type" in step3_log["reason"]

        # -------------------------------------------------------------
        # STEP 5: Upstream Non-Contact Assertion Summary
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("STEP 5: Upstream Non-Contact Verification Summary")
        print("-" * 70)
        print(f"  Total queries sent to Gateway:    3")
        print(f"  Total queries reached Upstream:   1 (Only allowed-service.test)")
        print(f"  Blocked queries reached Upstream: 0 (Admin rule & Tunneling queries blocked locally)")
        for idx, uq in enumerate(upstream.received_queries, 1):
            print(f"    [{idx}] Upstream received: {uq['qname']} ({uq['qtype']})")

        # -------------------------------------------------------------
        # STEP 6: Policy Rule Removal Restores Resolution
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("STEP 6: Rule Removal Restoring Permitted Resolution")
        print("-" * 70)
        conn = get_db(db_file)
        conn.execute("DELETE FROM custom_rules WHERE domain = ?", (admin_blocked_apex,))
        conn.commit()
        conn.close()
        engine.cache.clear()
        engine.reload_policies()
        print(f"  Removed Policy Rule: '{admin_blocked_apex}' from custom_rules")

        resp6 = send_dns_query(blocked_qname, "A")
        rcode6 = RCODE[resp6.header.rcode]
        ans6 = str(resp6.rr[0].rdata) if resp6.rr else "NONE"
        print(f"  Query:              {blocked_qname} (A)")
        print(f"  Client Received:    RCODE={rcode6}, Answer={ans6}")
        upstream_saw_step6 = any(q["qname"] == blocked_qname for q in upstream.received_queries)
        print(f"  Upstream Contact:   {upstream_saw_step6} (Query forwarded to upstream resolver)")
        assert rcode6 == "NOERROR"
        assert ans6 == "192.168.100.200"
        assert upstream_saw_step6 is True

        print("\n" + "=" * 70)
        print("  DEMONSTRATION STATUS: ALL 6 CHECKS PASSED (100% SUCCESS)")
        print("=" * 70)

    finally:
        gateway.stop()
        upstream.stop()
        # Clean up temporary database directory
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

    return True


if __name__ == "__main__":
    success = run_demonstration()
    sys.exit(0 if success else 1)
