"""
Legacy Telemetry Migration Script.
Safely migrates historical records from data/events/dns_events.jsonl into the
deterministic SQLite database (dns_logs table).
Converts legacy records into explicit ALLOW/BLOCK verdicts and purges all risk scores,
severity percentages, and probabilistic indices from the active workflow.
Preserves the original JSONL archive safely on disk.
"""

import os
import sys
import json
import sqlite3
import argparse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from gateway.config import GatewayConfig
from gateway.normalization import normalize_domain
from gateway.db import init_db, get_db

def migrate_legacy_events(dry_run: bool = False, max_records: int = 5000):
    jsonl_path = BASE_DIR / "data" / "events" / "dns_events.jsonl"
    if not jsonl_path.exists():
        print(f"[-] No legacy file found at {jsonl_path}")
        return

    init_db(GatewayConfig.DB_PATH)
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM dns_logs")
    existing_count = cur.fetchone()[0]
    print(f"[*] SQLite database currently contains {existing_count} DNS logs.")

    migrated_count = 0
    skipped_count = 0

    print(f"[*] Reading legacy events from {jsonl_path}...")
    with open(jsonl_path, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            if migrated_count >= max_records:
                break
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except Exception:
                skipped_count += 1
                continue

            qname = item.get("qname", "")
            norm, is_valid, _ = normalize_domain(qname)
            if not is_valid:
                norm = qname.lower().strip(".")

            ts = item.get("timestamp", 0.0)
            src_ip = item.get("src_ip", "127.0.0.1")
            qtype = item.get("qtype", "A")

            # Deterministic conversion without risk scores:
            # If domain contains lab tunnel or was classified suspicious, convert to BLOCK under policy
            status = str(item.get("status", "")).upper()
            classification = str(item.get("classification", "")).upper()
            is_tunnel = "dnsshield.local" in norm or "tunnel" in norm or status == "SUSPICIOUS" or classification in ("MEDIUM", "HIGH", "CRITICAL")

            if is_tunnel:
                decision = "BLOCK"
                decision_type = "ADMIN_POLICY"
                matched_rule = "LEGACY_POLICY:UNAUTHORIZED_TUNNEL"
                reason = "Domain matched administrator policy against unauthorized protocol encapsulation"
                rcode = "REFUSED"
            else:
                decision = "ALLOW"
                decision_type = "ALLOWED"
                matched_rule = "DEFAULT_POLICY"
                reason = "Benign query permitted by gateway baseline policy"
                rcode = "NOERROR"

            if not dry_run:
                cur.execute("""
                    INSERT INTO dns_logs 
                    (timestamp, client_ip, domain, qtype, decision, decision_type, matched_rule, reason, rcode, response_time_ms, upstream_server)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1.2, 'UPSTREAM')
                """, (ts, src_ip, norm, qtype, decision, decision_type, matched_rule, reason, rcode))

            migrated_count += 1

    if not dry_run:
        conn.commit()
    conn.close()

    action = "Dry run: would have migrated" if dry_run else "Successfully migrated"
    print(f"[+] {action} {migrated_count} records into SQLite database.")
    print(f"[*] Skipped/corrupted lines: {skipped_count}")
    print(f"[*] Original JSONL file safely preserved at: {jsonl_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate legacy DNS events to SQLite")
    parser.add_argument("--dry-run", action="store_true", help="Simulate migration without modifying DB")
    parser.add_argument("--max", type=int, default=5000, help="Max records to migrate")
    args = parser.parse_args()

    migrate_legacy_events(dry_run=args.dry_run, max_records=args.max)
