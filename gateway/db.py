"""
SQLite Database Layer for DNS Security Gateway.
Manages persistent storage for DNS query audit logs, administrative custom rules,
allowlists, threat blocklist feeds, upstream resolvers, and configuration settings.
"""

import sqlite3
import time
import json
import os
import threading
from typing import Dict, Any, List, Optional, Tuple
from gateway.config import GatewayConfig, BLOCKLISTS_DIR

_db_lock = threading.Lock()

def get_db(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Returns a SQLite connection configured with WAL journal mode and Row factory."""
    path = db_path or GatewayConfig.DB_PATH
    conn = sqlite3.connect(path, check_same_thread=False, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

def init_db(db_path: Optional[str] = None):
    """Initializes tables, indexes, and default configurations if not present."""
    with _db_lock:
        conn = get_db(db_path)
        cur = conn.cursor()
        
        # 1. DNS Query Logs (Deterministic ALLOW/BLOCK, zero risk scoring)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS dns_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            client_ip TEXT NOT NULL,
            domain TEXT NOT NULL,
            qtype TEXT NOT NULL,
            decision TEXT NOT NULL, -- ALLOW or BLOCK
            decision_type TEXT NOT NULL, -- THREAT_BLOCKLIST, ADMIN_POLICY, RECORD_TYPE, RATE_LIMIT, ACCESS_DENIED, PROTOCOL_VIOLATION, ALLOWED
            matched_rule TEXT,
            reason TEXT,
            rcode TEXT NOT NULL,
            response_time_ms REAL DEFAULT 0.0,
            upstream_server TEXT
        );
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_dns_logs_timestamp ON dns_logs(timestamp DESC);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_dns_logs_decision ON dns_logs(decision);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_dns_logs_domain ON dns_logs(domain);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_dns_logs_client ON dns_logs(client_ip);")

        # 2. Administrator Custom Blocking Rules
        cur.execute("""
        CREATE TABLE IF NOT EXISTS custom_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            rule_type TEXT NOT NULL DEFAULT 'subdomain', -- exact or subdomain
            action TEXT NOT NULL DEFAULT 'BLOCK',
            enabled INTEGER NOT NULL DEFAULT 1,
            reason TEXT,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        """)

        # 3. Administrator Allowlist (Overrides blocklists and custom blocks)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS allowlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            rule_type TEXT NOT NULL DEFAULT 'subdomain', -- exact or subdomain
            enabled INTEGER NOT NULL DEFAULT 1,
            reason TEXT,
            created_at REAL NOT NULL
        );
        """)

        # 4. Blocked DNS Record Types (e.g. ANY, TXT, etc.)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS blocked_record_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            qtype TEXT UNIQUE NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            reason TEXT,
            created_at REAL NOT NULL
        );
        """)

        # 5. Threat Blocklist Feed Sources
        cur.execute("""
        CREATE TABLE IF NOT EXISTS blocklist_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            url_or_path TEXT NOT NULL,
            category TEXT NOT NULL, -- malware, phishing, c2, policy
            enabled INTEGER NOT NULL DEFAULT 1,
            entry_count INTEGER NOT NULL DEFAULT 0,
            last_updated REAL,
            last_status TEXT DEFAULT 'PENDING',
            last_error TEXT
        );
        """)

        # 6. Blocklist Raw Domain Entries
        cur.execute("""
        CREATE TABLE IF NOT EXISTS blocklist_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            FOREIGN KEY (source_id) REFERENCES blocklist_sources(id) ON DELETE CASCADE
        );
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_blocklist_entries_domain ON blocklist_entries(domain);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_blocklist_entries_source ON blocklist_entries(source_id);")

        # 7. Upstream DNS Resolvers
        cur.execute("""
        CREATE TABLE IF NOT EXISTS upstream_resolvers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 53,
            protocol TEXT NOT NULL DEFAULT 'UDP',
            priority INTEGER NOT NULL DEFAULT 1,
            enabled INTEGER NOT NULL DEFAULT 1,
            health_status TEXT NOT NULL DEFAULT 'HEALTHY',
            last_latency_ms REAL DEFAULT 0.0,
            last_checked REAL
        );
        """)

        # 8. Rate Limits
        cur.execute("""
        CREATE TABLE IF NOT EXISTS rate_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_ip_or_subnet TEXT UNIQUE NOT NULL,
            requests_per_minute INTEGER NOT NULL DEFAULT 600,
            burst_limit INTEGER NOT NULL DEFAULT 60,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL
        );
        """)

        # 9. Administrative Audit Trail
        cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT,
            details_json TEXT
        );
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);")

        # 10. Gateway Key-Value Settings
        cur.execute("""
        CREATE TABLE IF NOT EXISTS gateway_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """)

        # Seed initial default configurations if empty
        _seed_defaults(cur)

        conn.commit()
        conn.close()

def _seed_defaults(cur: sqlite3.Cursor):
    # Seed default blocklist sources
    cur.execute("SELECT COUNT(*) FROM blocklist_sources;")
    if cur.fetchone()[0] == 0:
        now = time.time()
        cur.execute("""
            INSERT INTO blocklist_sources (name, url_or_path, category, enabled, entry_count, last_updated, last_status)
            VALUES 
            ('Malware & Ransomware Feed', ?, 'malware', 1, 0, ?, 'INITIAL'),
            ('Phishing & Credential Harvesters', ?, 'phishing', 1, 0, ?, 'INITIAL'),
            ('Command & Control (C2) Infrastructure', ?, 'c2', 1, 0, ?, 'INITIAL')
        """, (
            str(BLOCKLISTS_DIR / "malware_domains.txt"), now,
            str(BLOCKLISTS_DIR / "phishing_domains.txt"), now,
            str(BLOCKLISTS_DIR / "c2_domains.txt"), now
        ))

    # Seed default blocked record types (e.g. ANY query amplification mitigation)
    cur.execute("SELECT COUNT(*) FROM blocked_record_types;")
    if cur.fetchone()[0] == 0:
        cur.execute("""
            INSERT INTO blocked_record_types (qtype, enabled, reason, created_at)
            VALUES ('ANY', 1, 'RFC 8482 ANY query mitigation / DDoS amplification defense', ?)
        """, (time.time(),))

    # Seed default upstream resolvers
    cur.execute("SELECT COUNT(*) FROM upstream_resolvers;")
    if cur.fetchone()[0] == 0:
        cur.execute("""
            INSERT INTO upstream_resolvers (address, port, protocol, priority, enabled, health_status, last_checked)
            VALUES 
            ('1.1.1.1', 53, 'UDP', 1, 1, 'HEALTHY', ?),
            ('8.8.8.8', 53, 'UDP', 2, 1, 'HEALTHY', ?),
            ('9.9.9.9', 53, 'UDP', 3, 1, 'HEALTHY', ?)
        """, (time.time(), time.time(), time.time()))

    # Seed default custom rules
    cur.execute("SELECT COUNT(*) FROM custom_rules;")
    if cur.fetchone()[0] == 0:
        now = time.time()
        cur.execute("""
            INSERT INTO custom_rules (domain, rule_type, action, enabled, reason, created_at, updated_at)
            VALUES 
            ('internal-prohibited.local', 'subdomain', 'BLOCK', 1, 'Corporate security policy: unauthorized internal protocol', ?, ?),
            ('crypto-mining.pool.test', 'subdomain', 'BLOCK', 1, 'Administrative policy: unauthorized cryptocurrency miner', ?, ?)
        """, (now, now, now, now))

    # Seed default allowlist
    cur.execute("SELECT COUNT(*) FROM allowlist;")
    if cur.fetchone()[0] == 0:
        now = time.time()
        cur.execute("""
            INSERT INTO allowlist (domain, rule_type, enabled, reason, created_at)
            VALUES 
            ('trusted-partner.example.com', 'subdomain', 1, 'Authorized partner API endpoint', ?),
            ('connectivitycheck.gstatic.com', 'exact', 1, 'Network connectivity check', ?)
        """, (now, now))

    # Seed default gateway settings
    defaults = {
        "blocked_response_rcode": GatewayConfig.DEFAULT_BLOCKED_RCODE,
        "dns_host": GatewayConfig.DNS_HOST,
        "dns_port": str(GatewayConfig.DNS_PORT),
        "log_retention_days": str(GatewayConfig.LOG_RETENTION_DAYS),
        "allowed_networks": ",".join(GatewayConfig.ALLOWED_NETWORKS),
        "rate_limit_rpm": str(GatewayConfig.RATE_LIMIT_RPM),
        "rate_limit_burst": str(GatewayConfig.RATE_LIMIT_BURST)
    }
    for k, v in defaults.items():
        cur.execute("INSERT OR IGNORE INTO gateway_settings (key, value) VALUES (?, ?);", (k, v))

# Database Helper Functions

def log_dns_query(event: Dict[str, Any], db_path: Optional[str] = None) -> int:
    """Inserts a DNS query decision log into SQLite."""
    with _db_lock:
        conn = get_db(db_path)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO dns_logs 
            (timestamp, client_ip, domain, qtype, decision, decision_type, matched_rule, reason, rcode, response_time_ms, upstream_server)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("timestamp", time.time()),
            event.get("client_ip", "127.0.0.1"),
            event.get("domain", ""),
            event.get("qtype", "A"),
            event.get("decision", "ALLOW"),
            event.get("decision_type", "ALLOWED"),
            event.get("matched_rule", ""),
            event.get("reason", ""),
            event.get("rcode", "NOERROR"),
            event.get("response_time_ms", 0.0),
            event.get("upstream_server", "")
        ))
        row_id = cur.lastrowid
        conn.commit()
        conn.close()
        return row_id

def get_dns_logs(
    limit: int = 100,
    offset: int = 0,
    decision: Optional[str] = None,
    decision_type: Optional[str] = None,
    search_domain: Optional[str] = None,
    client_ip: Optional[str] = None,
    qtype: Optional[str] = None,
    db_path: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], int]:
    """Retrieves paginated and filtered DNS logs."""
    conn = get_db(db_path)
    cur = conn.cursor()
    
    conditions = []
    params = []

    if decision:
        conditions.append("decision = ?")
        params.append(decision.upper())
    if decision_type:
        conditions.append("decision_type = ?")
        params.append(decision_type)
    if search_domain:
        conditions.append("domain LIKE ?")
        params.append(f"%{search_domain.lower()}%")
    if client_ip:
        conditions.append("client_ip = ?")
        params.append(client_ip)
    if qtype:
        conditions.append("qtype = ?")
        params.append(qtype.upper())

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    count_query = f"SELECT COUNT(*) FROM dns_logs {where_clause}"
    cur.execute(count_query, params)
    total_count = cur.fetchone()[0]

    data_query = f"""
        SELECT id, timestamp, client_ip, domain, qtype, decision, decision_type, matched_rule, reason, rcode, response_time_ms, upstream_server
        FROM dns_logs {where_clause}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """
    cur.execute(data_query, params + [limit, offset])
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows, total_count

def get_dashboard_statistics(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Generates statistics for the dashboard without risk scoring."""
    conn = get_db(db_path)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM dns_logs")
    total_requests = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM dns_logs WHERE decision = 'ALLOW'")
    allowed_requests = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM dns_logs WHERE decision = 'BLOCK'")
    blocked_requests = cur.fetchone()[0]

    # Recent blocking activity (last 10 blocked)
    cur.execute("""
        SELECT id, timestamp, client_ip, domain, qtype, decision, decision_type, matched_rule, reason, rcode
        FROM dns_logs WHERE decision = 'BLOCK'
        ORDER BY timestamp DESC LIMIT 10
    """)
    recent_blocked = [dict(r) for r in cur.fetchall()]

    # Most frequently blocked domains
    cur.execute("""
        SELECT domain, COUNT(*) as count, decision_type, matched_rule
        FROM dns_logs WHERE decision = 'BLOCK'
        GROUP BY domain ORDER BY count DESC LIMIT 8
    """)
    top_blocked_domains = [dict(r) for r in cur.fetchall()]

    # Breakdown by decision_type
    cur.execute("""
        SELECT decision_type, COUNT(*) as count
        FROM dns_logs GROUP BY decision_type ORDER BY count DESC
    """)
    decision_type_counts = {r["decision_type"]: r["count"] for r in cur.fetchall()}

    # Resolver health
    cur.execute("SELECT address, port, protocol, priority, enabled, health_status, last_latency_ms FROM upstream_resolvers")
    upstreams = [dict(r) for r in cur.fetchall()]

    # Blocklist update status
    cur.execute("SELECT id, name, category, enabled, entry_count, last_updated, last_status, last_error FROM blocklist_sources")
    blocklists = [dict(r) for r in cur.fetchall()]

    total_blocklist_entries = sum(b.get("entry_count", 0) for b in blocklists if b.get("enabled", 1))

    conn.close()

    return {
        "total_requests": total_requests,
        "allowed_requests": allowed_requests,
        "blocked_requests": blocked_requests,
        "decision_type_breakdown": decision_type_counts,
        "recent_blocking_activity": recent_blocked,
        "most_frequently_blocked_domains": top_blocked_domains,
        "upstream_resolvers": upstreams,
        "blocklist_sources": blocklists,
        "total_blocklist_rules": total_blocklist_entries,
        "resolver_health": "ONLINE" if any(u.get("health_status") == "HEALTHY" for u in upstreams) else "DEGRADED"
    }

def record_audit(
    username: str,
    action: str,
    target_type: str,
    target_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    db_path: Optional[str] = None
):
    """Appends an administrative audit trail record."""
    with _db_lock:
        conn = get_db(db_path)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO audit_logs (timestamp, username, action, target_type, target_id, details_json)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            time.time(),
            username,
            action,
            target_type,
            target_id or "",
            json.dumps(details or {})
        ))
        conn.commit()
        conn.close()

def get_audit_logs(limit: int = 100, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves recent audit log records."""
    conn = get_db(db_path)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, timestamp, username, action, target_type, target_id, details_json
        FROM audit_logs ORDER BY timestamp DESC LIMIT ?
    """, (limit,))
    logs = []
    for r in cur.fetchall():
        item = dict(r)
        try:
            item["details"] = json.loads(item["details_json"]) if item["details_json"] else {}
        except Exception:
            item["details"] = {}
        logs.append(item)
    conn.close()
    return logs

def prune_old_logs(retention_days: int, db_path: Optional[str] = None) -> int:
    """Deletes DNS query logs older than the specified retention window."""
    with _db_lock:
        conn = get_db(db_path)
        cur = conn.cursor()
        cutoff = time.time() - (retention_days * 86400)
        cur.execute("DELETE FROM dns_logs WHERE timestamp < ?", (cutoff,))
        deleted_count = cur.rowcount
        conn.commit()
        conn.close()
        return deleted_count
