"""
FastAPI Backend Application for DNS Security Gateway.
Provides authenticated REST APIs, real-time WebSocket telemetry, rule management,
blocklist synchronization, upstream configuration, and audit logging.
"""

import os
import sys
import time
import asyncio
import logging
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Query, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field

from gateway.config import GatewayConfig
from gateway.normalization import normalize_domain
from gateway.policy import PolicyEngine
from gateway.db import (
    init_db, get_db, get_dns_logs, get_dashboard_statistics,
    record_audit, get_audit_logs, prune_old_logs
)
from gateway.upstream import UpstreamResolver
from api.auth import verify_admin_key

logger = logging.getLogger("DNSShield.API")

# Initialize SQLite database schema
init_db(GatewayConfig.DB_PATH)

# Initialize Global Policy Engine
policy_engine = PolicyEngine(db_path=GatewayConfig.DB_PATH)

app = FastAPI(
    title="DNS Security Gateway API",
    description="Deterministic ALLOW/BLOCK DNS Security Gateway & Threat Management Platform",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

# Hook event listener from policy engine to broadcast over WebSocket
def broadcast_dns_event(event: Dict[str, Any]):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(ws_manager.broadcast({"type": "DNS_EVENT", "data": event}))
    except Exception:
        pass

policy_engine.set_event_listener(broadcast_dns_event)

# Pydantic Request Models
class LoginRequest(BaseModel):
    api_key: str = Field(..., description="Administrative API Key")

class CustomRuleCreate(BaseModel):
    domain: str = Field(..., description="Domain name (e.g. malicious-portal.test)")
    rule_type: str = Field("subdomain", description="'exact' or 'subdomain'")
    reason: Optional[str] = Field("Administrative policy block", description="Reason for blocking")

class AllowlistCreate(BaseModel):
    domain: str = Field(..., description="Domain to permit (e.g. partner-api.com)")
    rule_type: str = Field("subdomain", description="'exact' or 'subdomain'")
    reason: Optional[str] = Field("Explicit administrative exemption", description="Reason for allowlist entry")

class RecordTypeCreate(BaseModel):
    qtype: str = Field(..., description="DNS record type to block (e.g. ANY, TXT, NULL)")
    reason: Optional[str] = Field("Prohibited DNS query type", description="Reason")

class BlocklistSourceCreate(BaseModel):
    name: str = Field(..., description="Human-readable feed title")
    url_or_path: str = Field(..., description="Local filepath or remote HTTPS URL")
    category: str = Field("malware", description="'malware', 'phishing', 'c2', or 'policy'")

class UpstreamCreate(BaseModel):
    address: str = Field(..., description="Upstream IP address (e.g. 1.1.1.1)")
    port: int = Field(53, ge=1, le=65535, description="Port")
    protocol: str = Field("UDP", description="'UDP' or 'TCP'")
    priority: int = Field(1, ge=1, description="Priority ordering")

class UpstreamTestRequest(BaseModel):
    address: str
    port: int = 53
    protocol: str = "UDP"

class SettingsUpdateRequest(BaseModel):
    blocked_response_rcode: Optional[str] = None
    log_retention_days: Optional[int] = None
    allowed_networks: Optional[str] = None
    rate_limit_rpm: Optional[int] = None
    rate_limit_burst: Optional[int] = None

class PruneLogsRequest(BaseModel):
    retention_days: Optional[int] = None

# Public / Telemetry Endpoints

@app.get("/api/status")
def get_status():
    """Returns overall health, listener configuration, and query counts."""
    stats = get_dashboard_statistics(GatewayConfig.DB_PATH)
    return {
        "status": "ONLINE",
        "system": "DNS Security Gateway",
        "timestamp": time.time(),
        "dns_gateway_listener": f"{GatewayConfig.DNS_HOST}:{GatewayConfig.DNS_PORT}",
        "total_requests": stats["total_requests"],
        "allowed_requests": stats["allowed_requests"],
        "blocked_requests": stats["blocked_requests"],
        "resolver_health": stats["resolver_health"],
        "total_blocklist_rules": stats["total_blocklist_rules"],
        "privacy_mode_active": False
    }

@app.get("/api/dns/statistics")
def get_dns_statistics():
    """Returns metrics for dashboard charts and counters without risk scoring."""
    stats = get_dashboard_statistics(GatewayConfig.DB_PATH)
    return {
        "total_queries": stats["total_requests"],
        "allowed_queries": stats["allowed_requests"],
        "blocked_queries": stats["blocked_requests"],
        "decision_types": stats["decision_type_breakdown"],
        "top_blocked_domains": stats["most_frequently_blocked_domains"],
        "recent_blocking": stats["recent_blocking_activity"],
        "resolver_health": stats["resolver_health"]
    }

@app.get("/api/dns/logs")
def get_logs(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    decision: Optional[str] = Query(None, description="'ALLOW' or 'BLOCK'"),
    decision_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    client_ip: Optional[str] = Query(None),
    qtype: Optional[str] = Query(None)
):
    """Retrieves paginated, filtered DNS query audit logs."""
    logs, total = get_dns_logs(
        limit=limit,
        offset=offset,
        decision=decision,
        decision_type=decision_type,
        search_domain=search,
        client_ip=client_ip,
        qtype=qtype,
        db_path=GatewayConfig.DB_PATH
    )
    return {"total": total, "limit": limit, "offset": offset, "logs": logs}

@app.get("/api/dns/latest")
def get_dns_latest():
    """Returns most recent DNS query log."""
    logs, _ = get_dns_logs(limit=1, db_path=GatewayConfig.DB_PATH)
    if not logs:
        return {"message": "No DNS queries recorded yet."}
    return logs[0]

# Authentication Endpoints

@app.post("/api/auth/login")
def login_admin(req: LoginRequest):
    """Authenticates administrator with API key."""
    if req.api_key == GatewayConfig.ADMIN_API_KEY:
        record_audit("admin", "LOGIN_SUCCESS", "AUTH", None, {"ip": "client"}, GatewayConfig.DB_PATH)
        return {
            "status": "SUCCESS",
            "token": GatewayConfig.ADMIN_API_KEY,
            "username": GatewayConfig.ADMIN_USERNAME
        }
    record_audit("anonymous", "LOGIN_FAILED", "AUTH", None, {}, GatewayConfig.DB_PATH)
    raise HTTPException(status_code=401, detail="Invalid administrative API Key.")

@app.get("/api/auth/verify")
def verify_session(admin: str = Depends(verify_admin_key)):
    """Validates active administrative token."""
    return {"status": "AUTHENTICATED", "username": admin}

# Administrative Management Endpoints (Protected)

# --- 1. Custom Blocking Rules ---
@app.get("/api/rules/custom")
def list_custom_rules(admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, domain, rule_type, action, enabled, reason, created_at, updated_at FROM custom_rules ORDER BY id DESC")
    rules = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rules

@app.post("/api/rules/custom")
def create_custom_rule(rule: CustomRuleCreate, admin: str = Depends(verify_admin_key)):
    norm, is_valid, err = normalize_domain(rule.domain)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Invalid domain syntax: {err}")

    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    now = time.time()
    try:
        cur.execute("""
            INSERT INTO custom_rules (domain, rule_type, action, enabled, reason, created_at, updated_at)
            VALUES (?, ?, 'BLOCK', 1, ?, ?, ?)
        """, (norm, rule.rule_type, rule.reason, now, now))
        rule_id = cur.lastrowid
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Rule creation error (domain may already exist): {e}")
    conn.close()

    # Invalidate cache and reload policy engine immediately without restart
    policy_engine.cache.invalidate_domain(norm)
    policy_engine.reload_policies()
    record_audit(admin, "CREATE_CUSTOM_RULE", "RULE", str(rule_id), {"domain": norm, "reason": rule.reason}, GatewayConfig.DB_PATH)
    return {"status": "SUCCESS", "id": rule_id, "domain": norm}

@app.delete("/api/rules/custom/{rule_id}")
def delete_custom_rule(rule_id: int, admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Rule not found")
    conn.commit()
    conn.close()

    policy_engine.reload_policies()
    record_audit(admin, "DELETE_CUSTOM_RULE", "RULE", str(rule_id), {}, GatewayConfig.DB_PATH)
    return {"status": "SUCCESS", "deleted_id": rule_id}

@app.put("/api/rules/custom/{rule_id}/toggle")
def toggle_custom_rule(rule_id: int, admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE custom_rules SET enabled = 1 - enabled, updated_at = ? WHERE id = ?", (time.time(), rule_id))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Rule not found")
    conn.commit()
    conn.close()

    policy_engine.reload_policies()
    record_audit(admin, "TOGGLE_CUSTOM_RULE", "RULE", str(rule_id), {}, GatewayConfig.DB_PATH)
    return {"status": "SUCCESS"}

# --- 2. Allowlist ---
@app.get("/api/rules/allowlist")
def list_allowlist(admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, domain, rule_type, enabled, reason, created_at FROM allowlist ORDER BY id DESC")
    rules = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rules

@app.post("/api/rules/allowlist")
def create_allowlist_entry(rule: AllowlistCreate, admin: str = Depends(verify_admin_key)):
    norm, is_valid, err = normalize_domain(rule.domain)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Invalid domain syntax: {err}")

    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    now = time.time()
    try:
        cur.execute("""
            INSERT INTO allowlist (domain, rule_type, enabled, reason, created_at)
            VALUES (?, ?, 1, ?, ?)
        """, (norm, rule.rule_type, rule.reason, now))
        rule_id = cur.lastrowid
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Allowlist entry error (domain may already exist): {e}")
    conn.close()

    policy_engine.reload_policies()
    record_audit(admin, "CREATE_ALLOWLIST", "ALLOWLIST", str(rule_id), {"domain": norm, "reason": rule.reason}, GatewayConfig.DB_PATH)
    return {"status": "SUCCESS", "id": rule_id, "domain": norm}

@app.delete("/api/rules/allowlist/{rule_id}")
def delete_allowlist_entry(rule_id: int, admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM allowlist WHERE id = ?", (rule_id,))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Allowlist entry not found")
    conn.commit()
    conn.close()

    policy_engine.reload_policies()
    record_audit(admin, "DELETE_ALLOWLIST", "ALLOWLIST", str(rule_id), {}, GatewayConfig.DB_PATH)
    return {"status": "SUCCESS", "deleted_id": rule_id}

@app.put("/api/rules/allowlist/{rule_id}/toggle")
def toggle_allowlist_entry(rule_id: int, admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE allowlist SET enabled = 1 - enabled WHERE id = ?", (rule_id,))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Entry not found")
    conn.commit()
    conn.close()

    policy_engine.reload_policies()
    record_audit(admin, "TOGGLE_ALLOWLIST", "ALLOWLIST", str(rule_id), {}, GatewayConfig.DB_PATH)
    return {"status": "SUCCESS"}

# --- 3. Blocked Record Types ---
@app.get("/api/rules/record-types")
def list_blocked_record_types(admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, qtype, enabled, reason, created_at FROM blocked_record_types ORDER BY qtype ASC")
    types = [dict(r) for r in cur.fetchall()]
    conn.close()
    return types

@app.post("/api/rules/record-types")
def create_blocked_record_type(entry: RecordTypeCreate, admin: str = Depends(verify_admin_key)):
    qt = entry.qtype.strip().upper()
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO blocked_record_types (qtype, enabled, reason, created_at)
            VALUES (?, 1, ?, ?)
        """, (qt, entry.reason, time.time()))
        row_id = cur.lastrowid
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Record type already configured or invalid: {e}")
    conn.close()

    policy_engine.reload_policies()
    record_audit(admin, "CREATE_RECORD_TYPE_BLOCK", "RECORD_TYPE", str(row_id), {"qtype": qt}, GatewayConfig.DB_PATH)
    return {"status": "SUCCESS", "id": row_id, "qtype": qt}

@app.delete("/api/rules/record-types/{entry_id}")
def delete_blocked_record_type(entry_id: int, admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM blocked_record_types WHERE id = ?", (entry_id,))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Entry not found")
    conn.commit()
    conn.close()

    policy_engine.reload_policies()
    record_audit(admin, "DELETE_RECORD_TYPE_BLOCK", "RECORD_TYPE", str(entry_id), {}, GatewayConfig.DB_PATH)
    return {"status": "SUCCESS", "deleted_id": entry_id}

# --- 4. Blocklist Feeds & Synchronization ---
@app.get("/api/blocklists")
def list_blocklists(admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, name, url_or_path, category, enabled, entry_count, last_updated, last_status, last_error FROM blocklist_sources ORDER BY id ASC")
    sources = [dict(r) for r in cur.fetchall()]
    conn.close()
    return sources

@app.post("/api/blocklists")
def create_blocklist_source(src: BlocklistSourceCreate, admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO blocklist_sources (name, url_or_path, category, enabled, entry_count, last_status)
            VALUES (?, ?, ?, 1, 0, 'PENDING')
        """, (src.name, src.url_or_path, src.category))
        source_id = cur.lastrowid
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Source creation failed: {e}")
    conn.close()

    # Automatically trigger initial sync for this source
    policy_engine.blocklist_manager.sync_source(source_id, GatewayConfig.DB_PATH)
    policy_engine.reload_policies()
    record_audit(admin, "CREATE_BLOCKLIST_SOURCE", "BLOCKLIST", str(source_id), {"name": src.name}, GatewayConfig.DB_PATH)
    return {"status": "SUCCESS", "id": source_id}

@app.post("/api/blocklists/{source_id}/sync")
def sync_blocklist_source(source_id: int, admin: str = Depends(verify_admin_key)):
    """Triggers atomic update and validation of a specific blocklist source."""
    success, msg = policy_engine.blocklist_manager.sync_source(source_id, GatewayConfig.DB_PATH)
    policy_engine.reload_policies()
    record_audit(admin, "SYNC_BLOCKLIST_SOURCE", "BLOCKLIST", str(source_id), {"success": success, "message": msg}, GatewayConfig.DB_PATH)
    if not success:
        return JSONResponse(status_code=400, content={"status": "FAILED", "detail": msg})
    return {"status": "SUCCESS", "message": msg}

@app.post("/api/blocklists/sync-all")
def sync_all_blocklists(admin: str = Depends(verify_admin_key)):
    """Triggers atomic synchronization across all enabled blocklist sources."""
    results = policy_engine.blocklist_manager.sync_all_sources(GatewayConfig.DB_PATH)
    policy_engine.reload_policies()
    record_audit(admin, "SYNC_ALL_BLOCKLISTS", "BLOCKLIST", None, results, GatewayConfig.DB_PATH)
    return {"status": "SUCCESS", "results": results}

@app.delete("/api/blocklists/{source_id}")
def delete_blocklist_source(source_id: int, admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM blocklist_sources WHERE id = ?", (source_id,))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Blocklist source not found")
    conn.commit()
    conn.close()

    policy_engine.blocklist_manager.load_from_db(GatewayConfig.DB_PATH)
    policy_engine.reload_policies()
    record_audit(admin, "DELETE_BLOCKLIST_SOURCE", "BLOCKLIST", str(source_id), {}, GatewayConfig.DB_PATH)
    return {"status": "SUCCESS", "deleted_id": source_id}

# --- 5. Upstream Resolvers ---
@app.get("/api/upstreams")
def list_upstreams(admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, address, port, protocol, priority, enabled, health_status, last_latency_ms, last_checked FROM upstream_resolvers ORDER BY priority ASC")
    upstreams = [dict(r) for r in cur.fetchall()]
    conn.close()
    return upstreams

@app.post("/api/upstreams")
def create_upstream(up: UpstreamCreate, admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO upstream_resolvers (address, port, protocol, priority, enabled, health_status)
        VALUES (?, ?, ?, ?, 1, 'HEALTHY')
    """, (up.address, up.port, up.protocol.upper(), up.priority))
    row_id = cur.lastrowid
    conn.commit()
    conn.close()

    policy_engine.reload_policies()
    record_audit(admin, "CREATE_UPSTREAM", "UPSTREAM", str(row_id), {"address": up.address, "port": up.port}, GatewayConfig.DB_PATH)
    return {"status": "SUCCESS", "id": row_id}

@app.post("/api/upstreams/test")
def test_upstream_endpoint(req: UpstreamTestRequest, admin: str = Depends(verify_admin_key)):
    """Tests latency and connectivity to specified upstream resolver."""
    res = UpstreamResolver.test_resolver(req.address, req.port, req.protocol)
    return res

@app.delete("/api/upstreams/{upstream_id}")
def delete_upstream(upstream_id: int, admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM upstream_resolvers WHERE id = ?", (upstream_id,))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Upstream resolver not found")
    conn.commit()
    conn.close()

    policy_engine.reload_policies()
    record_audit(admin, "DELETE_UPSTREAM", "UPSTREAM", str(upstream_id), {}, GatewayConfig.DB_PATH)
    return {"status": "SUCCESS", "deleted_id": upstream_id}

# --- 6. Settings & Audit Trail ---
@app.get("/api/settings")
def get_settings(admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT key, value FROM gateway_settings")
    settings = {r["key"]: r["value"] for r in cur.fetchall()}
    conn.close()
    return settings

@app.put("/api/settings")
def update_settings(body: SettingsUpdateRequest, admin: str = Depends(verify_admin_key)):
    conn = get_db(GatewayConfig.DB_PATH)
    cur = conn.cursor()
    updates = {}
    if body.blocked_response_rcode:
        rcode = body.blocked_response_rcode.upper()
        if rcode not in ("REFUSED", "NXDOMAIN"):
            raise HTTPException(status_code=400, detail="Blocked response code must be 'REFUSED' or 'NXDOMAIN'")
        cur.execute("UPDATE gateway_settings SET value = ? WHERE key = 'blocked_response_rcode'", (rcode,))
        updates["blocked_response_rcode"] = rcode

    if body.log_retention_days is not None:
        cur.execute("UPDATE gateway_settings SET value = ? WHERE key = 'log_retention_days'", (str(body.log_retention_days),))
        updates["log_retention_days"] = body.log_retention_days

    if body.allowed_networks is not None:
        cur.execute("UPDATE gateway_settings SET value = ? WHERE key = 'allowed_networks'", (body.allowed_networks,))
        updates["allowed_networks"] = body.allowed_networks

    conn.commit()
    conn.close()

    policy_engine.reload_policies()
    record_audit(admin, "UPDATE_SETTINGS", "SETTINGS", None, updates, GatewayConfig.DB_PATH)
    return {"status": "SUCCESS", "updated": updates}

@app.get("/api/audit")
def list_audit_logs(limit: int = Query(100, ge=1, le=500), admin: str = Depends(verify_admin_key)):
    """Returns administrative action audit history."""
    return get_audit_logs(limit=limit, db_path=GatewayConfig.DB_PATH)

@app.post("/api/dns/logs/prune")
def prune_logs_endpoint(body: PruneLogsRequest, admin: str = Depends(verify_admin_key)):
    """Prunes DNS query logs older than specified retention days."""
    days = body.retention_days or GatewayConfig.LOG_RETENTION_DAYS
    deleted = prune_old_logs(days, GatewayConfig.DB_PATH)
    record_audit(admin, "PRUNE_LOGS", "SYSTEM", None, {"days": days, "deleted_rows": deleted}, GatewayConfig.DB_PATH)
    return {"status": "SUCCESS", "deleted_rows": deleted, "retention_days": days}

# Offline Forensics / PCAP analysis (Preserved without risk scoring)
@app.post("/api/pcap/analyze")
async def analyze_pcap_upload(file: UploadFile = File(...)):
    """Analyzes offline PCAP file and reports query volume, domains, and record types."""
    temp_dir = os.path.join("data", "pcaps")
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, f"upload_{int(time.time())}_{file.filename}")
    
    with open(temp_path, "wb") as buffer:
        content = await file.read()
        buffer.write(content)

    from forensics.pcap_analyzer import PCAPAnalyzer
    analyzer = PCAPAnalyzer()
    raw_results = analyzer.analyze_pcap_file(temp_path)
    
    # Strip any risk scoring fields to align with deterministic philosophy
    clean_results = {
        "pcap_file": raw_results.get("pcap_file", file.filename),
        "total_packets": raw_results.get("total_packets", 0),
        "dns_packets": raw_results.get("dns_packets", 0),
        "unique_domains": raw_results.get("unique_domains", 0),
        "extracted_queries": raw_results.get("packet_samples", [])[:50]
    }
    return clean_results

# WebSocket Telemetry Stream
@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep alive ping/pong
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

# Static Dashboard Files Mount
def get_dashboard_dir() -> str:
    if getattr(sys, "frozen", False):
        base_dir = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        p1 = os.path.join(base_dir, "dashboard")
        if os.path.exists(p1):
            return p1
    p2 = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dashboard"))
    if os.path.exists(p2):
        return p2
    p3 = os.path.abspath("dashboard")
    if os.path.exists(p3):
        return p3
    return p2

dashboard_dir = get_dashboard_dir()
if os.path.exists(dashboard_dir):
    app.mount("/dashboard", StaticFiles(directory=dashboard_dir, html=True), name="dashboard_sub")
    app.mount("/", StaticFiles(directory=dashboard_dir, html=True), name="static_root")
else:
    @app.get("/")
    def read_root():
        return {"message": "DNS Security Gateway API running. Dashboard directory not found."}
