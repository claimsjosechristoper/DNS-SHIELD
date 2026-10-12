"""
Deterministic DNS Security Decision & Enforcement Policy Engine.
Every query receives an explicit ALLOW or BLOCK verdict.
Zero risk-scoring, zero threat percentages, and zero probabilistic thresholds.
"""

import time
import ipaddress
import logging
from typing import Dict, Any, Tuple, Optional, List, Set
from dnslib import DNSRecord, RCODE, QTYPE

from gateway.config import GatewayConfig
from gateway.normalization import normalize_domain
from gateway.matcher import RuleIndex
from gateway.blocklist_manager import BlocklistManager
from gateway.rate_limiter import RateLimiter
from gateway.cache import DNSCache
from gateway.upstream import UpstreamResolver
from gateway.db import get_db, log_dns_query
from detection_engine.tunneling_detector import TunnelingDetector

logger = logging.getLogger("DNSShield.PolicyEngine")

class PolicyEngine:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or GatewayConfig.DB_PATH
        
        # Core subsystems
        self.blocklist_manager = BlocklistManager()
        self.rate_limiter = RateLimiter(
            default_rpm=GatewayConfig.RATE_LIMIT_RPM,
            burst_limit=GatewayConfig.RATE_LIMIT_BURST
        )
        self.cache = DNSCache(
            max_entries=GatewayConfig.CACHE_MAX_ENTRIES,
            min_ttl=GatewayConfig.CACHE_MIN_TTL,
            max_ttl=GatewayConfig.CACHE_MAX_TTL
        )
        self.upstream_resolver = UpstreamResolver()
        self.tunneling_detector = TunnelingDetector()
        self.enable_tunneling_detection = True

        # In-memory fast rule indexes
        self.custom_rules_index = RuleIndex()
        self.allowlist_index = RuleIndex()
        self.blocked_record_types: Set[str] = set()
        
        # Access control CIDRs
        self.allowed_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._load_allowed_networks(GatewayConfig.ALLOWED_NETWORKS)

        # Default block response RCODE
        self.blocked_response_rcode: str = GatewayConfig.DEFAULT_BLOCKED_RCODE

        # Optional callback for live event broadcasting (e.g. WebSockets)
        self.event_listener = None

        # Load state from database
        self.reload_policies()

    def set_event_listener(self, callback):
        self.event_listener = callback

    def _load_allowed_networks(self, cidr_list: List[str]):
        nets = []
        for cidr in cidr_list:
            try:
                nets.append(ipaddress.ip_network(cidr.strip(), strict=False))
            except Exception as e:
                logger.warning(f"Invalid CIDR network '{cidr}': {e}")
        self.allowed_networks = nets

    def reload_policies(self):
        """
        Reloads custom rules, allowlist, blocked record types, upstream resolvers,
        and settings dynamically from SQLite without restarting the gateway.
        """
        conn = get_db(self.db_path)
        cur = conn.cursor()

        # 1. Custom Rules
        cur.execute("SELECT domain, rule_type, action, enabled, reason FROM custom_rules WHERE enabled = 1")
        new_custom = RuleIndex()
        for r in cur.fetchall():
            new_custom.add_rule(r["domain"], r["rule_type"], {
                "rule_name": f"CUSTOM:{r['domain']}",
                "reason": r["reason"] or "Blocked by administrator custom policy"
            })
        self.custom_rules_index = new_custom

        # 2. Allowlist
        cur.execute("SELECT domain, rule_type, enabled, reason FROM allowlist WHERE enabled = 1")
        new_allow = RuleIndex()
        for r in cur.fetchall():
            new_allow.add_rule(r["domain"], r["rule_type"], {
                "rule_name": f"ALLOWLIST:{r['domain']}",
                "reason": r["reason"] or "Permitted by administrator allowlist"
            })
        self.allowlist_index = new_allow

        # 3. Blocked Record Types
        cur.execute("SELECT qtype, enabled, reason FROM blocked_record_types WHERE enabled = 1")
        self.blocked_record_types = {r["qtype"].upper() for r in cur.fetchall()}

        # 4. Upstream Resolvers
        cur.execute("SELECT address, port, protocol, priority, enabled FROM upstream_resolvers WHERE enabled = 1 ORDER BY priority ASC")
        upstreams = [dict(r) for r in cur.fetchall()]
        if upstreams:
            self.upstream_resolver.set_upstreams(upstreams)

        # 5. Gateway Settings
        cur.execute("SELECT key, value FROM gateway_settings")
        settings = {r["key"]: r["value"] for r in cur.fetchall()}
        if "blocked_response_rcode" in settings:
            rcode_val = settings["blocked_response_rcode"].upper()
            if rcode_val in ("REFUSED", "NXDOMAIN"):
                self.blocked_response_rcode = rcode_val
        if "allowed_networks" in settings:
            self._load_allowed_networks(settings["allowed_networks"].split(","))

        conn.close()

        # 6. Load blocklists from DB / disk
        self.blocklist_manager.load_from_db(self.db_path)
        logger.info("Gateway security policies dynamically reloaded.")

    def is_client_authorized(self, client_ip: str) -> bool:
        """Verifies if client IP resides in configured authorized local networks."""
        try:
            ip_obj = ipaddress.ip_address(client_ip)
            for net in self.allowed_networks:
                if ip_obj in net:
                    return True
            return False
        except Exception:
            return False

    def build_blocked_response(self, request: DNSRecord, rcode_str: Optional[str] = None) -> bytes:
        """Constructs an RFC-compliant blocked response (default REFUSED or NXDOMAIN)."""
        rcode_name = rcode_str or self.blocked_response_rcode
        reply = request.reply()
        rcode_code = getattr(RCODE, rcode_name, RCODE.REFUSED)
        reply.header.rcode = rcode_code
        reply.header.ra = 1  # Recursion available
        return reply.pack()

    def build_error_response(self, request: Optional[DNSRecord], rcode_str: str, client_tx_id: int = 0) -> bytes:
        """Builds an error response like FORMERR, NOTIMP, or SERVFAIL."""
        if request:
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, rcode_str, RCODE.SERVFAIL)
            return reply.pack()
        else:
            # Raw fallback
            return self.upstream_resolver._build_servfail(b"", client_tx_id)

    def process_query(self, raw_data: bytes, client_ip: str, client_port: int) -> Tuple[bytes, Dict[str, Any]]:
        """
        Evaluates DNS request through strict precedence pipeline and produces
        one definitive verdict: ALLOW or BLOCK.
        """
        start_time = time.time()
        client_tx_id = 0

        # PIPELINE STEP 1: Protocol Validation & Malformed Check
        if len(raw_data) < 12:
            event = {
                "timestamp": start_time,
                "client_ip": client_ip,
                "domain": "<malformed-packet>",
                "qtype": "UNKNOWN",
                "decision": "BLOCK",
                "decision_type": "PROTOCOL_VIOLATION",
                "matched_rule": "RFC1035_MALFORMED_HEADER",
                "reason": "Packet length under 12 bytes; truncated DNS header",
                "rcode": "FORMERR",
                "response_time_ms": round((time.time() - start_time) * 1000, 2),
                "upstream_server": "NONE"
            }
            self._record_and_notify(event)
            return self.build_error_response(None, "FORMERR", client_tx_id), event

        try:
            request = DNSRecord.parse(raw_data)
            client_tx_id = request.header.id
        except Exception as e:
            # Extract tx_id from first 2 bytes if possible
            if len(raw_data) >= 2:
                client_tx_id = (raw_data[0] << 8) | raw_data[1]
            event = {
                "timestamp": start_time,
                "client_ip": client_ip,
                "domain": "<unparseable-packet>",
                "qtype": "UNKNOWN",
                "decision": "BLOCK",
                "decision_type": "PROTOCOL_VIOLATION",
                "matched_rule": "RFC1035_PARSE_FAILURE",
                "reason": f"Malformed wire format: {str(e)}",
                "rcode": "FORMERR",
                "response_time_ms": round((time.time() - start_time) * 1000, 2),
                "upstream_server": "NONE"
            }
            self._record_and_notify(event)
            return self.build_error_response(None, "FORMERR", client_tx_id), event

        # Must be a standard query (QR=0, QDCOUNT=1, OPCODE=0)
        if request.header.qr != 0:
            event = self._make_event(start_time, client_ip, "<qr-violation>", "UNKNOWN", "BLOCK",
                                     "PROTOCOL_VIOLATION", "RFC1035_QR_BIT", "Received response packet as query", "FORMERR")
            self._record_and_notify(event)
            return self.build_error_response(request, "FORMERR", client_tx_id), event

        if len(request.questions) != 1:
            event = self._make_event(start_time, client_ip, "<multiple-questions>", "UNKNOWN", "BLOCK",
                                     "PROTOCOL_VIOLATION", "RFC1035_QDCOUNT", f"Expected exactly 1 question, got {len(request.questions)}", "FORMERR")
            self._record_and_notify(event)
            return self.build_error_response(request, "FORMERR", client_tx_id), event

        if request.header.opcode != 0:
            event = self._make_event(start_time, client_ip, "<non-standard-opcode>", "UNKNOWN", "BLOCK",
                                     "PROTOCOL_VIOLATION", "RFC1035_OPCODE", f"Unsupported opcode {request.header.opcode}", "NOTIMP")
            self._record_and_notify(event)
            return self.build_error_response(request, "NOTIMP", client_tx_id), event

        raw_qname = str(request.q.qname)
        qtype_str = QTYPE.get(request.q.qtype, str(request.q.qtype))

        # Domain Normalization & RFC Syntax Check
        norm_domain, is_valid, norm_err = normalize_domain(raw_qname)
        if not is_valid:
            event = self._make_event(start_time, client_ip, raw_qname, qtype_str, "BLOCK",
                                     "PROTOCOL_VIOLATION", "RFC1035_SYNTAX", norm_err, "FORMERR")
            self._record_and_notify(event)
            return self.build_error_response(request, "FORMERR", client_tx_id), event

        # PIPELINE STEP 2: Access Control (Restrict to local authorized networks)
        if not self.is_client_authorized(client_ip):
            event = self._make_event(start_time, client_ip, norm_domain, qtype_str, "BLOCK",
                                     "ACCESS_DENIED", "ACCESS_CONTROL_CIDR", f"Client IP {client_ip} not permitted by network policy", "REFUSED")
            self._record_and_notify(event)
            return self.build_blocked_response(request, "REFUSED"), event

        # PIPELINE STEP 3: Per-Client Resource & Rate Limiting
        rl_allowed, rl_reason = self.rate_limiter.is_allowed(client_ip)
        if not rl_allowed:
            event = self._make_event(start_time, client_ip, norm_domain, qtype_str, "BLOCK",
                                     "RATE_LIMIT", "RATE_LIMIT_EXCEEDED", rl_reason, "REFUSED")
            self._record_and_notify(event)
            return self.build_blocked_response(request, "REFUSED"), event

        # PIPELINE STEP 4: Administrator Allowlist (Overrides blocklists and custom rules)
        # Note: Allowlist does NOT bypass Protocol Validation, Access Control, or Rate Limiting.
        allow_match = self.allowlist_index.match(norm_domain)
        if allow_match:
            # Permitted by allowlist -> Proceed directly to DNS Resolution
            return self._execute_allowed_resolution(request, raw_data, norm_domain, qtype_str, client_ip, start_time,
                                                    decision_type="ALLOWED",
                                                    matched_rule=allow_match["rule_name"],
                                                    reason=allow_match["reason"])

        # PIPELINE STEP 5: Administrator-Managed Custom Blocking Rules
        custom_block = self.custom_rules_index.match(norm_domain)
        if custom_block:
            event = self._make_event(start_time, client_ip, norm_domain, qtype_str, "BLOCK",
                                     "ADMIN_POLICY", custom_block["rule_name"], custom_block["reason"],
                                     self.blocked_response_rcode)
            self._record_and_notify(event)
            return self.build_blocked_response(request), event

        # PIPELINE STEP 6: Optional Blocking of Specified DNS Record Types
        if qtype_str in self.blocked_record_types:
            reason = f"DNS record type '{qtype_str}' blocked by administrator policy"
            event = self._make_event(start_time, client_ip, norm_domain, qtype_str, "BLOCK",
                                     "RECORD_TYPE", f"BLOCK_QTYPE_{qtype_str}", reason, self.blocked_response_rcode)
            self._record_and_notify(event)
            return self.build_blocked_response(request), event

        # PIPELINE STEP 7: Threat Blocklists (Known Malware, Phishing, C2)
        threat_match = self.blocklist_manager.match(norm_domain)
        if threat_match:
            category_label = threat_match.get("category", "threat").upper()
            reason = f"Identified in threat blocklist: {threat_match.get('source_name')} ({category_label})"
            event = self._make_event(start_time, client_ip, norm_domain, qtype_str, "BLOCK",
                                     "THREAT_BLOCKLIST", threat_match.get("source_name", "THREAT_FEED"),
                                     reason, self.blocked_response_rcode)
            self._record_and_notify(event)
            return self.build_blocked_response(request), event

        # PIPELINE STEP 7.5: Explainable DNS Tunneling Heuristics
        if self.enable_tunneling_detection:
            is_tunnel, tunnel_reason, _ = self.tunneling_detector.evaluate(norm_domain, qtype_str, client_ip)
            if is_tunnel:
                event = self._make_event(start_time, client_ip, norm_domain, qtype_str, "BLOCK",
                                         "SUSPECTED_TUNNELING", "HEURISTIC_TUNNELING_DETECTION",
                                         tunnel_reason, self.blocked_response_rcode)
                self._record_and_notify(event)
                return self.build_blocked_response(request), event

        # PIPELINE STEP 8: Default ALLOW Policy -> Forward to Upstream / Check Cache
        return self._execute_allowed_resolution(request, raw_data, norm_domain, qtype_str, client_ip, start_time,
                                                decision_type="ALLOWED",
                                                matched_rule="DEFAULT_POLICY",
                                                reason="Domain permitted by policy; forwarded to upstream resolver")

    def _execute_allowed_resolution(
        self,
        request: DNSRecord,
        raw_data: bytes,
        domain: str,
        qtype: str,
        client_ip: str,
        start_time: float,
        decision_type: str,
        matched_rule: str,
        reason: str
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Resolves an ALLOWED DNS query: checks cache first, or forwards to upstream.
        Enforces rule checks prior to cache lookups so cached entries cannot bypass updated rules.
        """
        client_tx_id = request.header.id

        # 1. Check Bounded DNS Cache
        cached_resp = self.cache.get(domain, qtype, client_tx_id)
        if cached_resp:
            latency = round((time.time() - start_time) * 1000, 2)
            event = self._make_event(start_time, client_ip, domain, qtype, "ALLOW",
                                     decision_type, matched_rule, f"{reason} [Served from Gateway Cache]",
                                     "NOERROR", latency, "CACHE")
            self._record_and_notify(event)
            return cached_resp, event

        # 2. Forward to Upstream Resolvers
        resp_bytes, upstream_used, latency, status_rcode = self.upstream_resolver.forward_query(raw_data, client_tx_id)

        # Store in cache if positive response with TTL
        if resp_bytes and status_rcode == "NOERROR":
            try:
                parsed_resp = DNSRecord.parse(resp_bytes)
                if parsed_resp.header.rcode == 0:
                    self.cache.put(domain, qtype, parsed_resp)
            except Exception:
                pass

        total_latency = round((time.time() - start_time) * 1000, 2)
        event = self._make_event(start_time, client_ip, domain, qtype, "ALLOW",
                                 decision_type, matched_rule, reason,
                                 status_rcode, total_latency, upstream_used)
        self._record_and_notify(event)
        return resp_bytes, event

    def _make_event(self, start_t: float, client_ip: str, domain: str, qtype: str,
                    decision: str, decision_type: str, matched_rule: str, reason: str,
                    rcode: str, latency: float = 0.0, upstream: str = "NONE") -> Dict[str, Any]:
        return {
            "timestamp": start_t,
            "client_ip": client_ip,
            "domain": domain,
            "qtype": qtype,
            "decision": decision,
            "decision_type": decision_type,
            "matched_rule": matched_rule,
            "reason": reason,
            "rcode": rcode,
            "response_time_ms": latency,
            "upstream_server": upstream
        }

    def _record_and_notify(self, event: Dict[str, Any]):
        try:
            log_dns_query(event, self.db_path)
        except Exception as e:
            logger.error(f"Failed to record DNS log to database: {e}")

        if self.event_listener:
            try:
                self.event_listener(event)
            except Exception:
                pass
