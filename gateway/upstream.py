"""
Upstream DNS Forwarding Engine with UDP/TCP Support, Failover, and Health Monitoring.
Never fabricates answers; returns SERVFAIL on upstream network failure.
"""

import socket
import struct
import time
import logging
from typing import List, Dict, Any, Optional, Tuple
from dnslib import DNSRecord, RCODE, DNSQuestion, QTYPE
from gateway.config import GatewayConfig

logger = logging.getLogger("DNSShield.Upstream")

class UpstreamResolver:
    def __init__(self, upstreams: Optional[List[Dict[str, Any]]] = None):
        # Default fallback upstreams
        self.upstreams = upstreams or [
            {"address": "1.1.1.1", "port": 53, "protocol": "UDP", "priority": 1, "enabled": True},
            {"address": "8.8.8.8", "port": 53, "protocol": "UDP", "priority": 2, "enabled": True}
        ]
        self.timeout = GatewayConfig.UPSTREAM_TIMEOUT

    def set_upstreams(self, upstreams: List[Dict[str, Any]]):
        self.upstreams = [u for u in upstreams if u.get("enabled", True)]
        # Sort by priority ascending
        self.upstreams.sort(key=lambda x: x.get("priority", 1))

    def forward_query(self, raw_query: bytes, client_tx_id: int) -> Tuple[Optional[bytes], str, float, str]:
        """
        Forwards DNS query to configured upstream resolvers with priority failover.
        Returns:
            (response_bytes, upstream_used, latency_ms, status)
        """
        for up in self.upstreams:
            addr = up.get("address", "1.1.1.1")
            port = int(up.get("port", 53))
            protocol = up.get("protocol", "UDP").upper()

            start_t = time.time()
            try:
                resp_bytes = self._query_server(raw_query, addr, port, protocol)
                if resp_bytes:
                    latency = round((time.time() - start_t) * 1000, 2)
                    up["health_status"] = "HEALTHY"
                    up["last_latency_ms"] = latency
                    up["last_checked"] = time.time()
                    return resp_bytes, f"{addr}:{port}", latency, "NOERROR"
            except Exception as e:
                logger.warning(f"Upstream {addr}:{port} failed: {e}. Attempting failover...")
                up["health_status"] = "UNREACHABLE"
                up["last_checked"] = time.time()

        # All upstreams exhausted or unreachable: synthesize SERVFAIL (RFC 1035)
        servfail_bytes = self._build_servfail(raw_query, client_tx_id)
        return servfail_bytes, "NONE", 0.0, "SERVFAIL"

    def _query_server(self, raw_query: bytes, host: str, port: int, protocol: str) -> Optional[bytes]:
        if protocol == "TCP":
            return self._query_tcp(raw_query, host, port)
        else:
            resp = self._query_udp(raw_query, host, port)
            # Check for truncation flag (TC bit); if truncated, retry via TCP per RFC 7766
            if resp:
                try:
                    parsed = DNSRecord.parse(resp)
                    if parsed.header.tc:
                        return self._query_tcp(raw_query, host, port)
                except Exception:
                    pass
            return resp

    def _query_udp(self, raw_query: bytes, host: str, port: int) -> bytes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(raw_query, (host, port))
            data, _ = sock.recvfrom(4096)
            return data
        finally:
            sock.close()

    def _query_tcp(self, raw_query: bytes, host: str, port: int) -> bytes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((host, port))
            # 2-byte length prefix
            prefix = struct.pack("!H", len(raw_query))
            sock.sendall(prefix + raw_query)

            len_buf = sock.recv(2)
            if len(len_buf) < 2:
                raise ConnectionError("Truncated TCP DNS length header")
            resp_len = struct.unpack("!H", len_buf)[0]

            received = b""
            while len(received) < resp_len:
                chunk = sock.recv(min(4096, resp_len - len(received)))
                if not chunk:
                    break
                received += chunk

            return received
        finally:
            sock.close()

    def _build_servfail(self, raw_query: bytes, client_tx_id: int) -> bytes:
        """Synthesizes RFC-compliant SERVFAIL response."""
        try:
            req = DNSRecord.parse(raw_query)
            rep = req.reply()
            rep.header.rcode = getattr(RCODE, "SERVFAIL")
            return rep.pack()
        except Exception:
            # Minimal DNS header with SERVFAIL
            # ID (2 bytes), Flags (2 bytes: QR=1, RCODE=2 SERVFAIL: 0x8182), QDCOUNT=0, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
            return struct.pack("!HHHHHH", client_tx_id, 0x8182, 0, 0, 0, 0)

    @staticmethod
    def test_resolver(address: str, port: int = 53, protocol: str = "UDP") -> Dict[str, Any]:
        """Performs a real-time connectivity and latency probe on an upstream server."""
        query = DNSRecord.question("one.one.one.one", "A").pack()
        client = UpstreamResolver()
        start = time.time()
        try:
            resp = client._query_server(query, address, port, protocol)
            latency = round((time.time() - start) * 1000, 2)
            parsed = DNSRecord.parse(resp)
            return {
                "success": True,
                "latency_ms": latency,
                "rcode": RCODE[parsed.header.rcode],
                "error": None
            }
        except Exception as e:
            return {
                "success": False,
                "latency_ms": 0.0,
                "rcode": "ERROR",
                "error": str(e)
            }
