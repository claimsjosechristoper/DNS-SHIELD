"""
Upstream DNS Forwarding Engine with IPv4/IPv6, UDP/TCP Support, Response Validation,
Failover, and Health Monitoring.
Never fabricates answers; returns SERVFAIL on upstream network failure.
"""

import socket
import struct
import time
import secrets
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
        Validates response transaction ID, QR flag, and question matching.
        Returns:
            (response_bytes, upstream_used, latency_ms, status)
        """
        parsed_query = None
        orig_qname = None
        orig_qtype = None
        try:
            parsed_query = DNSRecord.parse(raw_query)
            if parsed_query.questions:
                orig_qname = parsed_query.q.qname
                orig_qtype = parsed_query.q.qtype
        except Exception:
            pass

        for up in self.upstreams:
            addr = up.get("address", "1.1.1.1")
            port = int(up.get("port", 53))
            protocol = up.get("protocol", "UDP").upper()

            # Randomize transaction ID sent to upstream to mitigate spoofing
            upstream_tx_id = secrets.randbelow(65535) + 1
            if parsed_query:
                parsed_query.header.id = upstream_tx_id
                upstream_query_bytes = parsed_query.pack()
            else:
                upstream_query_bytes = raw_query

            start_t = time.time()
            try:
                resp_bytes = self._query_server(upstream_query_bytes, addr, port, protocol)
                if resp_bytes:
                    # Validate upstream response
                    validated_resp = self._validate_upstream_response(
                        resp_bytes, upstream_tx_id, orig_qname, orig_qtype, client_tx_id
                    )
                    latency = round((time.time() - start_t) * 1000, 2)
                    up["health_status"] = "HEALTHY"
                    up["last_latency_ms"] = latency
                    up["last_checked"] = time.time()
                    return validated_resp, f"{addr}:{port}", latency, "NOERROR"
            except Exception as e:
                logger.warning(f"Upstream {addr}:{port} failed or validation rejected: {e}. Attempting failover...")
                up["health_status"] = "UNREACHABLE"
                up["last_checked"] = time.time()

        # All upstreams exhausted or unreachable: synthesize SERVFAIL (RFC 1035)
        servfail_bytes = self._build_servfail(raw_query, client_tx_id)
        return servfail_bytes, "NONE", 0.0, "SERVFAIL"

    def _validate_upstream_response(
        self,
        resp_bytes: bytes,
        expected_tx_id: int,
        orig_qname: Any,
        orig_qtype: Any,
        client_tx_id: int
    ) -> bytes:
        """
        Strictly validates the upstream response packet:
        1. Valid DNS packet structure.
        2. QR bit must be 1 (response).
        3. Transaction ID must match expected_tx_id.
        4. Question section (if present) must match original question name and type.
        Rewrites header transaction ID to match client_tx_id.
        """
        record = DNSRecord.parse(resp_bytes)
        if record.header.qr != 1:
            raise ValueError("Upstream packet is not a DNS response (QR!=1)")

        if record.header.id != expected_tx_id:
            raise ValueError(f"Transaction ID mismatch: expected {expected_tx_id}, got {record.header.id}")

        if orig_qname is not None and record.questions:
            if record.q.qname != orig_qname:
                raise ValueError(f"Question name mismatch: expected {orig_qname}, got {record.q.qname}")
            if orig_qtype is not None and record.q.qtype != orig_qtype:
                raise ValueError(f"Question type mismatch: expected {orig_qtype}, got {record.q.qtype}")

        # Rewrite transaction ID to client_tx_id
        record.header.id = client_tx_id
        return record.pack()

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
        """Queries upstream DNS over UDP with IPv4 and IPv6 support."""
        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        if not addrinfo:
            raise ConnectionError(f"Cannot resolve upstream host: {host}")

        family, socktype, proto, _, sockaddr = addrinfo[0]
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(raw_query, sockaddr)
            data, _ = sock.recvfrom(4096)
            return data
        finally:
            sock.close()

    def _query_tcp(self, raw_query: bytes, host: str, port: int) -> bytes:
        """Queries upstream DNS over TCP with IPv4/IPv6 support and exact frame reading."""
        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addrinfo:
            raise ConnectionError(f"Cannot resolve upstream host: {host}")

        family, socktype, proto, _, sockaddr = addrinfo[0]
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(self.timeout)
        try:
            sock.connect(sockaddr)
            # 2-byte length prefix
            prefix = struct.pack("!H", len(raw_query))
            sock.sendall(prefix + raw_query)

            # Read 2-byte length prefix exactly
            len_buf = self._recv_exact(sock, 2)
            if not len_buf:
                raise ConnectionError("Truncated TCP DNS length header")
            resp_len = struct.unpack("!H", len_buf)[0]

            # Read payload exactly
            data = self._recv_exact(sock, resp_len)
            if data is None or len(data) < resp_len:
                raise ConnectionError("Incomplete TCP DNS response payload")
            return data
        finally:
            sock.close()

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> Optional[bytes]:
        data = bytearray()
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                return None
            data.extend(chunk)
        return bytes(data)

    def _build_servfail(self, raw_query: bytes, client_tx_id: int) -> bytes:
        """Synthesizes RFC-compliant SERVFAIL response."""
        try:
            req = DNSRecord.parse(raw_query)
            rep = req.reply()
            rep.header.id = client_tx_id
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
