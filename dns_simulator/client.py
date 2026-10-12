"""
Safe Localhost Laboratory DNS Client.
Transmits synthetic encoded DNS tunnel queries to the local Lab DNS Server.
Strictly configured to loopback (127.0.0.1).
"""

import time
import socket
import logging
from typing import Dict, Any, List
from dnslib import DNSRecord, QTYPE
from dns_simulator.encoder import DNSEncoder

logger = logging.getLogger("DNSShield.LabDNSClient")

class LabDNSClient:
    def __init__(self, server_host: str = "127.0.0.1", server_port: int = 5353):
        if server_host not in ("127.0.0.1", "localhost"):
            logger.warning(f"Restricting client target '{server_host}' to loopback '127.0.0.1' for safety.")
            server_host = "127.0.0.1"

        self.server_host = server_host
        self.server_port = server_port

    def send_query(self, domain: str, qtype: str = "A") -> bytes:
        """Sends a single DNS query to local laboratory DNS server via UDP."""
        qtype_str = qtype.upper()
        q = DNSRecord.question(domain, qtype=qtype_str)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        try:
            sock.sendto(q.pack(), (self.server_host, self.server_port))
            data, _ = sock.recvfrom(4096)
            return data
        except socket.timeout:
            logger.warning(f"Query timeout for domain: {domain}")
            return b""
        except Exception as e:
            logger.error(f"Error sending query for {domain}: {e}")
            return b""
        finally:
            sock.close()

    def simulate_tunnel_session(
        self,
        payload: str,
        encoding_method: str = "base32",
        delay_seconds: float = 0.05,
        parent_domain: str = "lab.dnsshield.local"
    ) -> Dict[str, Any]:
        """
        Encodes synthetic payload, generates sequence queries, and transmits them to local server.
        """
        session_id, queries, metadata = DNSEncoder.create_tunnel_queries(
            payload=payload,
            encoding_method=encoding_method,
            parent_domain=parent_domain
        )

        sent_count = 0
        responses = []

        for query in queries:
            resp_bytes = self.send_query(query, qtype="A")
            if resp_bytes:
                sent_count += 1
                responses.append(query)
            time.sleep(delay_seconds)

        return {
            "session_id": session_id,
            "total_queries": len(queries),
            "sent_count": sent_count,
            "queries": queries,
            "metadata": metadata
        }
