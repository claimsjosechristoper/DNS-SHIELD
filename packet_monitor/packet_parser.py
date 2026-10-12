"""
DNS Packet Parser module.
Extracts structured metadata from live or PCAP DNS packets safely.
Supports A, AAAA, TXT, and CNAME query/response types.
"""

import time
import logging
from typing import Dict, Any, Optional
from scapy.all import Packet, IP, IPv6, UDP, DNS, DNSQR, DNSRR

logger = logging.getLogger("DNSShield.PacketParser")

QTYPE_MAP = {
    1: "A",
    28: "AAAA",
    16: "TXT",
    5: "CNAME",
    15: "MX",
    2: "NS",
    6: "SOA",
    12: "PTR"
}

class DNSPacketParser:
    @staticmethod
    def parse_scapy_packet(packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Parses a Scapy packet object containing DNS layer.
        Returns a dictionary of extracted DNS metadata or None if unparseable.
        """
        try:
            if not packet.haslayer(DNS):
                return None

            dns_layer = packet.getlayer(DNS)
            
            # Extract IP layers safely
            src_ip = "127.0.0.1"
            dst_ip = "127.0.0.1"
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst

            timestamp = float(packet.time) if hasattr(packet, "time") else time.time()
            pkt_size = len(packet)

            # Is Query or Response
            is_response = bool(dns_layer.qr)
            rcode = dns_layer.rcode if is_response else 0

            # Extract Query Information
            qname = ""
            qtype = "A"
            qdcount = dns_layer.qdcount or 0
            if (qdcount > 0 or dns_layer.qd is not None) and dns_layer.qd:
                qname_bytes = dns_layer.qd.qname
                qname = qname_bytes.decode("utf-8", errors="replace").rstrip(".") if isinstance(qname_bytes, bytes) else str(qname_bytes).rstrip(".")
                qtype_num = dns_layer.qd.qtype
                qtype = QTYPE_MAP.get(qtype_num, f"TYPE_{qtype_num}")

            # Extract Subdomain and Label Details
            labels = qname.split(".") if qname and qname != "" else []
            label_count = len(labels)
            
            # Base domain extraction (simplified: last 2 labels, e.g. dnsshield.local or google.com)
            parent_domain = ".".join(labels[-2:]) if label_count >= 2 else qname
            subdomain = ".".join(labels[:-2]) if label_count > 2 else (labels[0] if label_count == 2 else "")
            subdomain_length = len(subdomain)

            # Response details
            answers = []
            ancount = dns_layer.ancount or 0
            if is_response and ancount > 0 and dns_layer.an:
                curr_rr = dns_layer.an
                while curr_rr:
                    rr_type = QTYPE_MAP.get(curr_rr.type, str(curr_rr.type))
                    rdata = str(getattr(curr_rr, "rdata", ""))
                    answers.append({"type": rr_type, "rdata": rdata})
                    curr_rr = curr_rr.payload if hasattr(curr_rr, "payload") and isinstance(curr_rr.payload, DNSRR) else None

            parsed_data = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "packet_size": pkt_size,
                "is_response": is_response,
                "rcode": rcode,
                "qname": qname,
                "qtype": qtype,
                "parent_domain": parent_domain,
                "subdomain": subdomain,
                "subdomain_length": subdomain_length,
                "label_count": label_count,
                "labels": labels,
                "answers": answers
            }

            return parsed_data

        except Exception as e:
            logger.warning(f"Failed to parse packet: {e}", exc_info=True)
            return None
