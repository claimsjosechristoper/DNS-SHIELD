"""
Offline PCAP Forensics Analyzer.
Reads offline PCAP files using Scapy, analyzes DNS packets, computes statistics, entropy distributions, and generates incident timelines.
"""

import os
import time
import logging
from typing import Dict, Any, List, Optional
from scapy.all import rdpcap, PcapWriter, IP, UDP, DNS, DNSQR
from packet_monitor.packet_parser import DNSPacketParser
from packet_monitor.feature_extractor import FeatureExtractor
from detection_engine.risk_engine import RiskEngine
from forensics.timeline import TimelineGenerator

logger = logging.getLogger("DNSShield.PCAPAnalyzer")

class PCAPAnalyzer:
    def __init__(self, risk_engine: Optional[RiskEngine] = None):
        self.risk_engine = risk_engine or RiskEngine()

    def analyze_pcap_file(self, pcap_path: str) -> Dict[str, Any]:
        """Reads and analyzes an offline PCAP file containing DNS traffic."""
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            logger.error(f"Error reading PCAP file {pcap_path}: {e}")
            return {"status": "error", "error": f"Failed to parse PCAP: {str(e)}"}

        parsed_events = []
        qtype_counts: Dict[str, int] = {}
        top_domains: Dict[str, int] = {}
        top_hosts: Dict[str, int] = {}
        entropy_distribution: List[float] = []
        suspicious_events: List[Dict[str, Any]] = []

        total_dns_packets = 0

        for pkt in packets:
            try:
                parsed = DNSPacketParser.parse_scapy_packet(pkt)
                if not parsed:
                    continue

                total_dns_packets += 1
                qname = parsed.get("qname", "")
                qtype = parsed.get("qtype", "A")
                src_ip = parsed.get("src_ip", "127.0.0.1")
                parent_domain = parsed.get("parent_domain", qname)

                # Counts
                qtype_counts[qtype] = qtype_counts.get(qtype, 0) + 1
                top_domains[parent_domain] = top_domains.get(parent_domain, 0) + 1
                top_hosts[src_ip] = top_hosts.get(src_ip, 0) + 1

                # Feature extraction & Risk Analysis
                features = FeatureExtractor.extract_features(parsed)
                entropy_distribution.append(features["shannon_entropy"])

                analysis = self.risk_engine.analyze_query(parsed, features)
                
                event_entry = {
                    "timestamp": parsed.get("timestamp", time.time()),
                    "src_ip": src_ip,
                    "dst_ip": parsed.get("dst_ip", "127.0.0.1"),
                    "qname": qname,
                    "qtype": qtype,
                    "parsed": parsed,
                    "features": features,
                    "risk_score": analysis["risk_score"],
                    "classification": analysis["classification"],
                    "status": analysis["status"],
                    "reasoning": analysis["reasoning"],
                    "indicators": analysis["indicators"],
                    "ml_result": analysis["ml_result"],
                    "mitre_mapping": analysis["mitre_mapping"]
                }
                parsed_events.append(event_entry)

                if analysis["risk_score"] >= 40:
                    suspicious_events.append(event_entry)

            except Exception as e:
                logger.debug(f"Skipping malformed packet in PCAP: {e}")
                continue

        timeline = TimelineGenerator.build_chronological_timeline(parsed_events)
        avg_entropy = round(sum(entropy_distribution) / max(1, len(entropy_distribution)), 2)

        return {
            "status": "success",
            "pcap_file": os.path.basename(pcap_path),
            "total_dns_packets": total_dns_packets,
            "suspicious_count": len(suspicious_events),
            "query_type_distribution": qtype_counts,
            "top_domains": dict(sorted(top_domains.items(), key=lambda x: x[1], reverse=True)[:10]),
            "top_hosts": dict(sorted(top_hosts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "average_entropy": avg_entropy,
            "entropy_distribution": entropy_distribution[:100],
            "timeline": timeline[:100],
            "suspicious_events": suspicious_events[:50]
        }

    @staticmethod
    def generate_demo_pcap(output_path: str) -> str:
        """Generates a synthetic laboratory DNS PCAP file for demonstration and offline testing."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        writer = PcapWriter(output_path, sync=True)
        
        # Add normal DNS packets
        for d in ["google.com", "github.com", "microsoft.com"]:
            pkt = IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=53535, dport=53)/DNS(rd=1, qd=DNSQR(qname=d, qtype=1))
            writer.write(pkt)

        # Add synthetic tunnel DNS packets
        from dns_simulator.encoder import DNSEncoder
        _, queries, _ = DNSEncoder.create_tunnel_queries("DEMO-PCAP-EXFILTRATION-TEST", encoding_method="base32")
        for q in queries:
            pkt = IP(src="192.168.1.55", dst="127.0.0.1")/UDP(sport=53536, dport=5353)/DNS(rd=1, qd=DNSQR(qname=q, qtype=16))
            writer.write(pkt)

        writer.close()
        return output_path
