"""
Tests for Feature Extractor and Packet Parser.
"""

from packet_monitor.feature_extractor import FeatureExtractor
from packet_monitor.packet_parser import DNSPacketParser
from scapy.all import IP, UDP, DNS, DNSQR

def test_shannon_entropy_calculation():
    # Benign domain label
    entropy_benign = FeatureExtractor.calculate_shannon_entropy("google")
    # Base64 high-entropy label with uppercase, lowercase, numbers, and special characters
    entropy_high = FeatureExtractor.calculate_shannon_entropy("a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0")
    
    assert entropy_benign < 2.5
    assert entropy_high > 4.0

def test_feature_extractor_ratios():
    parsed_mock = {
        "qname": "s1a2b3-q001-t005.lab.dnsshield.local",
        "subdomain": "s1a2b3-q001-t005",
        "labels": ["s1a2b3-q001-t005", "lab", "dnsshield", "local"],
        "qtype": "TXT",
        "packet_size": 128,
        "rcode": 0
    }
    
    features = FeatureExtractor.extract_features(parsed_mock)
    
    assert features["domain_length"] == len("s1a2b3-q001-t005.lab.dnsshield.local")
    assert features["subdomain_length"] == len("s1a2b3-q001-t005")
    assert features["label_count"] == 4
    assert features["maximum_label_length"] == len("s1a2b3-q001-t005")
    assert features["shannon_entropy"] > 3.0
    assert features["digit_ratio"] > 0.3

def test_scapy_packet_parsing():
    pkt = IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=12345, dport=53)/DNS(rd=1, qd=DNSQR(qname="test.dnsshield.local", qtype="TXT"))
    parsed = DNSPacketParser.parse_scapy_packet(pkt)
    
    assert parsed is not None
    assert parsed["src_ip"] == "192.168.1.100"
    assert parsed["qname"] == "test.dnsshield.local"
    assert parsed["qtype"] == "TXT"
    assert parsed["label_count"] == 3
