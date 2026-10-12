"""
Tests for PCAP Forensics and Evidence Exporter.
"""

import os
import pytest
from forensics.pcap_analyzer import PCAPAnalyzer
from forensics.evidence_exporter import EvidenceExporter

def test_generate_and_analyze_pcap(tmp_path):
    pcap_file = str(tmp_path / "test_demo.pcap")
    PCAPAnalyzer.generate_demo_pcap(pcap_file)
    
    assert os.path.exists(pcap_file)
    
    analyzer = PCAPAnalyzer()
    res = analyzer.analyze_pcap_file(pcap_file)
    
    assert res["status"] == "success"
    assert res["total_dns_packets"] > 0
    assert len(res["timeline"]) > 0

def test_evidence_exporter(tmp_path):
    exporter = EvidenceExporter(reports_dir=str(tmp_path))
    mock_event = {
        "timestamp": 1700000000.0,
        "src_ip": "192.168.1.50",
        "qname": "s001-q001-t002-tunnel.lab.dnsshield.local",
        "risk_score": 85,
        "classification": "CRITICAL",
        "reasoning": "High entropy and long subdomain detected.",
        "indicators": [{"indicator": "HIGH_ENTROPY", "severity": "HIGH"}],
        "features": {"shannon_entropy": 5.1},
        "ml_result": {"is_anomalous": True, "anomaly_score": 0.88}
    }
    
    filepath_json, report_json = exporter.generate_incident_report(mock_event, output_format="json")
    assert os.path.exists(filepath_json)
    assert report_json["incident_id"].startswith("INC-")
    assert report_json["risk_score"] == 85

    filepath_csv, report_csv = exporter.generate_incident_report(mock_event, output_format="csv")
    assert os.path.exists(filepath_csv)
