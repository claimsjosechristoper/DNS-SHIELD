"""
Tests for Detection Engine: Rules, Entropy, Behavioral Tracking, and Risk Fusion.
"""

from detection_engine.entropy_detector import EntropyDetector
from detection_engine.rule_detector import RuleDetector
from detection_engine.behavioral_detector import BehavioralDetector
from detection_engine.risk_engine import RiskEngine
from detection_engine.indicators import Severity

def test_entropy_detector():
    detector = EntropyDetector()
    
    # Benign feature
    feat_benign = {"shannon_entropy": 2.1, "subdomain": "mail"}
    res_benign = detector.detect(feat_benign)
    assert res_benign.severity == Severity.NORMAL

    # High entropy feature
    feat_high = {"shannon_entropy": 4.95, "subdomain": "s12345-q001-t010-jrevmrjnkncvevsf"}
    res_high = detector.detect(feat_high)
    assert res_high.severity in (Severity.HIGH, Severity.CRITICAL)

def test_rule_detector():
    rule_det = RuleDetector()
    features = {
        "subdomain_length": 65,
        "maximum_label_length": 50,
        "label_count": 6,
        "digit_ratio": 0.40,
        "uppercase_ratio": 0.35,
        "TXT_request_rate": 0.80,
        "average_packet_size": 500
    }
    
    indicators = rule_det.evaluate(features)
    ind_keys = [i.indicator for i in indicators]
    
    assert "LONG_SUBDOMAIN" in ind_keys
    assert "HIGH_ENCODED_CHAR_RATIO" in ind_keys
    assert "REPEATED_TXT_REQUESTS" in ind_keys

def test_behavioral_detector():
    beh_det = BehavioralDetector()
    src_ip = "192.168.1.50"
    domain = "lab.dnsshield.local"

    # Simulate query burst
    for i in range(40):
        beh_det.record_query(src_ip, domain, f"sub-{i}", "A", 0, 64)

    indicators = beh_det.evaluate_behavior(src_ip, domain)
    ind_keys = [i.indicator for i in indicators]
    
    assert "ABNORMALLY_HIGH_QUERY_FREQUENCY" in ind_keys
    assert "RAPID_UNIQUE_SUBDOMAIN_GENERATION" in ind_keys

def test_risk_engine_fusion():
    risk_engine = RiskEngine()
    
    parsed = {
        "src_ip": "10.0.0.15",
        "parent_domain": "lab.dnsshield.local",
        "subdomain": "s999-q001-t005-jrevmrjnkncvevsfkiwugtcjivhfil",
        "qtype": "TXT",
        "rcode": 0,
        "packet_size": 256
    }
    features = {
        "shannon_entropy": 5.15,
        "domain_length": 75,
        "subdomain_length": 60,
        "label_count": 5,
        "maximum_label_length": 48,
        "digit_ratio": 0.40,
        "uppercase_ratio": 0.35,
        "query_frequency": 8.0,
        "unique_subdomain_rate": 0.95,
        "TXT_request_rate": 0.90,
        "average_packet_size": 256
    }

    # Populate behavioral window
    for i in range(25):
        risk_engine.analyze_query(parsed, features)

    result = risk_engine.analyze_query(parsed, features)
    
    assert result["risk_score"] >= 50
    assert result["classification"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert "reasoning" in result
    assert result["mitre_mapping"]["technique_id"] == "T1071.004"
