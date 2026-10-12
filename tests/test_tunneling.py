"""
Unit tests for explainable DNS Tunneling Detection Heuristics.
Verifies multi-signal correlation and absence of false positives on legitimate CDNs.
"""

from detection_engine.tunneling_detector import (
    TunnelingDetector,
    calculate_shannon_entropy,
)


def test_shannon_entropy_calculation():
    # Low entropy (repeated characters)
    low = calculate_shannon_entropy("aaaaaaaaaa")
    assert low == 0.0

    # Normal english words
    normal = calculate_shannon_entropy("mycorporatewebsite")
    assert 2.5 <= normal <= 3.8

    # High entropy (base64/hex encoded random payload)
    high = calculate_shannon_entropy("8f7a6b2c9e1d4a5b6c7d8e9f0a1b2c3d")
    assert high >= 3.8


def test_cdn_and_cloud_allowlist_prevents_false_positives():
    detector = TunnelingDetector()

    cdn_samples = [
        "d123456abcdefg.cloudfront.net",
        "e1234.dscg.akamaiedge.net",
        "prod-api-v2.trafficmanager.net",
        "s3-1-w.amazonaws.com",
        "clients4.google.com",
    ]
    for domain in cdn_samples:
        is_tunnel, explanation, signals = detector.evaluate(domain, qtype="A")
        assert is_tunnel is False, f"False positive detected on legitimate CDN: {domain}"
        assert "exemption" in explanation.lower() or not signals


def test_standard_domains_not_flagged():
    detector = TunnelingDetector()

    standard_domains = [
        "google.com",
        "github.com",
        "microsoft.com",
        "mail.yahoo.com",
        "api.slack.com",
        "internal-portal.corp.local",
    ]
    for domain in standard_domains:
        is_tunnel, _, signals = detector.evaluate(domain, qtype="A")
        assert is_tunnel is False
        assert len(signals) < 2


def test_high_entropy_long_payload_txt_flagged_as_suspected():
    detector = TunnelingDetector()

    # Long, random-looking base32/base64 chunk with TXT record type
    tunnel_domain = "mfzwi3dbon2gg33om5ugk3lfnuxwy33onrxgkltf.tunnel-c2.test"
    is_tunnel, explanation, signals = detector.evaluate(tunnel_domain, qtype="TXT")

    assert is_tunnel is True
    assert "Suspected DNS tunneling" in explanation
    assert len(signals) >= 2
    # Verify exact signals are reported
    assert any("entropy" in s.lower() for s in signals)
    assert any("favored tunneling record type" in s.lower() for s in signals)


def test_burst_high_entropy_queries_flagged():
    detector = TunnelingDetector(burst_queries_per_apex=5, window_seconds=10.0)

    apex_domain = "exfil-server.test"
    # Send 6 queries with varying high-entropy prefixes
    for i in range(4):
        detector.evaluate(f"prefix{i}randomlabel{i * 12345}.{apex_domain}", qtype="A")

    # 5th and 6th query trigger burst + entropy signals
    is_tunnel, explanation, signals = detector.evaluate(
        f"chunk-98f7a6b2c9e1d4a5b6c7d8e9f0.{apex_domain}", qtype="A"
    )
    assert is_tunnel is True
    assert any("volume" in s.lower() or "entropy" in s.lower() for s in signals)
