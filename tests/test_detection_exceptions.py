"""
Regression tests for narrow detection exceptions.

Verifies:
- Customer-controlled cloud platforms (CloudFront, TrafficManager, S3) cannot be used as bypass channels.
- Favored tunneling record types (TXT, NULL) are never exempted, even on infrastructure domains.
- High-volume query bursts are never exempted on CDN domains.
- Legitimate CDN infrastructure exemptions are strictly scoped to benign address queries (A/AAAA/CNAME).
"""

from detection_engine.tunneling_detector import TunnelingDetector


def test_customer_controllable_cloud_domains_not_exempted_from_tunneling():
    """Attackers registering custom subdomains on CloudFront or TrafficManager must be flagged."""
    detector = TunnelingDetector()

    # High entropy base64 payload queried under customer-controlled CloudFront with TXT record
    cf_tunnel = "a8f7b6c5d4e3f2a1b2c3d4e5f6a7b8c9d0.d123456.cloudfront.net"
    is_tunnel, explanation, signals = detector.evaluate(cf_tunnel, qtype="TXT")

    assert is_tunnel is True
    assert "Suspected DNS tunneling" in explanation
    assert any("entropy" in s.lower() for s in signals)
    assert any("favored tunneling record type" in s.lower() for s in signals)


def test_txt_records_on_cdn_infrastructure_are_not_exempted():
    """Favored tunneling record type TXT must never be exempted, even on legitimate CDN domains."""
    detector = TunnelingDetector()

    # Querying a high-entropy TXT record on akamaiedge.net must NOT be exempted
    infra_txt = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c.akamaiedge.net"
    is_tunnel, explanation, signals = detector.evaluate(infra_txt, qtype="TXT")

    assert is_tunnel is True
    assert "Suspected DNS tunneling" in explanation
    assert any("favored tunneling record type 'txt'" in s.lower() for s in signals)


def test_high_volume_bursts_on_cdn_domains_are_not_exempted():
    """Query bursts with randomized subdomains to a CDN apex domain must be detected."""
    detector = TunnelingDetector(burst_queries_per_apex=5, window_seconds=30.0)

    apex = "akamaiedge.net"
    for i in range(4):
        detector.evaluate(f"edge-node-{i}.{apex}", qtype="A")

    # 5th query with high entropy triggers burst + entropy signals
    is_tunnel, explanation, signals = detector.evaluate(
        f"payload-8f7a6b5c4d3e2f1a0b9c8d7e6f.{apex}", qtype="TXT"
    )
    assert is_tunnel is True
    assert any("volume" in s.lower() for s in signals)


def test_narrow_infrastructure_exemption_scoped_to_address_queries():
    """Legitimate CDN hashed hostnames on A/AAAA queries should have entropy/length suppressed."""
    detector = TunnelingDetector()

    # Long hashed CDN edge host lookup for A record
    cdn_a_query = "a1234567890abcdef1234567890abcdef.dscg.akamaiedge.net"
    is_tunnel, explanation, signals = detector.evaluate(cdn_a_query, qtype="A")

    assert is_tunnel is False
    assert "exemption applied" in explanation.lower()
    # High entropy and length signals should have been suppressed
    assert len(signals) == 0
