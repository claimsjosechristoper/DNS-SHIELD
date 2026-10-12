"""
Synthetic Data Generator for DNS-SHIELD Lab Demonstrations.
Provides safe synthetic demonstration payloads and benign baseline DNS queries.
"""

import random
from typing import List

BENIGN_DOMAINS = [
    "google.com",
    "www.google.com",
    "api.github.com",
    "github.com",
    "microsoft.com",
    "update.microsoft.com",
    "aws.amazon.com",
    "s3.amazonaws.com",
    "cdn.jsdelivr.net",
    "fonts.googleapis.com",
    "slack.com",
    "api.slack.com",
    "cloudflare.com",
    "1.1.1.1",
    "schema.org",
    "stackoverlow.com",
    "pypi.org",
    "python.org",
    "wikipedia.org",
    "en.wikipedia.org"
]

BENIGN_SUBDOMAINS = [
    "mail", "dev", "staging", "api", "auth", "cdn", "img", "static", "docs", "app"
]

SYNTHETIC_LAB_PAYLOADS = [
    "DNS-SHIELD-LAB-DEMO-PAYLOAD-001",
    "CONFIDENTIAL-LAB-TEST-HEARTBEAT-STATUS-OK",
    "SYSTEM-METRICS: CPU=12% MEM=43% DISK=22% IP=127.0.0.1",
    "SYNTHETIC-DATA-EXCHANGE-LAB-DEMO-2026-SECURITY-RESEARCH",
    "EDUCATIONAL-DNS-TUNNEL-SIMULATION-CHUNK-VERIFICATION-PASS"
]

class SyntheticDataGenerator:
    @staticmethod
    def get_random_benign_query() -> str:
        """Return a typical benign DNS hostname."""
        domain = random.choice(BENIGN_DOMAINS)
        if random.random() > 0.5:
            prefix = random.choice(BENIGN_SUBDOMAINS)
            return f"{prefix}.{domain}"
        return domain

    @staticmethod
    def get_synthetic_tunnel_payload() -> str:
        """Return a safe synthetic demonstration payload."""
        return random.choice(SYNTHETIC_LAB_PAYLOADS)

    @staticmethod
    def get_burst_queries(count: int = 20, domain_suffix: str = "burst.lab.dnsshield.local") -> List[str]:
        """Generate a burst of unique subdomains to simulate rapid querying."""
        queries = []
        for i in range(count):
            rand_hex = f"{random.randint(10000, 99999):x}"
            queries.append(f"node-{i}-{rand_hex}.{domain_suffix}")
        return queries

    @staticmethod
    def get_txt_payload_query(domain_suffix: str = "txtdemo.lab.dnsshield.local") -> str:
        """Generate TXT-oriented query for TXT tunneling simulation."""
        rand_token = random.choice(["status", "report", "config", "keyex", "heartbeat"])
        rand_hash = f"{random.randint(100000, 999999):x}"
        return f"query-{rand_token}-{rand_hash}.{domain_suffix}"
