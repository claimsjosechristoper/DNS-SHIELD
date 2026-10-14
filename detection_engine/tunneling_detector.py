"""
Explainable Multi-Signal DNS Tunneling Detection Engine.

Detects suspected DNS tunneling anomalies using observable signals over bounded
time windows without probabilistic machine learning or numerical risk scores.
Every decision provides clear, deterministic diagnostic explanations.

Security Architecture Note on Cloud/CDN Exceptions:
Public cloud hosting (AWS, Azure, GCP, CloudFront, TrafficManager) is NOT proof of safety.
Attackers routinely register multi-tenant cloud resources (e.g. custom CloudFront distributions,
Azure Traffic Manager profiles, S3 buckets) to tunnel data or establish C2 channels.
Therefore:
1. Customer-controlled multi-tenant domains are NOT exempt from tunneling inspection.
2. Narrow exceptions apply ONLY to verified non-customer-registrable CDN infrastructure domains
   (e.g., akamaiedge.net, windowsupdate.com).
3. Even on infrastructure domains, exemptions ONLY suppress benign label entropy/length heuristics
   on standard address queries (A/AAAA/CNAME). They NEVER exempt favored tunneling record types
   (TXT, NULL) or abnormal query volume bursts.
"""

import math
import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

# Legitimate, non-customer-registrable CDN/vendor infrastructure domains
NARROW_INFRASTRUCTURE_DOMAINS: Set[str] = {
    "akamaiedge.net",
    "akamai.net",
    "windowsupdate.com",
    "gstatic.com",
    "apple-dns.net",
}


def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy (information density) of a string."""
    if not text:
        return 0.0
    length = len(text)
    frequencies = defaultdict(int)
    for char in text:
        frequencies[char] += 1
    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


class TunnelingDetector:
    """
    Explainable DNS tunneling heuristic analyzer.
    Combines label entropy, query length, record type, and time-bounded domain frequency.
    """

    def __init__(
        self,
        entropy_threshold: float = 3.8,
        label_length_threshold: int = 35,
        burst_queries_per_apex: int = 15,
        window_seconds: float = 60.0,
        infrastructure_domains: Optional[Set[str]] = None,
    ):
        self.entropy_threshold = entropy_threshold
        self.label_length_threshold = label_length_threshold
        self.burst_queries_per_apex = burst_queries_per_apex
        self.window_seconds = window_seconds
        self.infrastructure_domains = infrastructure_domains or set(NARROW_INFRASTRUCTURE_DOMAINS)

        # Apex domain -> list of timestamps
        self._domain_history: Dict[str, List[float]] = defaultdict(list)
        self._last_cleanup = time.time()

    def _extract_apex_and_subdomain(self, domain: str) -> Tuple[str, str]:
        """Separates the leftmost label (subdomain chunk) from the registered apex domain."""
        parts = domain.lower().rstrip(".").split(".")
        if len(parts) <= 2:
            return domain, parts[0] if parts else ""
        subdomain = parts[0]
        apex = ".".join(parts[-2:])
        return apex, subdomain

    def evaluate(
        self, domain: str, qtype: str = "A", client_ip: str = "127.0.0.1"
    ) -> Tuple[bool, str, List[str]]:
        """
        Evaluates domain query against multiple observable signals.
        Returns:
            (is_suspected_tunneling: bool, explanation: str, observed_signals: List[str])
        """
        clean_domain = domain.lower().rstrip(".")
        apex, leftmost = self._extract_apex_and_subdomain(clean_domain)
        qtype_upper = qtype.upper()

        # Check if domain matches verified infrastructure
        is_infra = any(
            clean_domain == infra or clean_domain.endswith("." + infra)
            for infra in self.infrastructure_domains
        )

        now = time.time()
        # Periodic cleanup of domain frequency history
        if now - self._last_cleanup > self.window_seconds:
            self._cleanup_history(now)

        signals: List[str] = []
        exempted_notes: List[str] = []

        # Signal A: Shannon Entropy of the leftmost payload label
        entropy = calculate_shannon_entropy(leftmost)
        has_high_entropy = (entropy >= self.entropy_threshold and len(leftmost) >= 12)

        # Signal B: Unusually long label length
        has_excessive_length = (len(leftmost) >= self.label_length_threshold)

        # Narrow exception scoping:
        # If domain is verified infrastructure AND query is standard address (A, AAAA, CNAME),
        # suppress Signal A and B to prevent false positives from CDN hash hostnames.
        if is_infra and qtype_upper in ("A", "AAAA", "CNAME"):
            if has_high_entropy:
                exempted_notes.append("High entropy suppressed for verified CDN infrastructure address lookup")
            if has_excessive_length:
                exempted_notes.append("Label length suppressed for verified CDN infrastructure address lookup")
        else:
            if has_high_entropy:
                signals.append(
                    f"High label entropy ({entropy:.2f} >= threshold {self.entropy_threshold:.2f})"
                )
            if has_excessive_length:
                signals.append(
                    f"Excessive label length ({len(leftmost)} chars >= threshold {self.label_length_threshold})"
                )

        # Signal C: Record type commonly abused for exfiltration/C2 channels (TXT, NULL)
        # NEVER exempted, even on infrastructure domains!
        if qtype_upper in ("TXT", "NULL"):
            signals.append(f"Favored tunneling record type '{qtype_upper}'")

        # Signal D: High query burst to the same apex domain with distinct prefixes
        # NEVER exempted, even on infrastructure domains!
        history = self._domain_history[apex]
        history.append(now)
        # Prune old timestamps
        cutoff = now - self.window_seconds
        while history and history[0] < cutoff:
            history.pop(0)

        if len(history) >= self.burst_queries_per_apex:
            signals.append(
                f"Abnormal query volume to apex '{apex}' ({len(history)} queries in {int(self.window_seconds)}s)"
            )

        # Decision Rule: At least two distinct signals must correlate to suspect tunneling
        if len(signals) >= 2:
            explanation = (
                f"Suspected DNS tunneling on '{clean_domain}': " + "; ".join(signals)
            )
            return True, explanation, signals

        if exempted_notes:
            return False, "Legitimate CDN infrastructure address query (entropy/length scoped exemption applied).", signals

        return False, "Query within expected traffic baseline.", signals

    def _cleanup_history(self, now: float):
        cutoff = now - self.window_seconds
        empty_keys = []
        for apex, timestamps in self._domain_history.items():
            while timestamps and timestamps[0] < cutoff:
                timestamps.pop(0)
            if not timestamps:
                empty_keys.append(apex)
        for k in empty_keys:
            del self._domain_history[k]
        self._last_cleanup = now
