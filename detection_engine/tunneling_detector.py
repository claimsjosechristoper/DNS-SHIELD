"""
Explainable Multi-Signal DNS Tunneling Detection Engine.

Detects suspected DNS tunneling anomalies using observable signals over bounded
time windows without probabilistic machine learning or numerical risk scores.
Every decision provides clear, deterministic diagnostic explanations.
"""

import math
import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

# Legitimate cloud/CDN platforms that frequently use long or hashed subdomains
DEFAULT_CDN_ALLOWLIST: Set[str] = {
    "akamaiedge.net",
    "akamai.net",
    "cloudfront.net",
    "azureedge.net",
    "trafficmanager.net",
    "amazonaws.com",
    "googleapis.com",
    "gstatic.com",
    "microsoft.com",
    "windowsupdate.com",
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
        cdn_allowlist: Optional[Set[str]] = None,
    ):
        self.entropy_threshold = entropy_threshold
        self.label_length_threshold = label_length_threshold
        self.burst_queries_per_apex = burst_queries_per_apex
        self.window_seconds = window_seconds
        self.cdn_allowlist = cdn_allowlist or set(DEFAULT_CDN_ALLOWLIST)

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

        # 1. Exempt legitimate CDN/Cloud domains
        for cdn in self.cdn_allowlist:
            if clean_domain == cdn or clean_domain.endswith("." + cdn):
                return False, "Domain matched legitimate CDN/Cloud infrastructure exemption.", []

        now = time.time()
        # Periodic cleanup of domain frequency history
        if now - self._last_cleanup > self.window_seconds:
            self._cleanup_history(now)

        signals: List[str] = []

        # Signal A: Shannon Entropy of the leftmost payload label
        entropy = calculate_shannon_entropy(leftmost)
        if entropy >= self.entropy_threshold and len(leftmost) >= 12:
            signals.append(
                f"High label entropy ({entropy:.2f} >= threshold {self.entropy_threshold:.2f})"
            )

        # Signal B: Unusually long label length
        if len(leftmost) >= self.label_length_threshold:
            signals.append(
                f"Excessive label length ({len(leftmost)} chars >= threshold {self.label_length_threshold})"
            )

        # Signal C: Record type commonly abused for exfiltration/C2 channels (TXT, NULL)
        if qtype.upper() in ("TXT", "NULL"):
            signals.append(f"Favored tunneling record type '{qtype}'")

        # Signal D: High query burst to the same apex domain with distinct prefixes
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
