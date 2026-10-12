"""
Entropy Detector Module.
Analyzes Shannon entropy of DNS queries and evaluates against configurable thresholds.
"""

from typing import Dict, Any
from detection_engine.indicators import IndicatorResult, Severity

DEFAULT_ENTROPY_THRESHOLDS = {
    "LOW": 3.8,
    "MEDIUM": 4.2,
    "HIGH": 4.6,
    "CRITICAL": 5.2
}

class EntropyDetector:
    def __init__(self, thresholds: Dict[str, float] = None):
        self.thresholds = thresholds or DEFAULT_ENTROPY_THRESHOLDS

    def detect(self, features: Dict[str, Any]) -> IndicatorResult:
        entropy = features.get("shannon_entropy", 0.0)
        subdomain = features.get("subdomain", "")
        target = subdomain if subdomain else features.get("qname", "")

        severity = Severity.NORMAL
        threshold = self.thresholds["LOW"]

        if entropy >= self.thresholds["CRITICAL"]:
            severity = Severity.CRITICAL
            threshold = self.thresholds["CRITICAL"]
        elif entropy >= self.thresholds["HIGH"]:
            severity = Severity.HIGH
            threshold = self.thresholds["HIGH"]
        elif entropy >= self.thresholds["MEDIUM"]:
            severity = Severity.MEDIUM
            threshold = self.thresholds["MEDIUM"]
        elif entropy >= self.thresholds["LOW"]:
            severity = Severity.LOW
            threshold = self.thresholds["LOW"]

        explanation = (
            f"Observed Shannon entropy of {entropy:.2f} on '{target}' "
            f"exceeded configured {severity.value} threshold of {threshold:.2f}. "
            "High character randomness indicates encoded/encrypted DNS payload chunking."
        ) if severity != Severity.NORMAL else (
            f"Shannon entropy of {entropy:.2f} is within normal baseline limits (< {self.thresholds['LOW']:.2f})."
        )

        return IndicatorResult(
            indicator="HIGH_ENTROPY",
            observed_value=round(entropy, 2),
            threshold=threshold,
            severity=severity,
            explanation=explanation,
            confidence="HIGH" if severity in (Severity.HIGH, Severity.CRITICAL) else "MEDIUM"
        )
