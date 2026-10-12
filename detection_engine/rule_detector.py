"""
Rule-Based Detection Engine.
Evaluates DNS feature metrics against configurable rule thresholds.
"""

from typing import Dict, Any, List
from detection_engine.indicators import IndicatorResult, Severity

DEFAULT_RULE_CONFIG = {
    "max_subdomain_length": 45,
    "max_label_length": 40,
    "max_label_count": 5,
    "max_encoded_char_ratio": 0.45,
    "txt_rate_threshold": 0.50,
    "large_packet_threshold": 400
}

class RuleDetector:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = {**DEFAULT_RULE_CONFIG, **(config or {})}

    def evaluate(self, features: Dict[str, Any]) -> List[IndicatorResult]:
        indicators: List[IndicatorResult] = []

        subdomain_len = features.get("subdomain_length", 0)
        max_label_len = features.get("maximum_label_length", 0)
        label_count = features.get("label_count", 0)
        digit_ratio = features.get("digit_ratio", 0.0)
        uppercase_ratio = features.get("uppercase_ratio", 0.0)
        txt_rate = features.get("TXT_request_rate", 0.0)
        pkt_size = features.get("average_packet_size", 64.0)

        # 1. Long Subdomain Rule
        if subdomain_len > self.config["max_subdomain_length"]:
            sev = Severity.CRITICAL if subdomain_len > 80 else (Severity.HIGH if subdomain_len > 60 else Severity.MEDIUM)
            indicators.append(IndicatorResult(
                indicator="LONG_SUBDOMAIN",
                observed_value=subdomain_len,
                threshold=self.config["max_subdomain_length"],
                severity=sev,
                explanation=f"Subdomain length ({subdomain_len} chars) exceeded threshold ({self.config['max_subdomain_length']} chars), suggesting embedded payload data.",
                confidence="HIGH"
            ))

        # 2. Suspicious Label Length
        if max_label_len > self.config["max_label_length"]:
            sev = Severity.HIGH if max_label_len > 55 else Severity.MEDIUM
            indicators.append(IndicatorResult(
                indicator="SUSPICIOUS_LABEL_LENGTH",
                observed_value=max_label_len,
                threshold=self.config["max_label_length"],
                severity=sev,
                explanation=f"Maximum label length ({max_label_len} chars) exceeded threshold ({self.config['max_label_length']} chars).",
                confidence="HIGH"
            ))

        # 3. High Label Count
        if label_count > self.config["max_label_count"]:
            indicators.append(IndicatorResult(
                indicator="HIGH_LABEL_COUNT",
                observed_value=label_count,
                threshold=self.config["max_label_count"],
                severity=Severity.LOW if label_count <= 7 else Severity.MEDIUM,
                explanation=f"Domain contains {label_count} labels, exceeding baseline limit of {self.config['max_label_count']}.",
                confidence="MEDIUM"
            ))

        # 4. Encoded Character Ratio
        encoded_char_ratio = digit_ratio + uppercase_ratio
        if encoded_char_ratio > self.config["max_encoded_char_ratio"]:
            indicators.append(IndicatorResult(
                indicator="HIGH_ENCODED_CHAR_RATIO",
                observed_value=round(encoded_char_ratio, 2),
                threshold=self.config["max_encoded_char_ratio"],
                severity=Severity.HIGH if encoded_char_ratio > 0.70 else Severity.MEDIUM,
                explanation=f"High proportion of digits and uppercase characters ({encoded_char_ratio:.2f}) indicates structured base32/64 encoding.",
                confidence="HIGH"
            ))

        # 5. TXT Request Frequency
        if txt_rate >= self.config["txt_rate_threshold"]:
            indicators.append(IndicatorResult(
                indicator="REPEATED_TXT_REQUESTS",
                observed_value=round(txt_rate, 2),
                threshold=self.config["txt_rate_threshold"],
                severity=Severity.HIGH,
                explanation=f"Abnormally high TXT query ratio ({txt_rate:.2f}). TXT records are frequently misused for DNS command & control payloads.",
                confidence="HIGH"
            ))

        # 6. Large DNS Response / Packet Size
        if pkt_size > self.config["large_packet_threshold"]:
            indicators.append(IndicatorResult(
                indicator="LARGE_DNS_RESPONSE",
                observed_value=int(pkt_size),
                threshold=self.config["large_packet_threshold"],
                severity=Severity.MEDIUM,
                explanation=f"DNS packet size ({int(pkt_size)} bytes) is abnormally large (> {self.config['large_packet_threshold']} bytes).",
                confidence="MEDIUM"
            ))

        return indicators
