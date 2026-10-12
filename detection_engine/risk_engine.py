"""
DNS Tunnel Risk Engine and Explainable Detection Fusion Module.
Calculates 0-100 Composite Risk Score fusing Rules, Entropy, Behavioral windowing, and ML Anomaly score.
Maps detections to MITRE ATT&CK T1071.004 (DNS).
"""

from typing import Dict, Any, List, Optional
from detection_engine.indicators import IndicatorResult, Severity
from detection_engine.entropy_detector import EntropyDetector
from detection_engine.rule_detector import RuleDetector
from detection_engine.behavioral_detector import BehavioralDetector
from ml_engine.predict import MLAnomalyDetector

class RiskEngine:
    def __init__(
        self,
        entropy_detector: Optional[EntropyDetector] = None,
        rule_detector: Optional[RuleDetector] = None,
        behavioral_detector: Optional[BehavioralDetector] = None,
        ml_detector: Optional[MLAnomalyDetector] = None
    ):
        self.entropy_detector = entropy_detector or EntropyDetector()
        self.rule_detector = rule_detector or RuleDetector()
        self.behavioral_detector = behavioral_detector or BehavioralDetector()
        self.ml_detector = ml_detector or MLAnomalyDetector()

    def analyze_query(
        self,
        parsed_packet: Dict[str, Any],
        features: Dict[str, Any]
    ) -> Dict[str, Any]:
        src_ip = parsed_packet.get("src_ip", "127.0.0.1")
        parent_domain = parsed_packet.get("parent_domain", "")
        subdomain = parsed_packet.get("subdomain", "")
        qtype = parsed_packet.get("qtype", "A")
        rcode = parsed_packet.get("rcode", 0)
        pkt_size = parsed_packet.get("packet_size", 64)

        # 1. Update Behavioral Window statistics
        hist_stats = self.behavioral_detector.record_query(
            src_ip=src_ip,
            parent_domain=parent_domain,
            subdomain=subdomain,
            qtype=qtype,
            rcode=rcode,
            pkt_size=pkt_size
        )

        # Update features with window statistics
        features.update(hist_stats)

        # 2. Execute Detection Components
        entropy_indicator = self.entropy_detector.detect(features)
        rule_indicators = self.rule_detector.evaluate(features)
        behavioral_indicators = self.behavioral_detector.evaluate_behavior(src_ip, parent_domain)
        ml_result = self.ml_detector.predict(features)

        # Combine all indicators
        all_indicators: List[IndicatorResult] = []
        if entropy_indicator.severity != Severity.NORMAL:
            all_indicators.append(entropy_indicator)
        all_indicators.extend(rule_indicators)
        all_indicators.extend(behavioral_indicators)

        # 3. Calculate Component Sub-scores (0-100 scale)
        # Rule sub-score
        rule_score = 0.0
        for ind in rule_indicators:
            if ind.severity == Severity.CRITICAL:
                rule_score += 40.0
            elif ind.severity == Severity.HIGH:
                rule_score += 25.0
            elif ind.severity == Severity.MEDIUM:
                rule_score += 15.0
            elif ind.severity == Severity.LOW:
                rule_score += 5.0
        rule_score = min(100.0, rule_score)

        # Entropy sub-score
        ent_val = features.get("shannon_entropy", 0.0)
        entropy_score = max(0.0, min(100.0, (ent_val - 3.2) * 45.0)) if ent_val > 3.2 else 0.0

        # Behavioral sub-score
        beh_score = 0.0
        for ind in behavioral_indicators:
            if ind.severity == Severity.CRITICAL:
                beh_score += 50.0
            elif ind.severity == Severity.HIGH:
                beh_score += 30.0
            elif ind.severity == Severity.MEDIUM:
                beh_score += 15.0
        beh_score = min(100.0, beh_score)

        # ML sub-score
        ml_score = ml_result["anomaly_score"] * 100.0

        # 4. Composite Formula Weighting
        # Formula: 0.35 * Rule + 0.25 * Entropy + 0.25 * Behavior + 0.15 * ML
        composite_score = (0.35 * rule_score) + (0.25 * entropy_score) + (0.25 * beh_score) + (0.15 * ml_score)
        final_risk_score = int(round(min(100.0, max(0.0, composite_score))))

        # 5. Risk Category Classification
        if final_risk_score >= 80:
            classification = Severity.CRITICAL
            status_text = "TUNNEL SUSPECTED"
        elif final_risk_score >= 60:
            classification = Severity.HIGH
            status_text = "TUNNEL SUSPECTED"
        elif final_risk_score >= 40:
            classification = Severity.MEDIUM
            status_text = "SUSPICIOUS"
        elif final_risk_score >= 20:
            classification = Severity.LOW
            status_text = "SUSPICIOUS"
        else:
            classification = Severity.NORMAL
            status_text = "NORMAL"

        # 6. Generate Explainable Reasoning Summary
        explanation_lines = []
        if all_indicators:
            top_reasons = [ind.indicator.replace('_', ' ').title() for ind in all_indicators[:3]]
            explanation_lines.append(f"Reason: High correlation across [{', '.join(top_reasons)}].")
        if ml_result["is_anomalous"]:
            explanation_lines.append(f"ML Model: Flagged as anomalous (Anomaly Index: {ml_result['anomaly_score']:.2f}).")
        if not explanation_lines:
            explanation_lines.append("Reason: All statistical metrics are within expected benign baseline limits.")

        reasoning = " ".join(explanation_lines)

        # 7. MITRE ATT&CK Mapping
        mitre_mapping = {
            "technique_id": "T1071.004",
            "technique_name": "Application Layer Protocol: DNS",
            "tactic": "Command and Control / Exfiltration",
            "observed_behavior": f"High entropy/frequency DNS queries for '{parent_domain}'",
            "detection_hypothesis": "Covert DNS tunneling session embedding structured payload chunks in host subdomains.",
            "status": "SUSPICIOUS / INVESTIGATION REQUIRED" if final_risk_score >= 40 else "BENIGN BASELINE"
        }

        return {
            "risk_score": final_risk_score,
            "classification": classification.value,
            "status": status_text,
            "reasoning": reasoning,
            "indicators": [ind.to_dict() for ind in all_indicators],
            "sub_scores": {
                "rule_score": round(rule_score, 1),
                "entropy_score": round(entropy_score, 1),
                "behavioral_score": round(beh_score, 1),
                "ml_score": round(ml_score, 1)
            },
            "features": features,
            "ml_result": ml_result,
            "mitre_mapping": mitre_mapping
        }
