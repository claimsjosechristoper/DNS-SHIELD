"""
Evidence Exporter Module.
Generates structured JSON and CSV forensic incident reports for SOC investigation and evidence retention.
"""

import os
import csv
import json
import time
import uuid
from typing import Dict, Any, List, Optional, Tuple

class EvidenceExporter:
    def __init__(self, reports_dir: str = os.path.join("data", "reports")):
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

    @staticmethod
    def get_defensive_recommendation(severity: str, indicators: List[Dict[str, Any]]) -> List[str]:
        """Provides actionable SOC playbooks based on triggered indicators and severity."""
        recommendations = [
            "Monitor source host DNS query velocity for baseline drift.",
            "Verify parent domain reputation and WHOIS creation timestamp."
        ]

        ind_keys = [i.get("indicator") if isinstance(i, dict) else str(i) for i in indicators]

        if "HIGH_ENTROPY" in ind_keys or "LONG_SUBDOMAIN" in ind_keys:
            recommendations.append("Isolate host endpoint and inspect active processes querying local DNS resolvers.")
            recommendations.append("Block parent domain on enterprise DNS firewall / RPZ (Response Policy Zone).")

        if "REPEATED_TXT_REQUESTS" in ind_keys:
            recommendations.append("Restrict outbound UDP/53 and TCP/53 to authorized internal DNS recursive resolvers.")
            recommendations.append("Inspect TXT payload responses for embedded base64/32 command structures.")

        if severity in ("HIGH", "CRITICAL"):
            recommendations.append("Initiate formal Incident Response (IR) triage for MITRE ATT&CK T1071.004.")

        return recommendations

    def generate_incident_report(
        self,
        event_data: Dict[str, Any],
        output_format: str = "json"
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Generates structured incident report dictionary and exports to JSON or CSV file.
        """
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        ts = event_data.get("timestamp", time.time())
        formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        
        parsed = event_data.get("parsed", {})
        src = event_data.get("src_ip") or parsed.get("src_ip", "127.0.0.1")
        domain = event_data.get("qname") or parsed.get("qname", "unknown")
        parent_domain = parsed.get("parent_domain", domain)

        risk_score = event_data.get("risk_score", 0)
        severity = event_data.get("classification", "NORMAL")
        indicators = event_data.get("indicators", [])
        features = event_data.get("features", {})
        ml_result = event_data.get("ml_result", {})
        explanation = event_data.get("reasoning", "No anomaly detected.")

        recs = self.get_defensive_recommendation(severity, indicators)

        report = {
            "incident_id": incident_id,
            "timestamp": ts,
            "formatted_time": formatted_time,
            "source": src,
            "domain": domain,
            "parent_domain": parent_domain,
            "risk_score": risk_score,
            "severity": severity,
            "indicators": indicators,
            "feature_values": features,
            "ML_result": ml_result,
            "explanation": explanation,
            "recommended_defensive_action": recs,
            "mitre_mapping": event_data.get("mitre_mapping", {})
        }

        if output_format.lower() == "csv":
            filename = f"{incident_id}.csv"
            filepath = os.path.join(self.reports_dir, filename)
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Incident ID", "Timestamp", "Source IP", "Domain", "Risk Score", "Severity", "Explanation"])
                writer.writerow([incident_id, formatted_time, src, domain, risk_score, severity, explanation])
        else:
            filename = f"{incident_id}.json"
            filepath = os.path.join(self.reports_dir, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

        return filepath, report
