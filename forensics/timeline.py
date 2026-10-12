"""
Forensics Timeline Generator.
Reconstructs chronological incident timelines from recorded security telemetry.
"""

import time
from typing import List, Dict, Any, Optional

class TimelineGenerator:
    @staticmethod
    def build_chronological_timeline(
        events: List[Dict[str, Any]],
        filter_host: Optional[str] = None,
        filter_domain: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Sorts and formats events into a structured incident investigation timeline.
        """
        timeline = []
        filtered_events = events

        if filter_host:
            filtered_events = [e for e in filtered_events if e.get("src_ip") == filter_host or e.get("parsed", {}).get("src_ip") == filter_host]

        if filter_domain:
            filtered_events = [e for e in filtered_events if filter_domain in e.get("qname", "") or filter_domain in e.get("parsed", {}).get("qname", "")]

        sorted_events = sorted(filtered_events, key=lambda x: x.get("timestamp", 0))

        for idx, evt in enumerate(sorted_events, start=1):
            ts = evt.get("timestamp", time.time())
            formatted_time = evt.get("formatted_time") or time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
            risk_score = evt.get("risk_score", 0)
            status = evt.get("status", "NORMAL")
            qname = evt.get("qname") or evt.get("parsed", {}).get("qname", "")
            src_ip = evt.get("src_ip") or evt.get("parsed", {}).get("src_ip", "127.0.0.1")
            qtype = evt.get("qtype") or evt.get("parsed", {}).get("qtype", "A")

            indicators = evt.get("indicators", [])
            ind_names = [i.get("indicator") for i in indicators if isinstance(i, dict)]

            timeline_entry = {
                "step_number": idx,
                "timestamp": ts,
                "formatted_time": formatted_time,
                "source_ip": src_ip,
                "qname": qname,
                "qtype": qtype,
                "risk_score": risk_score,
                "status": status,
                "indicators": ind_names,
                "reasoning": evt.get("reasoning", "")
            }
            timeline.append(timeline_entry)

        return timeline
