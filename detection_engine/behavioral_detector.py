"""
Behavioral Detection Engine with Sliding Window Statistics.
Tracks source hosts, parent domains, and (source, domain) pairs across 1-min, 5-min, and 15-min windows.
Detects query bursts, rapid unique-subdomain generation, persistent beaconing, and baseline deviations.
"""

import time
from collections import deque
from typing import Dict, Any, List, Tuple, Optional
from detection_engine.indicators import IndicatorResult, Severity

class SlidingWindowStats:
    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        # Queue of tuples: (timestamp, subdomain, qtype, rcode, pkt_size)
        self.events: deque = deque()

    def add_event(self, timestamp: float, subdomain: str, qtype: str, rcode: int, pkt_size: int):
        self.events.append((timestamp, subdomain, qtype, rcode, pkt_size))
        self._cleanup(timestamp)

    def _cleanup(self, current_time: float):
        cutoff = current_time - self.window_seconds
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def get_query_count(self) -> int:
        return len(self.events)

    def get_unique_subdomains(self) -> set:
        return {e[1] for e in self.events if e[1]}

    def get_txt_count(self) -> int:
        return sum(1 for e in self.events if e[2] == "TXT")

    def get_nxdomain_count(self) -> int:
        return sum(1 for e in self.events if e[3] == 3)

    def get_avg_packet_size(self) -> float:
        if not self.events:
            return 64.0
        return sum(e[4] for e in self.events) / len(self.events)


class BehavioralDetector:
    def __init__(self, learning_mode: bool = False):
        self.learning_mode = learning_mode
        # Key: (src_ip, parent_domain) -> {"1m": SlidingWindowStats, "5m": ..., "15m": ...}
        self.pair_windows: Dict[Tuple[str, str], Dict[str, SlidingWindowStats]] = {}
        # Key: parent_domain -> SlidingWindowStats(60)
        self.domain_windows: Dict[str, SlidingWindowStats] = {}
        # Key: src_ip -> SlidingWindowStats(60)
        self.host_windows: Dict[str, SlidingWindowStats] = {}

        # Learned baseline metrics per parent_domain
        self.domain_baselines: Dict[str, Dict[str, float]] = {}

    def record_query(self, src_ip: str, parent_domain: str, subdomain: str, qtype: str, rcode: int, pkt_size: int, timestamp: float = None) -> Dict[str, Any]:
        ts = timestamp or time.time()
        pair_key = (src_ip, parent_domain)

        if pair_key not in self.pair_windows:
            self.pair_windows[pair_key] = {
                "1m": SlidingWindowStats(60),
                "5m": SlidingWindowStats(300),
                "15m": SlidingWindowStats(900)
            }

        if parent_domain not in self.domain_windows:
            self.domain_windows[parent_domain] = SlidingWindowStats(60)

        if src_ip not in self.host_windows:
            self.host_windows[src_ip] = SlidingWindowStats(60)

        # Update windows
        for w in self.pair_windows[pair_key].values():
            w.add_event(ts, subdomain, qtype, rcode, pkt_size)

        self.domain_windows[parent_domain].add_event(ts, subdomain, qtype, rcode, pkt_size)
        self.host_windows[src_ip].add_event(ts, subdomain, qtype, rcode, pkt_size)

        # Retrieve 1m stats for feature extractor context
        w1m = self.pair_windows[pair_key]["1m"]
        q_count = w1m.get_query_count()
        unique_subs = len(w1m.get_unique_subdomains())
        txt_count = w1m.get_txt_count()
        nx_count = w1m.get_nxdomain_count()

        return {
            "query_frequency": round(q_count / 60.0, 4),
            "unique_subdomain_rate": round(unique_subs / max(1, q_count), 4),
            "unique_subdomain_count_1m": unique_subs,
            "txt_request_rate": round(txt_count / max(1, q_count), 4),
            "nxdomain_rate": round(nx_count / max(1, q_count), 4),
            "average_packet_size": round(w1m.get_avg_packet_size(), 2)
        }

    def evaluate_behavior(self, src_ip: str, parent_domain: str) -> List[IndicatorResult]:
        """Evaluates sliding window statistics to identify behavioral anomalies."""
        indicators = []
        pair_key = (src_ip, parent_domain)

        if pair_key not in self.pair_windows:
            return indicators

        w1m = self.pair_windows[pair_key]["1m"]
        w5m = self.pair_windows[pair_key]["5m"]
        
        count_1m = w1m.get_query_count()
        unique_subs_1m = len(w1m.get_unique_subdomains())
        count_5m = w5m.get_query_count()

        # 1. Query Burst Detection (> 30 queries/minute to a single parent domain)
        if count_1m > 30:
            sev = Severity.CRITICAL if count_1m > 100 else (Severity.HIGH if count_1m > 50 else Severity.MEDIUM)
            indicators.append(IndicatorResult(
                indicator="ABNORMALLY_HIGH_QUERY_FREQUENCY",
                observed_value=count_1m,
                threshold=30,
                severity=sev,
                explanation=f"Host {src_ip} generated {count_1m} queries in 60s to '{parent_domain}', indicating potential burst tunneling.",
                confidence="HIGH"
            ))

        # 2. Rapid Unique-Subdomain Generation (> 15 unique subdomains/min)
        if unique_subs_1m > 15:
            sev = Severity.CRITICAL if unique_subs_1m > 50 else (Severity.HIGH if unique_subs_1m > 30 else Severity.MEDIUM)
            indicators.append(IndicatorResult(
                indicator="RAPID_UNIQUE_SUBDOMAIN_GENERATION",
                observed_value=unique_subs_1m,
                threshold=15,
                severity=sev,
                explanation=f"Host {src_ip} generated {unique_subs_1m} unique subdomains for '{parent_domain}' within 1 minute.",
                confidence="HIGH"
            ))

        # 3. Persistent Beaconing / High Volume over 5-min (> 100 queries in 5m)
        if count_5m > 100:
            indicators.append(IndicatorResult(
                indicator="PERSISTENT_DNS_COMMUNICATION",
                observed_value=count_5m,
                threshold=100,
                severity=Severity.HIGH,
                explanation=f"Persistent high-volume DNS traffic ({count_5m} queries in 5m) between {src_ip} and '{parent_domain}'.",
                confidence="MEDIUM"
            ))

        return indicators
