"""
Thread-Safe Per-Client Rate Limiter.
Enforces requests-per-minute thresholds and burst limits per client IP
to protect gateway resources and mitigate DNS flood attacks.
"""

import time
import threading
from typing import Dict, List, Tuple, Optional
from gateway.config import GatewayConfig

class RateLimiter:
    def __init__(self, default_rpm: int = 600, burst_limit: int = 60):
        self.default_rpm = default_rpm
        self.burst_limit = burst_limit
        self._lock = threading.Lock()
        # client_ip -> list of request timestamps within last 60s
        self.client_history: Dict[str, List[float]] = {}
        # client_ip -> custom rpm
        self.custom_limits: Dict[str, int] = {}
        self.last_cleanup = time.time()

    def set_client_limit(self, client_ip: str, rpm: int):
        with self._lock:
            self.custom_limits[client_ip] = rpm

    def is_allowed(self, client_ip: str) -> Tuple[bool, str]:
        """
        Evaluates whether a request from client_ip is allowed under current rate limits.
        Returns:
            (allowed: bool, reason: str)
        """
        now = time.time()
        with self._lock:
            # Periodic cleanup of records older than 120s every 60 seconds
            if now - self.last_cleanup > 60:
                self._cleanup_idle(now)

            rpm = self.custom_limits.get(client_ip, self.default_rpm)
            window_start = now - 60.0

            history = self.client_history.setdefault(client_ip, [])
            # Prune events older than 60s
            while history and history[0] < window_start:
                history.pop(0)

            # Check burst limit in last 1 second
            one_sec_start = now - 1.0
            burst_count = sum(1 for t in history if t >= one_sec_start)
            if burst_count >= self.burst_limit:
                return False, f"Rate limit exceeded: {burst_count} req/sec exceeds burst threshold of {self.burst_limit}"

            # Check rolling 60-second limit
            if len(history) >= rpm:
                return False, f"Rate limit exceeded: {len(history)} req/min exceeds threshold of {rpm} RPM"

            # Allow and record timestamp
            history.append(now)
            return True, ""

    def _cleanup_idle(self, now: float):
        cutoff = now - 120.0
        empty_ips = []
        for ip, history in self.client_history.items():
            while history and history[0] < cutoff:
                history.pop(0)
            if not history:
                empty_ips.append(ip)
        for ip in empty_ips:
            del self.client_history[ip]
        self.last_cleanup = now
