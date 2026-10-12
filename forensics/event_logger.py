"""
Event Logger & Privacy Preserving Telemetry Manager.
Logs DNS security events to memory and disk.
Supports privacy masking for IP address anonymization.
"""

import os
import json
import time
import hashlib
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("DNSShield.EventLogger")

class EventLogger:
    def __init__(self, log_dir: str = os.path.join("data", "events"), mask_ips: bool = False):
        self.log_dir = log_dir
        self.mask_ips = mask_ips
        os.makedirs(self.log_dir, exist_ok=True)
        self.events_file = os.path.join(self.log_dir, "dns_events.jsonl")
        self.event_buffer: List[Dict[str, Any]] = []

    def set_privacy_mode(self, mask_ips: bool):
        self.mask_ips = mask_ips
        logger.info(f"Privacy-preserving IP masking set to: {self.mask_ips}")

    def anonymize_ip(self, ip_address: str) -> str:
        """
        Hashes/masks source IP addresses to preserve privacy.
        Example: '192.168.1.54' -> 'anon-a4f18d7b'
        
        Why this helps: Enables security analysts to track unique host telemetry patterns
        without violating privacy compliance regulations or storing PII.
        """
        if not self.mask_ips or ip_address in ("127.0.0.1", "localhost", "::1"):
            return ip_address
        
        salt = "DNS-SHIELD-PRIVACY-SALT-2026"
        hashed = hashlib.sha256(f"{salt}:{ip_address}".encode('utf-8')).hexdigest()[:8]
        return f"anon-{hashed}"

    def log_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Logs a single processed DNS query/alert event."""
        event_copy = dict(event)
        event_copy["id"] = event_copy.get("id") or f"evt-{int(time.time()*1000)}-{len(self.event_buffer)}"
        event_copy["timestamp"] = event_copy.get("timestamp") or time.time()
        event_copy["formatted_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event_copy["timestamp"]))
        
        # Apply IP anonymization if privacy mode is active
        if "src_ip" in event_copy:
            event_copy["src_ip"] = self.anonymize_ip(event_copy["src_ip"])
        if "parsed" in event_copy and "src_ip" in event_copy["parsed"]:
            event_copy["parsed"]["src_ip"] = self.anonymize_ip(event_copy["parsed"]["src_ip"])

        self.event_buffer.append(event_copy)
        if len(self.event_buffer) > 5000:
            self.event_buffer.pop(0)

        # Write to JSONL
        try:
            with open(self.events_file, "a") as f:
                f.write(json.dumps(event_copy) + "\n")
        except Exception as e:
            logger.error(f"Failed to append event to disk: {e}")

        return event_copy

    def get_events(self, limit: int = 100, min_risk: int = 0) -> List[Dict[str, Any]]:
        filtered = [e for e in self.event_buffer if e.get("risk_score", 0) >= min_risk]
        return filtered[-limit:]

    def get_suspicious_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [e for e in self.event_buffer if e.get("risk_score", 0) >= 40][-limit:]
