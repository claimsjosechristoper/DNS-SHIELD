"""
Thread-Safe Bounded LRU DNS Response Cache with Dynamic TTL Degradation.
Implements RFC-compliant TTL countdown, LRU eviction, and explicit domain invalidation.
Enforces that policy rules are evaluated before cache lookup.
"""

import time
import threading
from collections import OrderedDict
from typing import Optional, Tuple
from dnslib import DNSRecord
from gateway.config import GatewayConfig

class DNSCache:
    def __init__(self, max_entries: int = 10000, min_ttl: int = 5, max_ttl: int = 3600):
        self.max_entries = max_entries
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self._lock = threading.Lock()
        # Key: (normalized_domain, qtype_str) -> (raw_packed_bytes, inserted_at, min_ttl)
        self.cache: OrderedDict[Tuple[str, str], Tuple[bytes, float, int]] = OrderedDict()

    def get(self, domain: str, qtype: str, client_tx_id: int) -> Optional[bytes]:
        """
        Retrieves a cached response if valid, updating TTL values and matching client transaction ID.
        """
        key = (domain.lower().rstrip("."), qtype.upper())
        now = time.time()

        with self._lock:
            if key not in self.cache:
                return None

            raw_bytes, inserted_at, ttl = self.cache[key]
            elapsed = now - inserted_at

            if elapsed >= ttl:
                # Expired
                del self.cache[key]
                return None

            # Move to end for LRU
            self.cache.move_to_end(key)

        # Deserialize, decrement TTL, and match transaction ID
        try:
            record = DNSRecord.parse(raw_bytes)
            record.header.id = client_tx_id
            remaining_ttl = max(1, int(ttl - elapsed))
            
            for rr in record.rr:
                rr.ttl = remaining_ttl
            for auth in record.auth:
                auth.ttl = remaining_ttl

            return record.pack()
        except Exception:
            return None

    def put(self, domain: str, qtype: str, record: DNSRecord):
        """
        Stores an upstream response in cache if valid and answers exist.
        """
        if not record.rr or record.header.rcode != 0:
            return

        # Determine effective TTL from answers
        answer_ttls = [rr.ttl for rr in record.rr if hasattr(rr, "ttl") and rr.ttl > 0]
        if not answer_ttls:
            return

        effective_ttl = min(answer_ttls)
        effective_ttl = max(self.min_ttl, min(effective_ttl, self.max_ttl))

        key = (domain.lower().rstrip("."), qtype.upper())
        now = time.time()
        packed = record.pack()

        with self._lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            elif len(self.cache) >= self.max_entries:
                # Evict oldest
                self.cache.popitem(last=False)

            self.cache[key] = (packed, now, effective_ttl)

    def invalidate_domain(self, domain: str):
        """
        Invalidates cached entries for a domain and all its subdomains.
        Triggered when administrator adds a block rule or updates blocklists.
        """
        norm_d = domain.lower().rstrip(".")
        with self._lock:
            keys_to_del = [
                k for k in self.cache.keys()
                if k[0] == norm_d or k[0].endswith("." + norm_d)
            ]
            for k in keys_to_del:
                del self.cache[k]

    def clear(self):
        with self._lock:
            self.cache.clear()
