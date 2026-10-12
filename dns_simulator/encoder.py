"""
DNS Tunnel Simulator Encoders.
Supports Base32, Base64 (DNS-safe), and Hexadecimal encoding and subdomain chunking.
"""

import base64
import math
import uuid
from typing import List, Tuple, Dict, Any

class DNSEncoder:
    @staticmethod
    def encode_base32(data: str) -> str:
        """Encode UTF-8 string to lower-case Base32 without padding."""
        b_data = data.encode('utf-8')
        encoded = base64.b32encode(b_data).decode('utf-8').rstrip('=').lower()
        return encoded

    @staticmethod
    def encode_base64_safe(data: str) -> str:
        """Encode UTF-8 string to URL/DNS safe Base64 without padding."""
        b_data = data.encode('utf-8')
        encoded = base64.urlsafe_b64encode(b_data).decode('utf-8').rstrip('=').replace('_', '-')
        return encoded

    @staticmethod
    def encode_hex(data: str) -> str:
        """Encode UTF-8 string to lower-case hex."""
        return data.encode('utf-8').hex().lower()

    @classmethod
    def encode_payload(cls, data: str, method: str = 'base32') -> str:
        method = method.lower()
        if method == 'base32':
            return cls.encode_base32(data)
        elif method == 'base64':
            return cls.encode_base64_safe(data)
        elif method == 'hex':
            return cls.encode_hex(data)
        else:
            raise ValueError(f"Unsupported encoding method: {method}")

    @classmethod
    def create_tunnel_queries(
        cls,
        payload: str,
        encoding_method: str = 'base32',
        parent_domain: str = 'lab.dnsshield.local',
        chunk_size: str = 30,
        session_id: str = None
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Encodes a synthetic payload, splits it into DNS-safe labels,
        and constructs subdomains with session and sequence headers.
        
        Format: s<session_id>-q<seq>-t<total>-<chunk>.<parent_domain>
        """
        if not session_id:
            session_id = uuid.uuid4().hex[:6]

        encoded_data = cls.encode_payload(payload, method=encoding_method)

        # Split encoded data into chunks of max chunk_size (max DNS label length is 63)
        chunks = [encoded_data[i:i + chunk_size] for i in range(0, len(encoded_data), chunk_size)]
        total_chunks = len(chunks)

        queries = []
        for seq, chunk in enumerate(chunks, start=1):
            subdomain = f"s{session_id}-q{seq:03d}-t{total_chunks:03d}-{chunk}.{parent_domain}"
            queries.append(subdomain)

        metadata = {
            "session_id": session_id,
            "original_payload": payload,
            "encoding_method": encoding_method,
            "encoded_data": encoded_data,
            "total_chunks": total_chunks,
            "chunk_size": chunk_size,
            "parent_domain": parent_domain
        }

        return session_id, queries, metadata
