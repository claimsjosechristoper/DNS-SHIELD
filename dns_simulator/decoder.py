"""
DNS Tunnel Simulator Decoders.
Reconstructs transmitted synthetic payloads from DNS subdomain queries.
"""

import base64
import re
from typing import Dict, Any, Optional, Tuple

class DNSDecoder:
    def __init__(self):
        # Store session state: {session_id: {"encoding": str, "total": int, "chunks": {seq: chunk_str}, "reconstructed": str}}
        self.sessions: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def decode_base32(encoded_str: str) -> str:
        # Add padding back if necessary
        missing_padding = len(encoded_str) % 8
        if missing_padding:
            encoded_str += '=' * (8 - missing_padding)
        b_data = base64.b32encode_bytes if hasattr(base64, 'b32encode_bytes') else None
        return base64.b32decode(encoded_str.upper().encode('utf-8')).decode('utf-8', errors='replace')

    @staticmethod
    def decode_base64_safe(encoded_str: str) -> str:
        # Restore standard base64 URL chars and padding
        encoded_str = encoded_str.replace('-', '_')
        missing_padding = len(encoded_str) % 4
        if missing_padding:
            encoded_str += '=' * (4 - missing_padding)
        return base64.urlsafe_b64decode(encoded_str.encode('utf-8')).decode('utf-8', errors='replace')

    @staticmethod
    def decode_hex(encoded_str: str) -> str:
        return bytes.fromhex(encoded_str).decode('utf-8', errors='replace')

    @classmethod
    def decode_payload(cls, encoded_str: str, method: str = 'base32') -> str:
        method = method.lower()
        if method == 'base32':
            return cls.decode_base32(encoded_str)
        elif method == 'base64':
            return cls.decode_base64_safe(encoded_str)
        elif method == 'hex':
            return cls.decode_hex(encoded_str)
        else:
            raise ValueError(f"Unsupported decoding method: {method}")

    def parse_query(self, domain: str) -> Optional[Tuple[str, int, int, str]]:
        """
        Parses domain string matching pattern: s<session_id>-q<seq>-t<total>-<chunk>.<parent_domain>
        Returns (session_id, seq, total, chunk) if matched, else None.
        """
        pattern = r'^s([a-f0-9]+)-q(\d+)-t(\d+)-([a-zA-Z0-9_-]+)\.'
        match = re.match(pattern, domain)
        if match:
            session_id = match.group(1)
            seq = int(match.group(2))
            total = int(match.group(3))
            chunk = match.group(4)
            return session_id, seq, total, chunk
        return None

    def process_query(self, domain: str, encoding_method: str = 'base32') -> Dict[str, Any]:
        """
        Processes a single incoming query domain, adds chunk to session,
        and reassembles payload if all chunks have arrived.
        """
        parsed = self.parse_query(domain)
        if not parsed:
            return {"status": "non_tunnel", "domain": domain}

        session_id, seq, total, chunk = parsed

        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "session_id": session_id,
                "encoding": encoding_method,
                "total_chunks": total,
                "chunks": {},
                "reconstructed_payload": None,
                "is_complete": False,
                "received_count": 0
            }

        session = self.sessions[session_id]
        if seq not in session["chunks"]:
            session["chunks"][seq] = chunk
            session["received_count"] = len(session["chunks"])

        if len(session["chunks"]) == session["total_chunks"] and not session["is_complete"]:
            # Reconstruct full payload
            ordered_chunks = [session["chunks"][i] for i in sorted(session["chunks"].keys())]
            full_encoded = "".join(ordered_chunks)
            try:
                reconstructed = self.decode_payload(full_encoded, method=session["encoding"])
            except Exception:
                # Fallback to hex/base32 auto-detection if specified method fails
                try:
                    reconstructed = self.decode_base32(full_encoded)
                except Exception:
                    reconstructed = full_encoded

            session["reconstructed_payload"] = reconstructed
            session["is_complete"] = True

        return {
            "status": "complete" if session["is_complete"] else "in_progress",
            "session_id": session_id,
            "seq": seq,
            "total": total,
            "received_count": session["received_count"],
            "reconstructed_payload": session.get("reconstructed_payload")
        }

    def get_session_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self.sessions.get(session_id)
