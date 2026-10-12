"""
DNS Feature Extractor Module.
Calculates 15 numerical and statistical features per DNS request/stream.
Implements mathematical Shannon Entropy without external library dependencies.
"""

import math
from typing import Dict, Any, List

class FeatureExtractor:
    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """
        Calculates mathematical Shannon Entropy: H(X) = - sum( P(x_i) * log2(P(x_i)) )
        
        Why high entropy indicates encoded DNS payloads:
        Natural language domain names (e.g., 'google.com', 'mail.corp.com') use common English vowel/consonant
        patterns with predictable letter frequencies, yielding low entropy (typically 2.0 to 3.8).
        Encoded DNS tunnel payloads (Base32, Base64, Hex, encrypted strings) distribute characters much more
        uniformly across the character set, maximizing randomness and pushing Shannon entropy significantly
        higher (typically 4.0 to 5.8+).
        """
        if not text:
            return 0.0
        
        length = len(text)
        frequency: Dict[str, int] = {}
        for char in text:
            frequency[char] = frequency.get(char, 0) + 1

        entropy = 0.0
        for count in frequency.values():
            p = count / length
            entropy -= p * math.log2(p)

        return round(entropy, 4)

    @classmethod
    def extract_features(
        cls,
        parsed_packet: Dict[str, Any],
        historical_stats: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Extracts 15 key statistical and structural features from parsed DNS query data.
        """
        qname = parsed_packet.get("qname", "")
        subdomain = parsed_packet.get("subdomain", "")
        labels = parsed_packet.get("labels", [])
        qtype = parsed_packet.get("qtype", "A")
        pkt_size = parsed_packet.get("packet_size", 64)
        rcode = parsed_packet.get("rcode", 0)

        # 1. Structural lengths
        domain_length = len(qname)
        subdomain_length = len(subdomain)
        label_count = len(labels)

        # 2. Label statistics
        label_lengths = [len(l) for l in labels] if labels else [0]
        maximum_label_length = max(label_lengths) if label_lengths else 0
        average_label_length = sum(label_lengths) / len(label_lengths) if label_lengths else 0.0

        # 3. Target text for character statistics (focus on subdomain if available, else full qname)
        target_text = subdomain if subdomain else qname
        target_len = len(target_text)

        # 4. Mathematical Shannon Entropy
        shannon_entropy = cls.calculate_shannon_entropy(target_text)

        # 5. Character ratios
        if target_len > 0:
            digits = sum(1 for c in target_text if c.isdigit())
            uppercases = sum(1 for c in target_text if c.isupper())
            specials = sum(1 for c in target_text if not c.isalnum() and c not in ('-', '.'))
            unique_chars = len(set(target_text))

            digit_ratio = round(digits / target_len, 4)
            uppercase_ratio = round(uppercases / target_len, 4)
            special_character_ratio = round(specials / target_len, 4)
            unique_character_ratio = round(unique_chars / target_len, 4)
        else:
            digit_ratio = 0.0
            uppercase_ratio = 0.0
            special_character_ratio = 0.0
            unique_character_ratio = 0.0

        # 6. Historical / windowed context statistics (supplied by sliding window engine or defaults)
        stats = historical_stats or {}
        query_frequency = stats.get("query_frequency", 1.0)
        unique_subdomain_rate = stats.get("unique_subdomain_rate", 1.0)
        txt_request_rate = stats.get("txt_request_rate", 1.0 if qtype == "TXT" else 0.0)
        nxdomain_rate = stats.get("nxdomain_rate", 1.0 if rcode == 3 else 0.0)
        average_packet_size = stats.get("average_packet_size", float(pkt_size))

        return {
            "qname": qname,
            "subdomain": subdomain,
            "domain_length": domain_length,
            "subdomain_length": subdomain_length,
            "label_count": label_count,
            "maximum_label_length": maximum_label_length,
            "average_label_length": round(average_label_length, 2),
            "shannon_entropy": shannon_entropy,
            "digit_ratio": digit_ratio,
            "uppercase_ratio": uppercase_ratio,
            "special_character_ratio": special_character_ratio,
            "unique_character_ratio": unique_character_ratio,
            "query_frequency": query_frequency,
            "unique_subdomain_rate": unique_subdomain_rate,
            "TXT_request_rate": txt_request_rate,
            "NXDOMAIN_rate": nxdomain_rate,
            "average_packet_size": round(average_packet_size, 2)
        }
