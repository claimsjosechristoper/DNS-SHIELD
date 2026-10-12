"""
Domain Name Normalization and RFC 1035/1123 Syntax Validation.
Handles lowercase conversion, trailing dots, IDN Punycode normalization,
and protocol label boundary constraints.
"""

import re
from typing import Tuple

# RFC 1035 / RFC 1123 label pattern: alphanumeric and hyphen, cannot start or end with hyphen
LABEL_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-_]{0,61}[a-z0-9])?$")

def normalize_domain(domain: str) -> Tuple[str, bool, str]:
    """
    Normalizes a domain name and validates its syntax.
    Returns:
        (normalized_domain, is_valid, error_message)
    """
    if not domain:
        return "", False, "Domain name cannot be empty"

    cleaned = domain.strip().lower()
    
    # Strip trailing dot representing root zone
    cleaned = cleaned.rstrip(".")
    if not cleaned:
        # Root zone query "."
        return ".", True, ""

    # Total length check (RFC 1035 max wire representation is 255 octets, FQDN text max 253)
    if len(cleaned) > 253:
        return cleaned, False, "Domain name exceeds maximum RFC length of 253 characters"

    # IDN Punycode normalization
    try:
        # Convert any unicode domain labels to punycode ascii
        cleaned = cleaned.encode("idna").decode("ascii")
    except Exception as e:
        return cleaned, False, f"IDN Punycode encoding failed: {str(e)}"

    labels = cleaned.split(".")
    for idx, label in enumerate(labels):
        if not label:
            return cleaned, False, f"Empty label at position {idx} (e.g. double dot)"
        if len(label) > 63:
            return cleaned, False, f"Label '{label}' exceeds maximum RFC length of 63 characters"
        if not LABEL_PATTERN.match(label):
            # Allow single character labels and wildcards if explicitly allowed
            if len(label) == 1 and (label.isalnum() or label == "*"):
                continue
            return cleaned, False, f"Label '{label}' contains invalid characters or illegal hyphen position"

    return cleaned, True, ""
