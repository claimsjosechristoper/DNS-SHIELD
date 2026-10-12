"""
Gateway Configuration Management.
Loads settings from environment variables and provides sensible defaults
for development (port 5353, loopback) and production environments.
"""

import os
import secrets
from pathlib import Path
from typing import List

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
BLOCKLISTS_DIR = DATA_DIR / "blocklists"
BLOCKLISTS_DIR.mkdir(parents=True, exist_ok=True)

class GatewayConfig:
    # Gateway DNS Server Network Settings
    DNS_HOST: str = os.getenv("DNS_HOST", "127.0.0.1")
    DNS_PORT: int = int(os.getenv("DNS_PORT", "5353"))
    
    # Upstream DNS Resolvers (ordered by priority)
    UPSTREAM_SERVERS: List[str] = os.getenv("UPSTREAM_SERVERS", "1.1.1.1:53,8.8.8.8:53").split(",")
    UPSTREAM_TIMEOUT: float = float(os.getenv("UPSTREAM_TIMEOUT", "2.5"))
    
    # Default Blocked Response Action: REFUSED or NXDOMAIN
    DEFAULT_BLOCKED_RCODE: str = os.getenv("DEFAULT_BLOCKED_RCODE", "REFUSED").upper()
    if DEFAULT_BLOCKED_RCODE not in ("REFUSED", "NXDOMAIN"):
        DEFAULT_BLOCKED_RCODE = "REFUSED"
        
    # Allowed Client Networks (CIDR) - Restrict to prevent open resolver vulnerability
    ALLOWED_NETWORKS: List[str] = [
        cidr.strip() for cidr in os.getenv(
            "ALLOWED_NETWORKS",
            "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,::1/128"
        ).split(",") if cidr.strip()
    ]
    
    # DNS Cache settings
    CACHE_MAX_ENTRIES: int = int(os.getenv("CACHE_MAX_ENTRIES", "10000"))
    CACHE_MIN_TTL: int = int(os.getenv("CACHE_MIN_TTL", "5"))
    CACHE_MAX_TTL: int = int(os.getenv("CACHE_MAX_TTL", "3600"))
    
    # Rate Limiting (per-client IP)
    RATE_LIMIT_RPM: int = int(os.getenv("RATE_LIMIT_RPM", "600"))
    RATE_LIMIT_BURST: int = int(os.getenv("RATE_LIMIT_BURST", "60"))
    
    # Log Retention in days
    LOG_RETENTION_DAYS: int = int(os.getenv("LOG_RETENTION_DAYS", "30"))
    
    # Administrative Security
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_API_KEY: str = os.getenv("ADMIN_API_KEY", "")
    
    # Database
    DB_PATH: str = str(DATA_DIR / "dns_gateway.db")
    
    # API Server Settings
    API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))

# Initialize default secure key if not set
if not GatewayConfig.ADMIN_API_KEY:
    # Generate persistent default key in data/admin_key.txt if not configured
    key_file = DATA_DIR / "admin_key.txt"
    if key_file.exists():
        GatewayConfig.ADMIN_API_KEY = key_file.read_text().strip()
    else:
        new_key = secrets.token_hex(24)
        key_file.write_text(new_key)
        GatewayConfig.ADMIN_API_KEY = new_key
