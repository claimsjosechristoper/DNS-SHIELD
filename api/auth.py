"""
Administrative API Authentication and Security Guard.
Protects administrative endpoints using API Keys / Bearer Tokens with constant-time comparison.
"""

import secrets
from fastapi import Header, HTTPException, status, Depends
from typing import Optional
from gateway.config import GatewayConfig

def verify_admin_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization")
) -> str:
    """
    Validates administrative credentials from X-API-Key or Authorization Bearer header.
    Employs constant-time string comparison to defend against timing attacks.
    """
    token = None
    if x_api_key:
        token = x_api_key.strip()
    elif authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()

    expected = GatewayConfig.ADMIN_API_KEY
    if not token or not secrets.compare_digest(token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing administrative API credentials.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return "admin"
