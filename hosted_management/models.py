"""
Database Models and Schemas for DNS-SHIELD Hosted Multi-Tenant Management.
"""

import time
import secrets
import hashlib
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class TenantCreate(BaseModel):
    name: str
    contact_email: str


class AccountCreate(BaseModel):
    tenant_id: str
    username: str
    password: str
    role: str = "admin"  # admin or analyst


class EnrollmentTokenRequest(BaseModel):
    tenant_id: str
    device_name: str
    expires_in_minutes: int = 15


class DeviceEnrollRequest(BaseModel):
    enrollment_token: str
    hardware_uuid: str
    os_version: str
    hostname: str


class PolicyUpdate(BaseModel):
    name: str
    custom_blocked_domains: List[str]
    allowlisted_domains: List[str]
    blocked_record_types: List[str]
    version: int


class TelemetryEventBatch(BaseModel):
    device_id: str
    events: List[Dict[str, Any]]
