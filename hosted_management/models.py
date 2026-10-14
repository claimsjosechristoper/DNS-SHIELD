"""
Database Models and Schemas for DNS-SHIELD Hosted Multi-Tenant Management.
"""

from typing import Any, Dict, List, Optional
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
    name: Optional[str] = "Default Policy"
    custom_blocked_domains: List[str] = Field(default_factory=list)
    allowlisted_domains: List[str] = Field(default_factory=list)
    blocked_record_types: List[str] = Field(default_factory=list)
    version: Optional[int] = None


class TelemetrySettingsUpdate(BaseModel):
    telemetry_enabled: bool = True
    anonymize_ips: bool = False
    max_batch_size: int = 100


class TelemetryEventBatch(BaseModel):
    device_id: str
    events: List[Dict[str, Any]]
