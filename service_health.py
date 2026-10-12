"""Service health states and checks independent of Windows SCM."""

from enum import Enum
from dataclasses import dataclass


class HealthState(str, Enum):
    PROTECTED = "PROTECTED"
    DEGRADED = "DEGRADED"
    DISABLED = "DISABLED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class ProtectionHealth:
    state: HealthState
    listener_ready: bool
    policy_ready: bool
    upstream_ready: bool
    routing_verified: bool
    detail: str


def evaluate_health(
    *,
    enabled: bool,
    listener_ready: bool,
    policy_ready: bool,
    upstream_ready: bool,
    routing_verified: bool,
    startup_error: str = "",
) -> ProtectionHealth:
    if startup_error:
        return ProtectionHealth(
            HealthState.ERROR, listener_ready, policy_ready, upstream_ready,
            routing_verified, startup_error
        )
    if not enabled:
        return ProtectionHealth(
            HealthState.DISABLED, listener_ready, policy_ready, upstream_ready,
            routing_verified, "Protection is intentionally disabled."
        )
    checks = (listener_ready, policy_ready, upstream_ready, routing_verified)
    if all(checks):
        return ProtectionHealth(
            HealthState.PROTECTED, True, True, True, True,
            "Enforcement and routing checks passed."
        )
    return ProtectionHealth(
        HealthState.DEGRADED, listener_ready, policy_ready, upstream_ready,
        routing_verified, "One or more enforcement checks are incomplete."
    )
