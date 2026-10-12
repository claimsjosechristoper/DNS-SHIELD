"""
DNS Indicator and Severity Definitions.
Provides Pydantic and dictionary representations of detection indicators.
"""

from enum import Enum
from pydantic import BaseModel, Field
from typing import Any, Optional

class Severity(str, Enum):
    NORMAL = "NORMAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IndicatorResult(BaseModel):
    indicator: str = Field(..., description="Unique indicator key (e.g. HIGH_ENTROPY)")
    observed_value: Any = Field(..., description="Value measured in the traffic")
    threshold: Any = Field(..., description="Configured rule threshold")
    severity: Severity = Field(Severity.NORMAL, description="Severity rating")
    explanation: str = Field(..., description="Human-readable explanation of why this was triggered")
    confidence: str = Field("MEDIUM", description="Confidence level: LOW, MEDIUM, HIGH")

    def to_dict(self):
        return {
            "indicator": self.indicator,
            "observed_value": self.observed_value,
            "threshold": self.threshold,
            "severity": self.severity.value,
            "explanation": self.explanation,
            "confidence": self.confidence
        }
