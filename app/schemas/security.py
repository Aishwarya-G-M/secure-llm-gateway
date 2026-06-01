from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PolicyAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    REVIEW = "review"


class SecurityVerdict(BaseModel):
    allowed: bool
    action: PolicyAction
    reasons: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    inspector_used: str
    sanitized_text: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)