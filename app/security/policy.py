from typing import Any

from app.schemas.security import PolicyAction, SecurityVerdict


def build_allow_verdict(
    inspector_used: str,
    risk_score: float = 1.0,
    reasons: list[str] | None = None,
    matched_rules: list[str] | None = None,
    sanitized_text: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityVerdict:
    return SecurityVerdict(
        allowed=True,
        action=PolicyAction.ALLOW,
        risk_score=risk_score,
        reasons=reasons or [],
        matched_rules=matched_rules or [],
        inspector_used=inspector_used,
        sanitized_text=sanitized_text,
        metadata=metadata or {},
    )


def build_block_verdict(
    inspector_used: str,
    risk_score: float,
    reasons: list[str] | None = None,
    matched_rules: list[str] | None = None,
    sanitized_text: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityVerdict:
    return SecurityVerdict(
        allowed=False,
        action=PolicyAction.BLOCK,
        risk_score=risk_score,
        reasons=reasons or [],
        matched_rules=matched_rules or [],
        inspector_used=inspector_used,
        sanitized_text=sanitized_text,
        metadata=metadata or {},
    )


def build_review_verdict(
    inspector_used: str,
    risk_score: float,
    reasons: list[str] | None = None,
    matched_rules: list[str] | None = None,
    sanitized_text: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityVerdict:
    return SecurityVerdict(
        allowed=False,
        action=PolicyAction.REVIEW,
        risk_score=risk_score,
        reasons=reasons or [],
        matched_rules=matched_rules or [],
        inspector_used=inspector_used,
        sanitized_text=sanitized_text,
        metadata=metadata or {},
    )


def build_redact_verdict(
    inspector_used: str,
    risk_score: float,
    reasons: list[str] | None = None,
    matched_rules: list[str] | None = None,
    sanitized_text: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityVerdict:
    return SecurityVerdict(
        allowed=False,
        action=PolicyAction.REDACT,
        risk_score=risk_score,
        reasons=reasons or [],
        matched_rules=matched_rules or [],
        inspector_used=inspector_used,
        sanitized_text=sanitized_text,
        metadata=metadata or {},
    )


def resolve_action(max_severity: int) -> tuple[bool, PolicyAction]:
    if max_severity >= 9:
        return False, PolicyAction.BLOCK
    if max_severity >= 7:
        return False, PolicyAction.REVIEW
    if max_severity >= 6:
        return False, PolicyAction.REDACT
    return True, PolicyAction.ALLOW