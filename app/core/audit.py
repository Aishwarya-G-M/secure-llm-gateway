from app.core.logging_setup import audit_logger
from app.schemas.security_verdict import PolicyAction, SecurityVerdict


def emit_audit_event(
    *,
    request_id: str | None,
    trace_id: str | None,
    api_key: str | None,
    route: str,
    stage: str,
    action: PolicyAction,
    verdict: SecurityVerdict,
) -> None:
    if action == PolicyAction.ALLOW:
        return

    audit_logger.warning(
        "policy_decision",
        extra={
            "request_id": request_id,
            "trace_id": trace_id,
            "api_key_hint": api_key[:8] + "..." if api_key and len(api_key) > 8 else api_key,
            "route": route,
            "stage": stage,
            "action": action.value,
            "risk_score": verdict.risk_score,
            "matched_rules": verdict.matched_rules,
            "reasons": verdict.reasons,
            "inspector_used": verdict.inspector_used,
        },
    )