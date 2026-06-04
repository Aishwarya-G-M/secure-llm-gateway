import re
from typing import Any

from app.exceptions.policy import LLMGuardInspectorError
from app.models.inspection_context import InspectionContext
from app.schemas.security_verdict import PolicyAction, SecurityVerdict
from app.security.inspectors.base import BaseInspector

from llm_guard.input_scanners import (
    Gibberish,
    InvisibleText,
    PromptInjection,
    Secrets
)
from llm_guard.input_scanners.prompt_injection import MatchType as PromptInjectionMatchType
from llm_guard.output_scanners import (
    Sensitive,
    Relevance
)

def format_matched_rule(scanner: Any) -> str:
    scanner_name = re.sub(r"(?<!^)(?=[A-Z])", "_", scanner.__class__.__name__).lower()
    return f"llm_guard:{scanner_name}"

class LLMGuardInspector(BaseInspector):
    def __init__(
        self,
        threshold: float = 0.5,
        entity_types: list[str] | None = None,
        output_violation_action: PolicyAction = PolicyAction.BLOCK,
    ):
        self.output_violation_action = output_violation_action
        self.entity_types = entity_types or [
            "PERSON",
            "EMAIL",
            "PHONE_NUMBER",
            "ADDRESS",
            "CREDIT_CARD",
            "SSN",
            "IP_ADDRESS",
        ]

        self.input_scanners = [
            PromptInjection(
                threshold=threshold,
                match_type=PromptInjectionMatchType.FULL,
            ),
            Gibberish(),
            InvisibleText(),
            Secrets(),
        ]

        self.output_scanners = [
            Sensitive(
                entity_types=self.entity_types,
                redact=True,
            ),
            Relevance(threshold=0.5),
        ]

    def inspect_input(
            self,
            text: str,
            context: InspectionContext | None = None,
    ) -> SecurityVerdict:
        try:
            sanitized_text = text
            normalized_risk = 0.0

            for scanner in self.input_scanners:
                sanitized_text, is_valid, risk_score = scanner.scan(sanitized_text)

                normalized_risk = float(risk_score or 0.0)
                if normalized_risk <= 1:
                    normalized_risk *= 10

                if not is_valid:
                    return SecurityVerdict(
                        allowed=False,
                        action=PolicyAction.BLOCK,
                        risk_score=normalized_risk,
                        reasons=[
                            f"LLM Guard {scanner.__class__.__name__} flagged the input (score={risk_score})"
                        ],
                        matched_rules=[format_matched_rule(scanner)],
                        inspector_used="llm_guard_inspector",
                        sanitized_text=sanitized_text,
                        metadata={
                            "provider": "llm_guard",
                            "stage": "input",
                            "scanner": scanner.__class__.__name__,
                            "raw_risk_score": risk_score,
                            "threshold": getattr(scanner, "threshold", None),
                            "route": context.route if context else None,
                            "model_name": context.model_name if context else None,
                            "request_id": context.request_id if context else None,
                            "trace_id": context.trace_id if context else None,
                        },
                    )

            return SecurityVerdict(
                allowed=True,
                action=PolicyAction.ALLOW,
                risk_score=normalized_risk,
                reasons=["LLM Guard input inspection passed"],
                matched_rules=[],
                inspector_used="llm_guard_inspector",
                sanitized_text=sanitized_text,
                metadata={
                    "provider": "llm_guard",
                    "stage": "input",
                    "route": context.route if context else None,
                    "model_name": context.model_name if context else None,
                },
            )
        except Exception as exp:
            raise LLMGuardInspectorError("LLMGuard inspection failed for input prompt") from exp

    def inspect_output(
            self,
            text: str,
            context: InspectionContext | None = None,
    ) -> SecurityVerdict:
        try:
            if not text or not text.strip():
                return SecurityVerdict(
                    allowed=True,
                    action=PolicyAction.ALLOW,
                    reasons=["Empty output text"],
                    matched_rules=[],
                    risk_score=0.0,
                    inspector_used="llm_guard_inspector",
                    sanitized_text=text,
                    metadata={
                        "provider": "llm_guard",
                        "stage": "output",
                        "route": context.route if context else None,
                        "model_name": context.model_name if context else None,
                        "request_id": context.request_id if context else None,
                        "trace_id": context.trace_id if context else None,
                    },
                )

            prompt = context.prompt if context and context.prompt else ""
            sanitized_text = text
            normalized_risk = 0.0

            for scanner in self.output_scanners:
                sanitized_text, is_valid, risk_score = scanner.scan(prompt, sanitized_text)
                risk_score = float(risk_score)

                normalized_risk = float(risk_score or 0.0)
                if normalized_risk <= 1:
                    normalized_risk *= 10

                if not is_valid:
                    return SecurityVerdict(
                        allowed=False,
                        action=PolicyAction.BLOCK,
                        reasons=[
                            f"LLM Guard {scanner.__class__.__name__} flagged output content"
                        ],
                        matched_rules=[format_matched_rule(scanner)],
                        risk_score=normalized_risk,
                        inspector_used="llm_guard_inspector",
                        sanitized_text=sanitized_text,
                        metadata={
                            "provider": "llm_guard",
                            "stage": "output",
                            "scanner": scanner.__class__.__name__,
                            "raw_risk_score": risk_score,
                            "entity_types": getattr(scanner, "entity_types", None),
                            "route": context.route if context else None,
                            "model_name": context.model_name if context else None,
                            "request_id": context.request_id if context else None,
                            "trace_id": context.trace_id if context else None,
                        },
                    )

            return SecurityVerdict(
                allowed=True,
                action=PolicyAction.ALLOW,
                reasons=["LLM Guard output inspection passed"],
                matched_rules=[],
                risk_score=normalized_risk,
                inspector_used="llm_guard_inspector",
                sanitized_text=sanitized_text,
                metadata={
                    "provider": "llm_guard",
                    "stage": "output",
                    "route": context.route if context else None,
                    "model_name": context.model_name if context else None,
                    "request_id": context.request_id if context else None,
                    "trace_id": context.trace_id if context else None,
                },
            )
        except Exception as exp:
            raise LLMGuardInspectorError("LLMGuard inspection failed for output prompt") from exp
