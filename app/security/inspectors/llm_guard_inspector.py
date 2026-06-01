from app.models.security_models import InspectionContext
from app.schemas.security import PolicyAction, SecurityVerdict
from app.security.inspectors.base import BaseInspector

from llm_guard.input_scanners import PromptInjection
from llm_guard.input_scanners.prompt_injection import MatchType
from llm_guard.output_scanners import Sensitive


class LLMGuardInspector(BaseInspector):
    def __init__(
        self,
        threshold: float = 0.5,
        entity_types: list[str] | None = None,
        output_violation_action: PolicyAction = PolicyAction.BLOCK,
    ):
        self.output_violation_action = output_violation_action

        self.input_scanner = PromptInjection(
            threshold=threshold,
            match_type=MatchType.FULL,
        )
        self.output_scanner = Sensitive(
            entity_types=entity_types or ["PERSON", "EMAIL"],
            redact=True,
        )

    def inspect_input(
        self,
        text: str,
        context: InspectionContext | None = None,
    ) -> SecurityVerdict:
        sanitized_text, is_valid, risk_score = self.input_scanner.scan(text)

        normalized_risk = float(risk_score or 0.0)
        if normalized_risk <= 1:
            normalized_risk *= 10

        if not is_valid:
            return SecurityVerdict(
                allowed=False,
                action=PolicyAction.BLOCK,
                risk_score=normalized_risk,
                reasons=[
                    f"LLM Guard detected prompt injection risk (score={risk_score})"
                ],
                matched_rules=["llm_guard:prompt_injection"],
                inspector_used="llm_guard_inspector",
                sanitized_text=sanitized_text,
                metadata={
                    "provider": "llm_guard",
                    "stage": "input",
                    "scanner": "PromptInjection",
                    "raw_risk_score": risk_score,
                    "threshold": getattr(self.input_scanner, "threshold", None),
                    "route": context.route if context else None,
                    "model_name": context.model_name if context else None,
                },
            )

        return SecurityVerdict(
            allowed=True,
            action=PolicyAction.ALLOW,
            risk_score=normalized_risk,
            reasons=["No prompt injection detected by LLM Guard"],
            matched_rules=[],
            inspector_used="llm_guard_inspector",
            sanitized_text=sanitized_text,
            metadata={
                "provider": "llm_guard",
                "stage": "input",
                "scanner": "PromptInjection",
                "raw_risk_score": risk_score,
                "threshold": getattr(self.input_scanner, "threshold", None),
                "route": context.route if context else None,
                "model_name": context.model_name if context else None,
            },
        )

    def inspect_output(
        self,
        text: str,
        context: InspectionContext | None = None,
    ) -> SecurityVerdict:
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
                    "scanner": "Sensitive",
                    "route": context.route if context else None,
                    "model_name": context.model_name if context else None,
                },
            )

        prompt = context.prompt if context and context.prompt else ""
        sanitized_text, is_valid, risk_score = self.output_scanner.scan(prompt, text)

        normalized_risk = float(risk_score or 0.0)
        if normalized_risk <= 1:
            normalized_risk *= 10

        if not is_valid:
            return SecurityVerdict(
                allowed=False,
                action=PolicyAction.BLOCK,
                reasons=["LLM Guard output scanner flagged sensitive content"],
                matched_rules=["llm_guard:sensitive"],
                risk_score=normalized_risk,
                inspector_used="llm_guard_inspector",
                sanitized_text=sanitized_text,
                metadata={
                    "provider": "llm_guard",
                    "stage": "output",
                    "scanner": "Sensitive",
                    "raw_risk_score": risk_score,
                    "entity_types": getattr(self.output_scanner, "entity_types", None),
                    "route": context.route if context else None,
                    "model_name": context.model_name if context else None,
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
                "scanner": "Sensitive",
                "raw_risk_score": risk_score,
                "entity_types": getattr(self.output_scanner, "entity_types", None),
                "route": context.route if context else None,
                "model_name": context.model_name if context else None,
            },
        )