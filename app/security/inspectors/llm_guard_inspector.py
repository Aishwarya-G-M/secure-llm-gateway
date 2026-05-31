from llm_guard.input_scanners import PromptInjection
from llm_guard.input_scanners.prompt_injection import MatchType

from app.schemas.security import SecurityVerdict, PolicyAction
from app.security.inspectors.base import BaseInspector


class LLMGuardInspector(BaseInspector):
    def __init__(self, threshold: float = 0.5):
        self.scanner = PromptInjection(
            threshold=threshold,
            match_type=MatchType.FULL,
        )

    def inspect_input(self,text : str) -> SecurityVerdict:
        _, is_valid, risk_score = self.scanner.scan(text)

        if not is_valid:
            return SecurityVerdict(
                allowed = False,
                action = PolicyAction.BLOCK,
                risk_score=int(round(risk_score*10)) if risk_score <= 1 else int(risk_score),
                reasons=[
                    f"LLM Guard detected prompt injection risk (score={risk_score})"
                ],
                matched_rules=["llm_guard:prompt_injection"],
                inspector_used="llm_guard_inspector",
            )
        return SecurityVerdict(
            allowed=True,
            action=PolicyAction.ALLOW,
            risk_score=1,
            reasons=["No prompt injection detected by LLM Guard"],
            matched_rules=[],
            inspector_used="llm_guard_inspector",
        )

    def inspect_output(self,text:str):
        raise NotImplementedError("LLMGuardInspector currently supports input inspection only")