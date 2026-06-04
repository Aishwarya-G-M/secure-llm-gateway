from dataclasses import dataclass

from app.schemas.security_verdict import PolicyAction
from app.security.inspectors.llm_guard_inspector import LLMGuardInspector


@dataclass
class AppResources:
    llm_guard_inspector: LLMGuardInspector


def create_app_resources() -> AppResources:
    llm_guard_inspector = LLMGuardInspector(
        threshold=0.5,
        entity_types=[
            "PERSON",
            "EMAIL",
            "PHONE_NUMBER",
            "ADDRESS",
            "CREDIT_CARD",
            "SSN",
            "IP_ADDRESS",
        ],
        output_violation_action=PolicyAction.BLOCK,
    )

    return AppResources(llm_guard_inspector=llm_guard_inspector)