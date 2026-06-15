from dataclasses import dataclass

from app.config.prompts import load_system_prompt, load_prompt_version
from app.core.metrics import gateway_metrics, GatewayMetrics
from app.schemas.security_verdict import PolicyAction
from app.security.inspectors.llm_guard_inspector import LLMGuardInspector
from app.security.inspectors.rule_inspector import RuleInspector


@dataclass
class AppResources:
    llm_guard_inspector: LLMGuardInspector
    rule_inspector: RuleInspector
    system_prompt: str
    system_prompt_version: str
    metrics: GatewayMetrics


def create_app_resources() -> AppResources:
    system_prompt = load_system_prompt(prompt_name="chat")
    system_prompt_version = load_prompt_version(prompt_name="chat")
    rule_inspector = RuleInspector()
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
    metrics = gateway_metrics

    return AppResources(
        rule_inspector=rule_inspector,
        llm_guard_inspector=llm_guard_inspector,
        system_prompt=system_prompt,
        system_prompt_version=system_prompt_version,
        metrics=metrics,
    )