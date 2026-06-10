import os
os.environ.setdefault("API_KEYS", "key-abc123,key-def456")
import pytest
from fastapi import Request
from starlette.testclient import TestClient

from app.clients.llm_protocol import LlmClientProtocol
from app.main import app, get_gateway_inspector
from app.gateway.orchestrator import GatewayOrchestrator
from app.schemas.llm import LLMMetadata, LLMResponse, LLMRequest
from app.schemas.security_verdict import PolicyAction, SecurityVerdict
from app.security.inspectors.base import BaseInspector
from app.security.inspectors.rule_inspector import RuleInspector

class FakeLlmClient(LlmClientProtocol):
    def generate(self, request: LLMRequest) -> LLMResponse:
        return LLMResponse(
            content="Redis caching stores frequently accessed data in memory to speed up responses and reduce repeated database queries.",
            metadata=LLMMetadata(
                request_id="test-ci",
                provider="fake",
                model="fake-model",
                latency_ms=1,
            ),
            input_tokens=5,
            output_tokens=3,
            total_tokens=8,
        )


class FakeLLMGuardInspector(BaseInspector):
    def inspect_input(self, text: str, context=None) -> SecurityVerdict:
        return SecurityVerdict(
            allowed=True,
            action=PolicyAction.ALLOW,
            reasons=["No known unsafe input patterns detected"],
            matched_rules=[],
            risk_score=0.0,
            inspector_used="fake_llm_guard_inspector",
            sanitized_text=None,
            metadata={},
        )

    def inspect_output(self, text: str, context=None) -> SecurityVerdict:
        return SecurityVerdict(
            allowed=True,
            action=PolicyAction.ALLOW,
            reasons=["No known unsafe output patterns detected"],
            matched_rules=[],
            risk_score=0.0,
            inspector_used="fake_llm_guard_inspector",
            sanitized_text=None,
            metadata={},
        )


@pytest.fixture
def llm_client_override():
    return FakeLlmClient()


@pytest.fixture(autouse=True)
def override_app_dependencies(llm_client_override):
    original_overrides = app.dependency_overrides.copy()

    def override_gateway_inspector(request: Request):
        return GatewayOrchestrator(
            rule_inspector=RuleInspector(),
            llm_guard_inspector=FakeLLMGuardInspector(),
            llm_client=llm_client_override,
            system_prompt="You are a test assistant.",
        )

    app.dependency_overrides[get_gateway_inspector] = override_gateway_inspector
    yield
    app.dependency_overrides = original_overrides

@pytest.fixture
def client():
    with TestClient(app, headers={"X-API-Key": "key-abc123"}) as test_client:
        yield test_client

class AlwaysBlockRuleInspector(BaseInspector):
    def inspect_input(self, text, context=None):
        return SecurityVerdict(
            allowed=False,
            action=PolicyAction.BLOCK,
            reasons=["Prompt injection detected"],
            matched_rules=["test:block"],
            risk_score=9.0,
            inspector_used="always_block_rule_inspector",
            metadata={},
        )

    def inspect_output(self, text, context=None):
        return SecurityVerdict(
            allowed=True,
            action=PolicyAction.ALLOW,
            reasons=["ok"],
            matched_rules=[],
            risk_score=0.0,
            inspector_used="always_block_rule_inspector",
            metadata={},
        )