import pytest
from fastapi.testclient import TestClient

from app.main import app, get_gateway_inspector
from app.gateway.service import GatewayInspector
from app.schemas.llm import LLMMetadata, LLMResponse
from app.security.inspectors.llm_guard_inspector import LLMGuardInspector
from app.security.inspectors.rule_inspector import RuleInspector


class FakeLlmClient:
    def generate(self, request):
        return LLMResponse(
            content="safe model response",
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


@pytest.fixture
def llm_client_override():
    return FakeLlmClient()


@pytest.fixture(autouse=True)
def override_app_dependencies(llm_client_override):
    original_overrides = app.dependency_overrides.copy()

    def override_gateway_inspector():
        return GatewayInspector(
            rule_inspector=RuleInspector(),
            llm_guard_inspector=LLMGuardInspector(),
            llm_client=llm_client_override,
        )

    app.dependency_overrides[get_gateway_inspector] = override_gateway_inspector
    yield
    app.dependency_overrides = original_overrides


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client