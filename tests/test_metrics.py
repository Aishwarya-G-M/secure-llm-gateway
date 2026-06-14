import pytest

from app.core.metrics import gateway_metrics

@pytest.fixture(autouse=True)
def reset_metrics():
    gateway_metrics.requests_total = 0
    gateway_metrics.requests_allowed = 0
    gateway_metrics.requests_blocked = 0
    gateway_metrics.requests_redacted = 0
    gateway_metrics.requests_reviewed = 0
    gateway_metrics.llm_errors_total = 0
    yield


def test_metrics_endpoint_returns_counters(client):
    response = client.get("/metrics")

    assert response.status_code == 200
    body = response.json()
    assert "requests_total" in body
    assert "requests_allowed" in body
    assert "requests_blocked" in body
    assert "requests_redacted" in body
    assert "requests_reviewed" in body
    assert "llm_errors_total" in body


def test_metrics_increments_allowed_on_safe_request(client):
    before = client.get("/metrics").json()

    response = client.post(
        "/chat",
        json={"prompt": "Explain how Redis caching works"},
    )

    assert response.status_code == 200

    after = client.get("/metrics").json()

    assert after["requests_total"] == before["requests_total"] + 1
    assert after["requests_allowed"] == before["requests_allowed"] + 1