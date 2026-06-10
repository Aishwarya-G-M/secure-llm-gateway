from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.middleware.api_key_auth import ApiKeyMiddleware

TEST_API_KEYS = frozenset({"key-abc123", "key-def456"})

def create_test_app(api_keys: frozenset[str] = TEST_API_KEYS) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        ApiKeyMiddleware,
        excluded_paths={"/health"},
        api_keys=api_keys,
    )

    @app.post("/chat")
    def chat():
        return {"message": "ok"}

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app

def test_request_without_api_key_returns_401():
    client = TestClient(create_test_app())
    response = client.post("/chat", json={"prompt": "hello"})

    assert response.status_code == 401
    assert response.json()["error_code"] == "missing_api_key"


def test_request_with_invalid_api_key_returns_403():
    client = TestClient(create_test_app())
    response = client.post(
        "/chat",
        json={"prompt": "hello"},
        headers={"X-API-Key": "invalid-key"},
    )

    assert response.status_code == 403
    assert response.json()["error_code"] == "invalid_api_key"


def test_request_with_valid_api_key_is_allowed():
    client = TestClient(create_test_app())
    response = client.post(
        "/chat",
        json={"prompt": "hello"},
        headers={"X-API-Key": "key-abc123"},
    )

    assert response.status_code == 200


def test_health_endpoint_requires_no_api_key():
    client = TestClient(create_test_app())
    response = client.get("/health")

    assert response.status_code == 200


def test_health_endpoint_with_invalid_key_still_passes():
    client = TestClient(create_test_app())
    response = client.get(
        "/health",
        headers={"X-API-Key": "totally-invalid"},
    )

    assert response.status_code == 200