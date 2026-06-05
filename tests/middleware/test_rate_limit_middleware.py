# tests/test_rate_limit_middleware.py

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.rate_limit import RateLimitMiddleware

def create_test_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        RateLimitMiddleware,
        default_max_requests=5,
        default_window_seconds=60,
        path_limits={
            "/chat": {"max_requests": 1, "window_seconds": 60},
        },
        excluded_paths={"/health"},
    )

    @app.post("/chat")
    def chat():
        return {"message": "ok"}

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/info")
    def info():
        return {"service": "ok"}

    return app


def test_chat_request_under_limit_is_allowed():
    client = TestClient(create_test_app())

    response = client.post("/chat", json={"prompt": "hello"})

    assert response.status_code == 200
    assert response.json() == {"message": "ok"}


def test_chat_request_over_limit_returns_429():
    client = TestClient(create_test_app())

    first = client.post("/chat", json={"prompt": "hello"})
    second = client.post("/chat", json={"prompt": "hello again"})

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["detail"] == "Rate limit exceeded"

def test_non_limited_path_is_not_blocked():
    client = TestClient(create_test_app())

    first = client.get("/health")
    second = client.get("/health")

    assert first.status_code == 200
    assert second.status_code == 200

def test_excluded_path_is_never_rate_limited():
    client = TestClient(create_test_app())

    first = client.get("/health")
    second = client.get("/health")
    third = client.get("/health")

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 200

def test_non_overridden_path_uses_default_rate_limit():
    client = TestClient(create_test_app())

    for _ in range(5):
        response = client.get("/info")
        assert response.status_code == 200

    blocked = client.get("/info")
    assert blocked.status_code == 429