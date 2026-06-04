
def test_request_context_middleware_propagates_request_id(client):
    response = client.get("/health", headers={"x-request-id": "abc-123"})

    assert response.status_code == 200
    assert response.headers["x-request-id"] == "abc-123"
    assert response.headers["x-trace-id"] == "abc-123"

def test_request_context_middleware_generates_ids(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert "x-request-id" in response.headers
    assert "x-trace-id" in response.headers
    assert response.headers["x-request-id"]
    assert response.headers["x-trace-id"]