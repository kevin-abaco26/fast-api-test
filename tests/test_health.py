"""Tests for /health endpoint."""


class TestHealth:
    def test_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_returns_timestamp(self, client):
        resp = client.get("/health")
        assert "timestamp" in resp.json()
