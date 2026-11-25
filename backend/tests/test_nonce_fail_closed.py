import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.api.probe_routes import register_authorized_probe
from probe.client import CensorScopeProbe

client = TestClient(app)

def test_nonce_store_fails_closed_when_redis_unavailable():
    """
    Task 3 Verification:
    Proves: If Redis is unavailable, the report endpoint fails closed with HTTP 503 Service Unavailable
    instead of silently falling back to insecure in-memory storage.
    Does not prove: Fault tolerance against network partitions when Redis cluster is degraded.
    """
    probe = CensorScopeProbe(asn=55836)
    register_authorized_probe(probe.public_key_hex)
    report = probe.run_measurement("wikipedia.org")

    with patch("app.api.probe_routes.ALLOW_TEST_MEMORY_NONCE", False):
        with patch("app.api.probe_routes.get_redis_client", side_effect=ConnectionError("Redis down")):
            resp = client.post("/api/v1/reports", json=report)
            assert resp.status_code == 503
            assert "Nonce store unavailable" in resp.json()["detail"]
