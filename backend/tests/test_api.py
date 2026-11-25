"""
backend/tests/test_api.py
API tests for CensorScope FastAPI service.
Tests valid domain lookups, bad inputs, and database fallbacks.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_invalid_domain_formats():
    bad_domains = [
        "notadomain",
        "invalid..domain",
        "domain.12345",
        "domain/with/slashes",
        "http://",
    ]
    for bad_d in bad_domains:
        response = client.get(f"/api/v1/domain/{bad_d}")
        assert response.status_code == 400
        assert "Invalid domain" in response.json()["detail"]


def test_unknown_domain_returns_insufficient_data():
    """Unmeasured domain returns Insufficient data with 200 OK (no live probe)."""
    response = client.get("/api/v1/domain/unmeasured-domain-xyz123.org")
    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == "unmeasured-domain-xyz123.org"
    assert data["overall_verdict"] == "Insufficient data"
    assert data["confidence"] == 0.0
    assert data["evidence_count"] == 0
    assert "timeline" in data
    assert "isp_verdicts" in data


def test_cautious_disclaimer_present():
    response = client.get("/api/v1/domain/wikipedia.org")
    assert response.status_code == 200
    data = response.json()
    assert "disclaimer" in data
    assert "legal determinations" in data["disclaimer"]


def test_rate_limiter_rejects_x_forwarded_for_spoofing():
    """Verify rate limiter cannot be bypassed by sending arbitrary X-Forwarded-For headers from untrusted clients."""
    from app.api.limiter import get_client_ip
    from starlette.requests import Request

    scope = {
        "type": "http",
        "client": ("192.168.1.100", 12345),
        "headers": [(b"x-forwarded-for", b"203.0.113.195, 10.0.0.1")],
    }
    req = Request(scope)
    # Must return direct socket IP (192.168.1.100) instead of forged header IP because peer is untrusted
    assert get_client_ip(req) == "192.168.1.100"


def test_rate_limiter_honors_x_forwarded_for_from_trusted_proxy():
    """Verify rate limiter honors X-Forwarded-For when the direct peer is a trusted proxy."""
    from app.api.limiter import get_client_ip
    from starlette.requests import Request

    scope = {
        "type": "http",
        "client": ("127.0.0.1", 54321),
        "headers": [(b"x-forwarded-for", b"198.51.100.42")],
    }
    req = Request(scope)
    assert get_client_ip(req) == "198.51.100.42"


def test_rate_limiter_multiple_hops_under_trusted_proxies():
    """Verify handling of multiple proxy hops, stripping trusted proxies from right to left."""
    from app.api.limiter import get_client_ip
    from starlette.requests import Request

    scope = {
        "type": "http",
        "client": ("127.0.0.1", 54321),
        "headers": [(b"x-forwarded-for", b"203.0.113.50, 198.51.100.1, 127.0.0.1")],
    }
    req = Request(scope)
    # The rightmost untrusted hop before trusted proxy 127.0.0.1 is 198.51.100.1
    assert get_client_ip(req) == "198.51.100.1"


def test_cache_keys_are_hmac_hashed_for_privacy():
    """Verify that domain names are keyed with HMAC-SHA256 and cannot be recomputed without the secret."""
    import hashlib
    import hmac
    from app.api.cache import _domain_cache_key, _EFFECTIVE_SECRET

    domain = "sensitive-query.org"
    key = _domain_cache_key(domain)

    # Key must NOT contain plaintext domain
    assert domain not in key
    # Plain SHA-256 without HMAC does NOT match the cache key
    plain_sha = hashlib.sha256(domain.encode("utf-8")).hexdigest()
    assert plain_sha not in key

    # Key matches HMAC-SHA256 with server's secret
    expected_mac = hmac.new(_EFFECTIVE_SECRET, domain.encode("utf-8"), hashlib.sha256).hexdigest()
    assert key == f"censorscope:domain_h:{expected_mac}"

    # A different secret generates an entirely different key (attacker cannot guess keys)
    attacker_mac = hmac.new(b"attacker_secret_key_123456789012345", domain.encode("utf-8"), hashlib.sha256).hexdigest()
    assert key != f"censorscope:domain_h:{attacker_mac}"
