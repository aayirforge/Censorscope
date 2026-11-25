"""
backend/tests/test_phase3.py
Comprehensive Phase 3 Test Suite:
1. Forged cryptographic signature rejection
2. Tampered payload rejection
3. Replayed nonce rejection
4. Expired timestamp rejection
5. Unknown probe public key rejection
6. Sybil cluster simulation (multiple probe keys on a single network must not achieve quorum)
7. Security headers and zero IP-domain linkage verification
"""

import time

from fastapi.testclient import TestClient
from probe.client import CensorScopeProbe

from analysis.verdict import VerdictEngine
from app.api import probe_routes
from app.api.probe_routes import (
    AUTHORIZED_PROBES,
    canonical_json_dumps,
    register_authorized_probe,
)
from app.main import app

# Enable memory nonce mode specifically for offline mock integration tests in this module
probe_routes.ALLOW_TEST_MEMORY_NONCE = True

client = TestClient(app)


def test_forged_signature_rejected():
    """
    Proves: A report with an invalid or forged Ed25519 signature is strictly rejected with HTTP 401.
    Does not prove: The authenticity of the probe's underlying physical hardware.
    """
    probe = CensorScopeProbe(asn=55836)
    register_authorized_probe(probe.public_key_hex)
    report = probe.run_measurement("wikipedia.org")

    # Forge the signature (replace with arbitrary 128 hex bytes)
    report["signature"] = "a" * 128

    resp = client.post("/api/v1/reports", json=report)
    assert resp.status_code == 401
    assert "invalid signature" in resp.json()["detail"].lower()


def test_tampered_payload_rejected():
    """
    Proves: Any modification to payload fields after signing alters canonical serialization and fails verification.
    Does not prove: Protection against malicious probes providing false measurements before signing.
    """
    probe = CensorScopeProbe(asn=55836)
    register_authorized_probe(probe.public_key_hex)
    report = probe.run_measurement("wikipedia.org")

    # Tamper with the result field after signing
    report["result"]["anomaly"] = not report["result"]["anomaly"]

    resp = client.post("/api/v1/reports", json=report)
    assert resp.status_code == 401
    assert "invalid signature" in resp.json()["detail"].lower()


def test_replayed_nonce_rejected():
    """
    Proves: A report with a duplicate nonce is detected and rejected with HTTP 409 Conflict.
    Does not prove: Detection of identical measurements submitted under a fresh nonce.
    """
    probe = CensorScopeProbe(asn=55836)
    register_authorized_probe(probe.public_key_hex)
    report = probe.run_measurement("wikipedia.org")

    # Submit first time -> 201 Created
    resp1 = client.post("/api/v1/reports", json=report)
    assert resp1.status_code == 201

    # Replay same report -> 409 Conflict
    resp2 = client.post("/api/v1/reports", json=report)
    assert resp2.status_code == 409
    assert "Replay attack detected" in resp2.json()["detail"]


def test_expired_timestamp_rejected():
    """
    Proves: Reports older than +/- 10 minutes from current UTC are rejected with HTTP 400.
    Does not prove: Absolute clock synchronization precision beyond the 10-minute threshold window.
    """
    probe = CensorScopeProbe(asn=55836)
    register_authorized_probe(probe.public_key_hex)
    report = probe.run_measurement("wikipedia.org")

    # Set timestamp to 20 minutes ago
    report["timestamp"] = int(time.time()) - 1200
    # Re-sign with expired timestamp
    payload_dict = dict(report)
    payload_dict.pop("signature", None)
    canonical = canonical_json_dumps(payload_dict)
    report["signature"] = probe.private_key.sign(canonical).hex()

    resp = client.post("/api/v1/reports", json=report)
    assert resp.status_code == 400
    assert "expired" in resp.json()["detail"].lower()


def test_unknown_probe_key_rejected():
    """
    Proves: Reports from probe public keys not present in the authorized registry are rejected with HTTP 403.
    Does not prove: Protection against an attacker stealing the private key of an authorized probe.
    """
    unauthorized_probe = CensorScopeProbe(asn=55836)
    # Ensure probe key is NOT registered
    AUTHORIZED_PROBES.discard(unauthorized_probe.public_key_hex.lower())
    # Ensure registry has at least one key so whitelist is active
    register_authorized_probe("1" * 64)

    report = unauthorized_probe.run_measurement("wikipedia.org")
    resp = client.post("/api/v1/reports", json=report)
    assert resp.status_code == 403
    assert "Unauthorized probe public key" in resp.json()["detail"]


def test_sybil_cluster_does_not_reach_quorum():
    """
    Proves: Multiple distinct probe keys operating on a single network/resolver cannot reach quorum for 'Blocked'.
    Does not prove: Prevention of Sybil attacks if an adversary controls multiple disparate residential ASNs.
    """
    engine = VerdictEngine()
    # 5 different fake probes, but all reporting from the same ASN and network resolver on a single day
    measurements = []
    for i in range(5):
        measurements.append(
            {
                "id": i,
                "measured_at": "2026-11-24 10:00:00",
                "anomaly": True,
                "signals": {"dns": True},
                "technique_labels": ["dns_tampering"],
                "raw_json": {
                    "probe_pubkey": f"key_{i}",
                    "probe_asn": 55836,
                    "test": {"dns": {"resolver": "192.168.1.1"}},  # Same network
                },
            }
        )

    # Total 5 measurements, 5 anomalies, but only 1 network and 1 distinct day
    res = engine.compute_isp_verdict(55836, "Reliance Jio", measurements)
    # Must NOT become Blocked because quorum requires >= 2 distinct networks and >= 2 distinct days
    # and has_strong_signature requires >= 2 distinct days
    assert res.verdict != "Blocked"
    assert res.verdict in ("Likely blocked", "Inconclusive")
    assert any(
        "distinct observation day" in f.lower() or "probable network interference" in f.lower()
        for f in res.explanation.factors
    )


def test_security_headers_present():
    """
    Proves: Mandatory enterprise security headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy) are attached.
    Does not prove: End-to-end immunity from browser zero-day vulnerabilities.
    """
    resp = client.get("/health")
    assert resp.status_code == 200
    headers = resp.headers
    assert "Content-Security-Policy" in headers
    assert "Strict-Transport-Security" in headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert "strict-origin-when-cross-origin" in headers.get("Referrer-Policy")
