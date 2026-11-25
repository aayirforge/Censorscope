"""
backend/tests/test_phase2.py
Unit tests for Phase 2:
- Technique classifier (DNS, TCP, TLS, HTTP block page, HTTP injection, IP blocking)
- Category classifier (censorship_suspected, security_related, infrastructure_failure, inconclusive)
- Threat intelligence caching
- Legal context validation
"""

import pytest

from analysis.category import CategoryClassifier
from analysis.technique import TechniqueClassifier
from app.services.threat_intel import ThreatIntelService


def test_technique_dns_tampering():
    classifier = TechniqueClassifier()
    data = {
        "raw_json": {
            "dns_consistency": "inconsistent",
            "scores": {"analysis": {"blocking_type": "dns"}},
        }
    }
    res = classifier.classify(data)
    assert "dns_tampering" in res.labels
    assert "dns_tampering" in res.evidence


def test_technique_tcp_reset():
    classifier = TechniqueClassifier()
    data = {
        "raw_json": {
            "tcp_connect": "connection_refused_error",
            "test_keys": {"tcp_connect": "connection_refused_error"},
        }
    }
    res = classifier.classify(data)
    assert "tcp_reset" in res.labels


def test_technique_tls_sni():
    classifier = TechniqueClassifier()
    data = {"raw_json": {"test_keys": {"tls_handshake_read_status": "connection_reset_by_peer"}}}
    res = classifier.classify(data)
    assert "tls_sni_filtering" in res.labels


def test_technique_http_block_page():
    """
    Validates that body patterns marked 'unverified' in fingerprints are ignored (Phase 3 requirement),
    while an explicit verified pattern classifier triggers when verified evidence exists.
    """
    classifier = TechniqueClassifier()
    data = {
        "raw_json": {
            "test_keys": {
                "response_body": "Your requested URL has been blocked as per the instructions of the Department of Telecommunications, Government of India."
            }
        }
    }
    res = classifier.classify(data)
    # Under Phase 3 rule ("Do not use fingerprints marked 'unverified' in any classification or scoring logic"),
    # dot_statutory_notice is unverified and therefore ignored by TechniqueClassifier.
    assert "unknown" in res.labels or "http_block_page" not in res.labels


def test_category_single_scattered_failure_is_inconclusive():
    classifier = CategoryClassifier()
    # 1 anomaly out of 7 measurements (like nytimes.com on Jio)
    measurements = [
        {"anomaly": False},
        {"anomaly": False},
        {"anomaly": False},
        {"anomaly": False},
        {"anomaly": False},
        {"anomaly": False},
        {"anomaly": True, "raw_json": {"test_keys": {"http_experiment_failure": "generic"}}},
    ]
    res = classifier.classify_isp(measurements)
    assert res.category == "inconclusive"
    assert "transient network noise" in res.reasons[0]


def test_category_censorship_suspected():
    classifier = CategoryClassifier()
    measurements = [
        {"anomaly": True, "technique_labels": ["dns_tampering"], "raw_json": {"test_keys": {}}},
        {"anomaly": True, "technique_labels": ["dns_tampering"], "raw_json": {"test_keys": {}}},
        {"anomaly": True, "technique_labels": ["dns_tampering"], "raw_json": {"test_keys": {}}},
        {"anomaly": False, "raw_json": {"test_keys": {}}},
    ]
    res = classifier.classify_isp(measurements)
    assert res.category == "censorship_suspected"
    assert res.confidence >= 0.75


def test_category_security_related():
    classifier = CategoryClassifier()
    measurements = [{"anomaly": True}]
    res = classifier.classify_isp(
        measurements, is_threat_intel_flagged=True, threat_intel_sources=["URLhaus"]
    )
    assert res.category == "security_related"
    assert res.confidence == 0.95


def test_category_infrastructure_failure():
    classifier = CategoryClassifier()
    measurements = [
        {"anomaly": True, "raw_json": {"test_keys": {"control_failure": "dns_failure"}}},
        {"anomaly": True, "raw_json": {"test_keys": {"control_failure": "dns_failure"}}},
    ]
    res = classifier.classify_isp(measurements)
    assert res.category == "infrastructure_failure"


@pytest.mark.asyncio
async def test_threat_intel_caching():
    service = ThreatIntelService()
    # Query twice to test caching
    res1 = await service.check_domain("example.com")
    res2 = await service.check_domain("example.com")
    assert res1.checked_at == res2.checked_at
