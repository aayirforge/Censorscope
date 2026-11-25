"""
backend/tests/test_verdict_engine.py
Unit tests for Verdict Engine v1 across diverse ISP telemetry fixtures.
"""

from datetime import datetime, timedelta

import pytest

from app.analysis.verdict import VerdictEngine


@pytest.fixture
def verdict_engine():
    return VerdictEngine()


def test_blocked_fixture(verdict_engine):
    """Fixture: 10 measurements across 3 days, 100% DNS anomaly with signature."""
    base_date = datetime(2026, 3, 1, 10, 0, 0)
    measurements = [
        {
            "id": i,
            "measured_at": base_date + timedelta(days=i % 3, hours=i),
            "anomaly": True,
            "signals": {"dns": True, "tcp": False, "http": False, "tls": False},
            "raw_json": {
                "probe_pubkey": f"probe_{i % 3}",
                "test": {"dns": {"resolver": f"resolver_{i % 2}"}},
            },
        }
        for i in range(10)
    ]

    result = verdict_engine.compute_isp_verdict(55836, "Jio", measurements)
    assert result.verdict == "Blocked"
    assert result.confidence >= 0.80
    assert result.primary_technique == "DNS Tampering"
    assert result.explanation.has_strong_signature is True
    assert result.explanation.anomaly_ratio == 1.0


def test_accessible_fixture(verdict_engine):
    """Fixture: 12 measurements across 4 days, 0 anomalies, strong control agreement."""
    base_date = datetime(2026, 3, 1, 10, 0, 0)
    measurements = [
        {
            "measured_at": base_date + timedelta(days=i % 4, hours=i),
            "anomaly": False,
            "signals": {"dns": False, "tcp": False, "http": False, "tls": False},
        }
        for i in range(12)
    ]

    result = verdict_engine.compute_isp_verdict(45609, "Airtel", measurements)
    assert result.verdict == "Accessible"
    assert result.confidence >= 0.80
    assert result.explanation.anomaly_ratio == 0.0
    assert result.explanation.control_agreement_ratio == 1.0


def test_mixed_isp_fixture(verdict_engine):
    """Fixture: Jio blocks domain via TCP reset, but Airtel provides full accessibility."""
    base_date = datetime(2026, 3, 1, 10, 0, 0)
    jio_meas = [
        {
            "id": i,
            "measured_at": base_date + timedelta(days=i % 3, hours=i),
            "anomaly": True,
            "signals": {"dns": False, "tcp": True, "http": False, "tls": False},
            "raw_json": {
                "probe_pubkey": f"probe_{i % 3}",
                "test": {"dns": {"resolver": f"resolver_{i % 2}"}},
            },
        }
        for i in range(8)
    ]
    airtel_meas = [
        {
            "measured_at": base_date + timedelta(days=i % 3, hours=i),
            "anomaly": False,
            "signals": {"dns": False, "tcp": False, "http": False, "tls": False},
        }
        for i in range(8)
    ]

    jio_res = verdict_engine.compute_isp_verdict(55836, "Jio", jio_meas)
    airtel_res = verdict_engine.compute_isp_verdict(45609, "Airtel", airtel_meas)

    assert jio_res.verdict == "Blocked"
    assert airtel_res.verdict == "Accessible"

    # Evaluate synthesized overall verdict
    overall = verdict_engine.compute_domain_overall_verdict(
        "example-mixed-domain.org", [jio_res, airtel_res]
    )

    assert overall.overall_verdict == "Blocked on some ISPs"
    assert "Jio" in overall.summary_explanation["summary"]
    assert "Airtel" in overall.summary_explanation["summary"]


def test_sparse_data_insufficient_fixture(verdict_engine):
    """Fixture: Only 1 measurement recorded (below threshold of 3)."""
    measurements = [
        {
            "measured_at": datetime(2026, 3, 1, 12, 0, 0),
            "anomaly": True,
            "signals": {"dns": True, "tcp": False, "http": False, "tls": False},
        }
    ]

    result = verdict_engine.compute_isp_verdict(9829, "BSNL", measurements)
    assert result.verdict == "Insufficient data"
    assert result.confidence <= 0.40
    assert any("below minimum threshold" in f for f in result.explanation.factors)
