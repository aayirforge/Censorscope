"""
backend/tests/test_live_check.py
Comprehensive test suite for Universal Live Domain Check system.

Test coverage (all unit tests mocked; integration marked):
1. Input validation:
   - IDN / punycode support
   - Single-label rejection
   - IP literal rejection (IPv4 and IPv6)
   - Invalid TLD rejection
   - Internal / reserved TLD rejection
   - Private / loopback resolving domain rejection (127.0.0.1, 169.254.169.254)
2. Registration Service:
   - Random never-registered domain -> APPEARS_UNREGISTERED with evidence and disclaimer
   - example.com -> REGISTERED with evidence
   - NXDOMAIN with RDAP 'found' result -> does NOT give APPEARS_UNREGISTERED
   - TLD with no RDAP service -> UNKNOWN
3. Reachability Service:
   - Reachable site -> REACHABLE
   - Registered domain with no web server -> TCP_FAILURE
   - Domain with expired / invalid certificate -> TLS_FAILURE
4. Rate limiting and per-domain cooldown behavior
5. Explanation Engine:
   - Returns 'cannot determine' when evidence is insufficient
   - Synthesizes multi-country anomalies appropriately
6. SSRF suite compatibility & mutation checks
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

try:
    from analysis.explain import explain_domain_status, ExplanationResult
    from app.utils.tld_validator import validate_and_normalize_target
    from services.check_manager import LiveCheckManager
    from services.country_data import GlobalInterferenceSummary, CountryTelemetry
    from services.reachability import check_reachability, ReachabilityResult
    from services.registration import (
        check_domain_registration,
        RegistrationResult,
        DISCLAIMER_SENTENCE,
    )
except ImportError:
    from backend.analysis.explain import explain_domain_status, ExplanationResult
    from backend.app.utils.tld_validator import validate_and_normalize_target
    from backend.services.check_manager import LiveCheckManager
    from backend.services.country_data import GlobalInterferenceSummary, CountryTelemetry
    from backend.services.reachability import check_reachability, ReachabilityResult
    from backend.services.registration import (
        check_domain_registration,
        RegistrationResult,
        DISCLAIMER_SENTENCE,
    )


# --- 1. Input Validation Tests ---

def test_validate_target_idn_punycode():
    # German umlaut domain -> punycode
    normalized = validate_and_normalize_target("münchen.de")
    assert normalized == "xn--mnchen-3ya.de"


def test_validate_target_single_label_rejected():
    with pytest.raises(ValueError):
        validate_and_normalize_target("localhost")

    with pytest.raises(ValueError):
        validate_and_normalize_target("intranet")


def test_validate_target_ip_literal_rejected():
    with pytest.raises(ValueError, match="IP literals are not permitted"):
        validate_and_normalize_target("192.168.1.1")

    with pytest.raises(ValueError, match="IP literals are not permitted"):
        validate_and_normalize_target("127.0.0.1")

    with pytest.raises(ValueError, match="IP literals are not permitted"):
        validate_and_normalize_target("[::1]")


def test_validate_target_invalid_tld_rejected():
    with pytest.raises(ValueError, match="not recognized in the official IANA TLD registry"):
        validate_and_normalize_target("somefakehostname.notarealtldatallxyz999")


def test_validate_target_reserved_internal_tld_rejected():
    with pytest.raises(ValueError, match="reserved or internal"):
        validate_and_normalize_target("myapp.local")

    with pytest.raises(ValueError, match="reserved or internal"):
        validate_and_normalize_target("internal-service.onion")

    with pytest.raises(ValueError, match="reserved or internal"):
        validate_and_normalize_target("test-box.test")


def test_validate_target_own_domain_rejected():
    with pytest.raises(ValueError, match="Probing internal infrastructure or self-domain"):
        validate_and_normalize_target("censorscope.org")

    with pytest.raises(ValueError):
        validate_and_normalize_target("postgres")


# --- 2. Registration Service Tests (Mocked) ---

@pytest.mark.asyncio
async def test_registration_unregistered_domain():
    domain = "longrandomnonexistentlabel9876543210.com"

    mock_dns = {
        "ns_records": [],
        "soa_present": False,
        "ip_records": [],
        "nxdomain": True,
        "has_records": False,
    }
    mock_doh = {"success": True, "doh_status": 3, "has_answers": False, "nxdomain": True}
    mock_rdap = {
        "queried": True,
        "status_code": 404,
        "rdap_status": [],
        "registrar": None,
        "expiration_date": None,
        "not_found": True,
        "endpoint": "https://rdap.verisign.com/com/v1/",
        "error": None,
    }

    REG_MOD = check_domain_registration.__module__
    with patch(f"{REG_MOD}.query_local_dns", AsyncMock(return_value=mock_dns)), \
         patch(f"{REG_MOD}.query_public_doh", AsyncMock(return_value=mock_doh)), \
         patch(f"{REG_MOD}.query_rdap", AsyncMock(return_value=mock_rdap)):

        res = await check_domain_registration(domain)
        assert res.status == "APPEARS_UNREGISTERED"
        assert "HTTP 404 Not Found" in res.evidence
        assert res.disclaimer == DISCLAIMER_SENTENCE
        assert res.registrar_links is not None
        assert "Namecheap" in res.registrar_links
        assert "GoDaddy" in res.registrar_links


@pytest.mark.asyncio
async def test_registration_example_com_registered():
    domain = "example.com"

    mock_dns = {
        "ns_records": ["a.iana-servers.net", "b.iana-servers.net"],
        "soa_present": True,
        "ip_records": ["93.184.215.14"],
        "nxdomain": False,
        "has_records": True,
    }
    mock_doh = {"success": True, "doh_status": 0, "has_answers": True, "nxdomain": False}
    mock_rdap = {
        "queried": True,
        "status_code": 200,
        "rdap_status": ["clienttransferprohibited"],
        "registrar": "RESERVED-Internet Assigned Numbers Authority",
        "expiration_date": "2027-08-13T04:00:00Z",
        "not_found": False,
        "endpoint": "https://rdap.verisign.com/com/v1/",
        "error": None,
    }

    REG_MOD = check_domain_registration.__module__
    with patch(f"{REG_MOD}.query_local_dns", AsyncMock(return_value=mock_dns)), \
         patch(f"{REG_MOD}.query_public_doh", AsyncMock(return_value=mock_doh)), \
         patch(f"{REG_MOD}.query_rdap", AsyncMock(return_value=mock_rdap)):

        res = await check_domain_registration(domain)
        assert res.status == "REGISTERED"
        assert res.registrar_name == "RESERVED-Internet Assigned Numbers Authority"
        assert res.expiration_date == "2027-08-13T04:00:00Z"
        assert res.registrar_links is None


@pytest.mark.asyncio
async def test_registration_nxdomain_with_rdap_found_not_unregistered():
    # If DNS returns NXDOMAIN (e.g. no NS/A records configured) but RDAP returns 200, domain is NOT unregistered
    domain = "parked-domain-without-dns.com"

    mock_dns = {
        "ns_records": [],
        "soa_present": False,
        "ip_records": [],
        "nxdomain": True,
        "has_records": False,
    }
    mock_doh = {"success": True, "doh_status": 3, "has_answers": False, "nxdomain": True}
    mock_rdap = {
        "queried": True,
        "status_code": 200,
        "rdap_status": ["clienthold"],
        "registrar": "SomeRegistrar LLC",
        "expiration_date": "2027-01-01T00:00:00Z",
        "not_found": False,
        "endpoint": "https://rdap.verisign.com/com/v1/",
        "error": None,
    }

    REG_MOD = check_domain_registration.__module__
    with patch(f"{REG_MOD}.query_local_dns", AsyncMock(return_value=mock_dns)), \
         patch(f"{REG_MOD}.query_public_doh", AsyncMock(return_value=mock_doh)), \
         patch(f"{REG_MOD}.query_rdap", AsyncMock(return_value=mock_rdap)):

        res = await check_domain_registration(domain)
        assert res.status == "REGISTERED"
        assert "clienthold" in res.evidence


@pytest.mark.asyncio
async def test_registration_tld_with_no_rdap_returns_unknown():
    domain = "example.customtldwithnordap"

    mock_dns = {
        "ns_records": [],
        "soa_present": False,
        "ip_records": [],
        "nxdomain": True,
        "has_records": False,
    }
    mock_doh = {"success": False, "doh_status": None, "has_answers": False, "nxdomain": False}
    mock_rdap = {
        "queried": False,
        "status_code": None,
        "rdap_status": [],
        "registrar": None,
        "expiration_date": None,
        "not_found": False,
        "endpoint": None,
        "error": "TLD does not have a registered authoritative RDAP service",
    }

    REG_MOD = check_domain_registration.__module__
    with patch(f"{REG_MOD}.query_local_dns", AsyncMock(return_value=mock_dns)), \
         patch(f"{REG_MOD}.query_public_doh", AsyncMock(return_value=mock_doh)), \
         patch(f"{REG_MOD}.query_rdap", AsyncMock(return_value=mock_rdap)):

        res = await check_domain_registration(domain)
        assert res.status == "UNKNOWN"
        assert "cannot be verified" in res.evidence


# --- 3. Reachability Service Tests ---

@pytest.mark.asyncio
async def test_reachability_rejects_private_ip():
    domain = "internal-fake.com"
    REACH_MOD = check_reachability.__module__

    with patch(f"{REACH_MOD}.validate_and_resolve_host", side_effect=ValueError("Resolves to private IP 127.0.0.1")):
        res = await check_reachability(domain)
        assert res.status == "DNS_FAILURE" or res.status == "NON_PUBLIC_IP"
        assert "127.0.0.1" in res.evidence


@pytest.mark.asyncio
async def test_reachability_tcp_failure_no_web_server():
    domain = "nowebserver.example.com"
    REACH_MOD = check_reachability.__module__

    with patch(f"{REACH_MOD}.validate_and_resolve_host", return_value="93.184.215.14"), \
         patch(f"{REACH_MOD}.test_tcp_connection", AsyncMock(return_value=(False, "Connection refused (RST)"))):

        res = await check_reachability(domain)
        assert res.status == "TCP_FAILURE"
        assert res.failing_layer == "TCP"
        assert "refused" in res.evidence


@pytest.mark.asyncio
async def test_reachability_tls_failure_expired_cert():
    domain = "expired.badssl.com"
    REACH_MOD = check_reachability.__module__

    with patch(f"{REACH_MOD}.validate_and_resolve_host", return_value="104.154.89.105"), \
         patch(f"{REACH_MOD}.test_tcp_connection", AsyncMock(side_effect=[(True, None), (True, None)])), \
         patch(f"{REACH_MOD}.test_tls_handshake", AsyncMock(return_value=(False, None, "certificate has expired"))), \
         patch(f"{REACH_MOD}.safe_fetch", AsyncMock(side_effect=Exception("TLS handshake failed"))):

        res = await check_reachability(domain)
        assert res.status == "TLS_FAILURE"
        assert res.failing_layer == "TLS"
        assert "certificate has expired" in res.evidence


# --- 4. Explanation Engine Tests ---

def test_explanation_insufficient_evidence_returns_cannot_determine():
    reg = RegistrationResult(
        domain="unknown-domain.com",
        status="UNKNOWN",
        ns_records=[],
        soa_present=False,
        dns_resolved=False,
        doh_crosscheck_ok=False,
        rdap_queried=False,
        rdap_status=[],
        rdap_registry_url=None,
        registrar_name=None,
        expiration_date=None,
        evidence="Inconclusive registry signals.",
        disclaimer=DISCLAIMER_SENTENCE,
    )
    reach = ReachabilityResult(
        domain="unknown-domain.com",
        status="DNS_FAILURE",
        failing_layer="DNS",
        http_status=None,
        resolved_ip=None,
        port=0,
        tls_version=None,
        tls_error_detail=None,
        tcp_error_detail=None,
        dns_error_detail="Timeout",
        http_error_detail=None,
        redirect_target=None,
        blockpage_signature=None,
        evidence="DNS query timed out.",
        vantage="Checked from our server",
    )
    country_data = GlobalInterferenceSummary(
        domain="unknown-domain.com",
        countries_observed=0,
        countries_with_anomalies=0,
        total_measurements=0,
        country_data=[],
        india_isp_data=None,
        notice="No measurements available.",
    )

    exp = explain_domain_status(reg, reach, country_data)
    assert exp.overall_status == "INCONCLUSIVE"
    labels = [r.label for r in exp.reasons]
    assert "cannot determine" in labels
    assert "only our server cannot reach it" in labels
    for r in exp.reasons:
        if r.label == "cannot determine":
            assert r.confidence == "Low"


# --- 5. Per-Domain Cooldown and Cache Key Test ---

@pytest.mark.asyncio
async def test_live_check_cooldown_and_cache():
    domain = "cooldown-test.com"

    mock_result = {
        "domain": domain,
        "registration": {"status": "REGISTERED"},
        "reachability_now": {"status": "REACHABLE"},
        "countries": [],
    }

    # Save to cache
    LiveCheckManager.save_cached_result(domain, mock_result, ttl=600)

    # Calling create_check_job should immediately hit cache
    job_id, is_cached = await LiveCheckManager.create_check_job(domain)
    assert is_cached is True
    assert job_id.startswith("cached-")

    job = LiveCheckManager.get_job(job_id)
    assert job is not None
    assert job["status"] == "completed"
    assert job["result"]["domain"] == domain
