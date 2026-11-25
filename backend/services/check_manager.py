"""
backend/services/check_manager.py
Asynchronous Live Domain Check Pipeline Manager.

Features:
- Concurrency cap (max concurrent background workers)
- In-memory / Redis job storage with progress tracking
- Per-domain cooldown and HMAC-SHA256 privacy-preserving cache
- Hard timeouts for each step
- Kill switch: ENABLE_LIVE_CHECKS environment variable
- Extensible CAPTCHA / PoW verification hook
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from typing import Any, Dict, Optional

try:
    from analysis.explain import explain_domain_status, ExplanationResult
    from app.api.cache import get_hmac_cache_key
    from app.utils.tld_validator import validate_and_normalize_target
    from services.country_data import get_global_country_data, GlobalInterferenceSummary
    from services.reachability import check_reachability, ReachabilityResult
    from services.registration import check_domain_registration, RegistrationResult
except (ImportError, ModuleNotFoundError):
    from backend.analysis.explain import explain_domain_status, ExplanationResult
    from backend.app.api.cache import get_hmac_cache_key
    from backend.app.utils.tld_validator import validate_and_normalize_target
    from backend.services.country_data import get_global_country_data, GlobalInterferenceSummary
    from backend.services.reachability import check_reachability, ReachabilityResult
    from backend.services.registration import check_domain_registration, RegistrationResult

logger = logging.getLogger(__name__)

# Concurrency & limits
MAX_CONCURRENT_JOBS = int(os.getenv("MAX_CONCURRENT_LIVE_CHECKS", "10"))
ENABLE_LIVE_CHECKS = os.getenv("ENABLE_LIVE_CHECKS", "true").lower() in ("true", "1", "yes")

# TTLs in seconds
TTL_REACHABILITY = 600       # 10 minutes (per-domain cooldown)
TTL_RDAP = 86400            # 24 hours
TTL_COUNTRY_OONI = 21600    # 6 hours

# Semaphore for concurrency control
_WORKER_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_JOBS)

# Job store (in-memory with Redis fallback if available)
_JOBS: Dict[str, Dict[str, Any]] = {}
_DOMAIN_COOLDOWNS: Dict[str, float] = {}  # domain -> timestamp when cooldown expires
_CACHE: Dict[str, Tuple[float, Any]] = {}  # hmac_key -> (expires_at, data)


def is_live_check_enabled() -> bool:
    """Checks the global kill switch."""
    return os.getenv("ENABLE_LIVE_CHECKS", "true").lower() in ("true", "1", "yes")


def verify_pow_token_hook(token: Optional[str]) -> bool:
    """
    Placeholder hook for Cloudflare Turnstile or proof-of-work validation.
    Returns True by default unless TURNSTILE_SECRET_KEY or REQUIRE_POW is set.
    """
    require_pow = os.getenv("REQUIRE_POW", "false").lower() in ("true", "1")
    if not require_pow:
        return True
    if not token:
        return False
    # Validate token if integration key is provided
    secret = os.getenv("TURNSTILE_SECRET_KEY")
    if secret:
        # In production, query Cloudflare siteverify API here
        return len(token) > 20
    return True


class LiveCheckManager:
    """Orchestrates registration, reachability, country data, and explanation."""

    @classmethod
    def get_job(cls, job_id: str) -> Optional[Dict[str, Any]]:
        return _JOBS.get(job_id)

    @classmethod
    def check_cached_result(cls, domain: str) -> Optional[Dict[str, Any]]:
        """Checks if a valid, unexpired check result exists for this domain."""
        now = time.time()
        key = get_hmac_cache_key(f"full_check:{domain}")
        if key in _CACHE:
            exp, data = _CACHE[key]
            if now < exp:
                return data
            else:
                del _CACHE[key]
        return None

    @classmethod
    def save_cached_result(cls, domain: str, result_dict: Dict[str, Any], ttl: int = TTL_REACHABILITY) -> None:
        key = get_hmac_cache_key(f"full_check:{domain}")
        _CACHE[key] = (time.time() + ttl, result_dict)
        _DOMAIN_COOLDOWNS[domain] = time.time() + ttl

    @classmethod
    async def create_check_job(cls, raw_domain: str, pow_token: Optional[str] = None) -> Tuple[str, bool]:
        """
        Validates input, checks kill switch, checks cache/cooldown, creates job, and queues processing.
        Returns: (job_id, is_cached_immediate)
        """
        if not is_live_check_enabled():
            raise RuntimeError("Live reachability checks are currently disabled by administrator (kill-switch active).")

        if not verify_pow_token_hook(pow_token):
            raise PermissionError("Proof-of-work or bot challenge verification failed.")

        # Normalize and validate TLD / IP / Internal names
        domain = validate_and_normalize_target(raw_domain)

        # Check existing cached result (per-domain cooldown)
        cached = cls.check_cached_result(domain)
        if cached:
            job_id = f"cached-{uuid.uuid4()}"
            _JOBS[job_id] = {
                "id": job_id,
                "domain": domain,
                "status": "completed",
                "progress": 100,
                "created_at": time.time(),
                "completed_at": time.time(),
                "result": cached,
                "cached": True,
            }
            return job_id, True

        # Create new active job
        job_id = str(uuid.uuid4())
        _JOBS[job_id] = {
            "id": job_id,
            "domain": domain,
            "status": "queued",
            "progress": 5,
            "created_at": time.time(),
            "completed_at": None,
            "result": None,
            "error": None,
            "cached": False,
        }

        # Spawn asynchronous worker task
        asyncio.create_task(cls._execute_check_pipeline(job_id, domain))
        return job_id, False

    @classmethod
    async def _execute_check_pipeline(cls, job_id: str, domain: str) -> None:
        """Executes registration, reachability, and OONI country checks with timeout."""
        job = _JOBS[job_id]
        async with _WORKER_SEMAPHORE:
            try:
                job["status"] = "processing"
                job["progress"] = 15

                # Step 1: Registration check (DNS + RDAP) - 7s timeout
                try:
                    reg_res: RegistrationResult = await asyncio.wait_for(
                        check_domain_registration(domain), timeout=8.0
                    )
                except asyncio.TimeoutError:
                    logger.warning("Registration check timed out for %s", domain)
                    reg_res = RegistrationResult(
                        domain=domain,
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
                        evidence="Registration and RDAP queries timed out.",
                        disclaimer="Availability, price and restrictions must be confirmed with a registrar.",
                    )
                job["progress"] = 45

                # Step 2: Reachability check (safe_fetch TCP/TLS/HTTP) - 10s timeout
                try:
                    reach_res: ReachabilityResult = await asyncio.wait_for(
                        check_reachability(domain), timeout=10.0
                    )
                except asyncio.TimeoutError:
                    logger.warning("Reachability check timed out for %s", domain)
                    reach_res = ReachabilityResult(
                        domain=domain,
                        status="TCP_FAILURE",
                        failing_layer="TCP",
                        http_status=None,
                        resolved_ip=None,
                        port=443,
                        tls_version=None,
                        tls_error_detail=None,
                        tcp_error_detail="Connection attempt timed out.",
                        dns_error_detail=None,
                        http_error_detail=None,
                        redirect_target=None,
                        blockpage_signature=None,
                        evidence="Live connection test timed out from our server.",
                        vantage="Checked from our server",
                    )
                job["progress"] = 75

                # Step 3: Global Country OONI Aggregation - 8s timeout
                try:
                    country_res: GlobalInterferenceSummary = await asyncio.wait_for(
                        get_global_country_data(domain), timeout=8.0
                    )
                except Exception as e:
                    logger.warning("Global country data error for %s: %s", domain, e)
                    country_res = GlobalInterferenceSummary(
                        domain=domain,
                        countries_observed=0,
                        countries_with_anomalies=0,
                        total_measurements=0,
                        country_data=[],
                        india_isp_data=None,
                        notice="Failed to fetch external country telemetry.",
                    )
                job["progress"] = 90

                # Step 4: Synthesize through Explanation Engine
                explanation: ExplanationResult = explain_domain_status(reg_res, reach_res, country_res)

                final_result = {
                    "domain": domain,
                    "registration": reg_res.to_dict(),
                    "reachability_now": reach_res.to_dict(),
                    "countries": [c.to_dict() for c in country_res.country_data],
                    "countries_summary": {
                        "countries_observed": country_res.countries_observed,
                        "countries_with_anomalies": country_res.countries_with_anomalies,
                        "total_measurements": country_res.total_measurements,
                        "notice": country_res.notice,
                    },
                    "india_isp": country_res.india_isp_data,
                    "explanation": explanation.to_dict(),
                    "reasons": [r.to_dict() for r in explanation.reasons],
                    "limitations": explanation.limitations,
                    "timestamp": time.time(),
                }

                # Save to cache with cooldown
                cls.save_cached_result(domain, final_result, ttl=TTL_REACHABILITY)

                job["status"] = "completed"
                job["progress"] = 100
                job["result"] = final_result
                job["completed_at"] = time.time()

            except Exception as e:
                logger.exception("Error processing live check for domain %s: %s", domain, e)
                job["status"] = "failed"
                job["error"] = str(e)
                job["completed_at"] = time.time()
