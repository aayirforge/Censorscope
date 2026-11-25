"""
backend/app/services/threat_intel.py
Threat Intelligence Integration for CensorScope.
Integrates:
1. URLhaus (abuse.ch) - host lookup API (Requires free Auth-Key from auth.abuse.ch: URLHAUS_AUTH_KEY)
2. Google Safe Browsing Lookup API v4 (Requires free API key: SAFE_BROWSING_API_KEY)
3. PhishTank (Registration closed / public API deprecated by Cisco Talos; handled with status notice)

Caches results for 24 hours in Redis or in-memory dictionary.
Works for any queried domain, even if zero OONI telemetry exists.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 86400  # 24 hours
_IN_MEMORY_CACHE: Dict[str, tuple[float, "ThreatIntelResult"]] = {}


@dataclass
class ThreatIntelResult:
    domain: str
    is_flagged: bool
    category: Optional[str]  # e.g., "malware", "phishing", "c2"
    sources: List[str]  # e.g., ["URLhaus", "Google Safe Browsing"]
    details: Dict[str, any]
    checked_at: float


class ThreatIntelService:
    def __init__(
        self,
        safe_browsing_key: Optional[str] = None,
        urlhaus_auth_key: Optional[str] = None,
    ):
        self.safe_browsing_key = safe_browsing_key or os.getenv("SAFE_BROWSING_API_KEY", "")
        self.urlhaus_auth_key = urlhaus_auth_key or os.getenv("URLHAUS_AUTH_KEY", "")

    async def check_domain(self, domain: str) -> ThreatIntelResult:
        """
        Check domain across threat intelligence feeds with 24-hour caching.
        """
        now = time.time()
        # Check in-memory cache
        if domain in _IN_MEMORY_CACHE:
            cached_time, res = _IN_MEMORY_CACHE[domain]
            if now - cached_time < CACHE_TTL_SECONDS:
                return res

        sources = []
        is_flagged = False
        category = None
        details = {}

        # 1. URLhaus API Check (Requires Auth-Key for reliable programmatic access)
        # Endpoint: POST https://urlhaus-api.abuse.ch/v1/host/ with host=<domain>
        # Headers: Auth-Key: <key>
        headers = {"Accept": "application/json"}
        if self.urlhaus_auth_key:
            headers["Auth-Key"] = self.urlhaus_auth_key

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    "https://urlhaus-api.abuse.ch/v1/host/",
                    data={"host": domain},
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    query_status = data.get("query_status")
                    if query_status in ("online", "offline"):
                        # Host found in URLhaus
                        is_flagged = True
                        category = "malware"
                        sources.append("URLhaus")
                        details["urlhaus"] = {
                            "query_status": query_status,
                            "url_count": data.get("url_count", 0),
                            "threat": "malware_distribution",
                        }
                    else:
                        details["urlhaus"] = {"query_status": query_status}
                elif resp.status_code == 401 or resp.status_code == 403:
                    details["urlhaus"] = {
                        "status": "unauthenticated",
                        "error": "URLhaus requires an Auth-Key from https://auth.abuse.ch/.",
                    }
                else:
                    details["urlhaus"] = {"http_status": resp.status_code}
        except Exception as e:
            logger.warning(f"URLhaus lookup failed for {domain}: {e}")
            details["urlhaus"] = {"error": str(e)}

        # 2. Google Safe Browsing Lookup API v4 Check
        if self.safe_browsing_key:
            try:
                gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.safe_browsing_key}"
                payload = {
                    "client": {
                        "clientId": "censorscope",
                        "clientVersion": "1.0.0",
                    },
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION",
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [
                            {"url": f"http://{domain}/"},
                            {"url": f"https://{domain}/"},
                        ],
                    },
                }
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.post(gsb_url, json=payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        matches = data.get("matches", [])
                        if matches:
                            is_flagged = True
                            if not category:
                                category = matches[0].get("threatType", "malware").lower()
                            sources.append("Google Safe Browsing")
                            details["google_safe_browsing"] = {"matches": matches}
                        else:
                            details["google_safe_browsing"] = {"status": "clean"}
                    else:
                        details["google_safe_browsing"] = {"http_status": resp.status_code}
            except Exception as e:
                logger.warning(f"Google Safe Browsing check failed for {domain}: {e}")
                details["google_safe_browsing"] = {"error": str(e)}
        else:
            details["google_safe_browsing"] = {"status": "unconfigured_missing_api_key"}

        # 3. PhishTank note
        details["phishtank"] = {
            "status": "registration_closed_upstream",
            "note": "Public registration for new PhishTank accounts and API keys has been closed by Cisco Talos due to abuse. Unauthenticated public checks are deprecated or heavily restricted.",
        }

        result = ThreatIntelResult(
            domain=domain,
            is_flagged=is_flagged,
            category=category,
            sources=sources,
            details=details,
            checked_at=now,
        )

        _IN_MEMORY_CACHE[domain] = (now, result)
        return result
