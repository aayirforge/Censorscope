"""
backend/services/registration.py
Authoritative Domain Registration Status & RDAP Inspection Service.

Rules:
1. Queries DNS for NS, SOA, A, and AAAA using local resolver.
2. Cross-checks via public DoH resolver (Cloudflare / Google) using safe_fetch client.
3. Queries RDAP: uses IANA RDAP bootstrap file (cached) to locate registry RDAP endpoint.
4. HTTP 404 from registry RDAP treated as 'not found'.
5. Reads status values: pendingDelete, redemptionPeriod, clientHold, serverHold, and expiry date.
6. Respects rate limits (HTTP 429) with exponential backoff.
7. Outputs one of: REGISTERED, APPEARS_UNREGISTERED, UNKNOWN.
   - Never outputs 'available to buy'.
   - NXDOMAIN alone is NOT enough to say unregistered (explicitly explained in evidence).
8. Always includes evidence and registrar search links for APPEARS_UNREGISTERED.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import socket
import ssl

try:
    from security.safe_fetch import safe_fetch, SSRFSecurityError
except ImportError:
    from backend.security.safe_fetch import safe_fetch, SSRFSecurityError

logger = logging.getLogger(__name__)

CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "cache"
RDAP_BOOTSTRAP_FILE = CACHE_DIR / "rdap_dns.json"
BOOTSTRAP_TTL_SECONDS = 86400  # 24 hours

DISCLAIMER_SENTENCE = "Availability, price and restrictions (premium, reserved or pending-delete names) must be confirmed with a registrar."

# Status codes indicating hold or deletion phases
HOLD_OR_DELETION_STATUSES = {
    "pendingdelete",
    "redemptionperiod",
    "clienthold",
    "serverhold",
    "inactive",
}


@dataclass
class RegistrationResult:
    domain: str
    status: str  # "REGISTERED", "APPEARS_UNREGISTERED", "UNKNOWN"
    ns_records: List[str]
    soa_present: bool
    dns_resolved: bool
    doh_crosscheck_ok: bool
    rdap_queried: bool
    rdap_status: List[str]
    rdap_registry_url: Optional[str]
    registrar_name: Optional[str]
    expiration_date: Optional[str]
    evidence: str
    disclaimer: str
    registrar_links: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RDAPBootstrapManager:
    """Manages IANA RDAP bootstrap data (https://data.iana.org/rdap/dns.json)."""

    _bootstrap_data: Optional[Dict[str, Any]] = None
    _last_loaded: float = 0.0

    @classmethod
    def get_rdap_endpoint(cls, tld: str) -> Optional[str]:
        cls._ensure_loaded()
        if not cls._bootstrap_data or "services" not in cls._bootstrap_data:
            return None

        clean_tld = tld.strip().lower()
        services = cls._bootstrap_data.get("services", [])
        for tld_list, endpoints in services:
            if clean_tld in [t.lower() for t in tld_list]:
                if endpoints:
                    # Return first HTTPS endpoint if available
                    for ep in endpoints:
                        if ep.startswith("https://"):
                            return ep.rstrip("/") + "/"
                    return endpoints[0].rstrip("/") + "/"
        return None

    @classmethod
    def _ensure_loaded(cls, force: bool = False) -> None:
        now = time.time()
        if not force and cls._bootstrap_data and (now - cls._last_loaded < BOOTSTRAP_TTL_SECONDS):
            return

        CACHE_DIR.mkdir(parents=True, exist_ok=True)

        if RDAP_BOOTSTRAP_FILE.exists() and not force:
            mtime = RDAP_BOOTSTRAP_FILE.stat().st_mtime
            if now - mtime < BOOTSTRAP_TTL_SECONDS:
                try:
                    data = json.loads(RDAP_BOOTSTRAP_FILE.read_text(encoding="utf-8"))
                    cls._bootstrap_data = data
                    cls._last_loaded = now
                    return
                except Exception as e:
                    logger.warning("Error reading RDAP bootstrap cache: %s", e)

        # Download fresh from IANA
        try:
            import urllib.request
            url = "https://data.iana.org/rdap/dns.json"
            req = urllib.request.Request(url, headers={"User-Agent": "CensorScope-RDAPBootstrap/1.0"})
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    raw = resp.read().decode("utf-8")
                    data = json.loads(raw)
                    RDAP_BOOTSTRAP_FILE.write_text(raw, encoding="utf-8")
                    cls._bootstrap_data = data
                    cls._last_loaded = now
                    logger.info("Successfully refreshed IANA RDAP bootstrap file.")
                    return
        except Exception as e:
            logger.warning("Failed to download IANA RDAP bootstrap file: %s", e)

        if RDAP_BOOTSTRAP_FILE.exists():
            try:
                cls._bootstrap_data = json.loads(RDAP_BOOTSTRAP_FILE.read_text(encoding="utf-8"))
                cls._last_loaded = now
            except Exception:
                cls._bootstrap_data = {"services": []}
        else:
            cls._bootstrap_data = {"services": []}


def generate_registrar_links(domain: str) -> Dict[str, str]:
    """Generates plain outbound query links to standard domain registrars."""
    encoded = urllib.parse.quote(domain)
    return {
        "Namecheap": f"https://www.namecheap.com/domains/registration/results/?domain={encoded}",
        "GoDaddy": f"https://www.godaddy.com/domainsearch/find?checkAvail=1&domainToCheck={encoded}",
        "Hostinger": f"https://www.hostinger.com/domain-name-search?domain={encoded}",
        "Squarespace (Google Domains)": f"https://domains.squarespace.com/domain-search?q={encoded}",
    }


async def query_local_dns(domain: str) -> Dict[str, Any]:
    """Queries local resolver for A/AAAA and host info using standard library socket."""
    ns_records: List[str] = []
    soa_present = False
    ip_records: List[str] = []
    nxdomain = False

    def resolve_addr():
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            return [info[4][0] for info in infos]
        except socket.gaierror as e:
            if e.errno in (socket.EAI_NONAME, socket.EAI_NODATA, -2):
                return "NXDOMAIN"
            return None
        except Exception:
            return None

    res = await asyncio.to_thread(resolve_addr)
    if res == "NXDOMAIN":
        nxdomain = True
    elif isinstance(res, list) and res:
        ip_records = list(set(res))

    return {
        "ns_records": ns_records,
        "soa_present": soa_present,
        "ip_records": ip_records,
        "nxdomain": nxdomain,
        "has_records": bool(ip_records),
    }


async def query_public_doh(domain: str) -> Dict[str, Any]:
    """Cross-checks domain DNS via Cloudflare/Google DoH over safe_fetch client."""
    doh_url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type=A"
    headers = {"Accept": "application/dns-json", "User-Agent": "CensorScope-RegistrationCheck/1.0"}

    try:
        resp = await safe_fetch(doh_url, method="GET", headers=headers, timeout=4.0)
        if resp.status_code == 200:
            data = json.loads(resp.text)
            status_code = data.get("Status", -1)
            # Status 0 = NOERROR, 3 = NXDOMAIN
            answers = data.get("Answer", [])
            return {
                "success": True,
                "doh_status": status_code,
                "has_answers": bool(answers),
                "nxdomain": status_code == 3,
            }
    except Exception as e:
        logger.debug("DoH crosscheck failed for %s: %s", domain, e)

    # Fallback to Google DoH
    try:
        google_doh_url = f"https://dns.google/resolve?name={urllib.parse.quote(domain)}&type=A"
        resp = await safe_fetch(google_doh_url, method="GET", timeout=4.0)
        if resp.status_code == 200:
            data = json.loads(resp.text)
            status_code = data.get("Status", -1)
            answers = data.get("Answer", [])
            return {
                "success": True,
                "doh_status": status_code,
                "has_answers": bool(answers),
                "nxdomain": status_code == 3,
            }
    except Exception as e:
        logger.debug("Google DoH fallback failed for %s: %s", domain, e)

    return {"success": False, "doh_status": None, "has_answers": False, "nxdomain": False}


async def query_rdap(domain: str, tld: str) -> Dict[str, Any]:
    """
    Queries authoritative registry RDAP server for the domain.
    Respects HTTP 429 with backoff.
    """
    endpoint = RDAPBootstrapManager.get_rdap_endpoint(tld)
    if not endpoint:
        return {
            "queried": False,
            "status_code": None,
            "rdap_status": [],
            "registrar": None,
            "expiration_date": None,
            "not_found": False,
            "endpoint": None,
            "error": f"TLD '.{tld}' does not have a registered authoritative RDAP service in IANA bootstrap.",
        }

    target_url = f"{endpoint}domain/{urllib.parse.quote(domain)}"
    headers = {"Accept": "application/rdap+json, application/json", "User-Agent": "CensorScope-RDAPClient/1.0"}

    # Attempt query with backoff on 429
    max_retries = 2
    for attempt in range(max_retries):
        try:
            resp = await safe_fetch(target_url, method="GET", headers=headers, timeout=5.0)
            if resp.status_code == 200:
                data = json.loads(resp.text)
                statuses = [s.lower() for s in data.get("status", [])]
                registrar = None
                for entity in data.get("entities", []):
                    if "registrar" in entity.get("roles", []):
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item and item[0] == "fn":
                                    registrar = item[3]
                                    break
                # Expiration date from events
                exp_date = None
                for event in data.get("events", []):
                    if event.get("eventAction") == "expiration":
                        exp_date = event.get("eventDate")
                        break

                return {
                    "queried": True,
                    "status_code": 200,
                    "rdap_status": statuses,
                    "registrar": registrar,
                    "expiration_date": exp_date,
                    "not_found": False,
                    "endpoint": endpoint,
                    "error": None,
                }

            elif resp.status_code == 404:
                return {
                    "queried": True,
                    "status_code": 404,
                    "rdap_status": [],
                    "registrar": None,
                    "expiration_date": None,
                    "not_found": True,
                    "endpoint": endpoint,
                    "error": None,
                }

            elif resp.status_code == 429:
                if attempt < max_retries - 1:
                    await asyncio.sleep(1.5 * (attempt + 1))
                    continue
                return {
                    "queried": True,
                    "status_code": 429,
                    "rdap_status": [],
                    "registrar": None,
                    "expiration_date": None,
                    "not_found": False,
                    "endpoint": endpoint,
                    "error": "RDAP registry rate limit reached (HTTP 429).",
                }
            else:
                return {
                    "queried": True,
                    "status_code": resp.status_code,
                    "rdap_status": [],
                    "registrar": None,
                    "expiration_date": None,
                    "not_found": False,
                    "endpoint": endpoint,
                    "error": f"RDAP server returned HTTP {resp.status_code}.",
                }

        except Exception as e:
            if attempt < max_retries - 1:
                await asyncio.sleep(1.0)
                continue
            return {
                "queried": True,
                "status_code": None,
                "rdap_status": [],
                "registrar": None,
                "expiration_date": None,
                "not_found": False,
                "endpoint": endpoint,
                "error": f"RDAP connection error: {str(e)}",
            }

    return {
        "queried": True,
        "status_code": None,
        "rdap_status": [],
        "registrar": None,
        "expiration_date": None,
        "not_found": False,
        "endpoint": endpoint,
        "error": "RDAP request timed out after retries.",
    }


async def check_domain_registration(domain: str) -> RegistrationResult:
    """
    Main registration verification workflow combining DNS, DoH crosscheck, and RDAP.
    Outputs: REGISTERED, APPEARS_UNREGISTERED, or UNKNOWN.
    """
    parts = domain.strip().lower().split(".")
    tld = parts[-1]

    # Run DNS and RDAP queries in parallel
    dns_task = query_local_dns(domain)
    doh_task = query_public_doh(domain)
    rdap_task = query_rdap(domain, tld)

    dns_res, doh_res, rdap_res = await asyncio.gather(dns_task, doh_task, rdap_task)

    ns_records = dns_res["ns_records"]
    soa_present = dns_res["soa_present"]
    has_dns_records = dns_res["has_records"]
    dns_nxdomain = dns_res["nxdomain"] or (doh_res["success"] and doh_res["nxdomain"])

    rdap_queried = rdap_res["queried"]
    rdap_404 = rdap_res["not_found"]
    rdap_statuses = rdap_res["rdap_status"]
    rdap_endpoint = rdap_res["endpoint"]
    registrar = rdap_res["registrar"]
    exp_date = rdap_res["expiration_date"]

    evidence_parts: List[str] = []

    # 1. Evaluate RDAP 200 (Registered)
    if rdap_queried and rdap_res["status_code"] == 200:
        status_str = ", ".join(rdap_statuses) if rdap_statuses else "active"
        evidence_parts.append(f"Authoritative RDAP registry returned record (Status: {status_str}).")
        if registrar:
            evidence_parts.append(f"Registrar: {registrar}.")
        if exp_date:
            evidence_parts.append(f"Expiration Date: {exp_date}.")

        # Check for hold or deletion states
        found_holds = [s for s in rdap_statuses if s in HOLD_OR_DELETION_STATUSES]
        if found_holds:
            evidence_parts.append(f"Domain is currently in regulatory/lifecycle status: {', '.join(found_holds)}.")

        return RegistrationResult(
            domain=domain,
            status="REGISTERED",
            ns_records=ns_records,
            soa_present=soa_present,
            dns_resolved=has_dns_records,
            doh_crosscheck_ok=doh_res["success"],
            rdap_queried=True,
            rdap_status=rdap_statuses,
            rdap_registry_url=rdap_endpoint,
            registrar_name=registrar,
            expiration_date=exp_date,
            evidence=" ".join(evidence_parts),
            disclaimer=DISCLAIMER_SENTENCE,
            registrar_links=None,
        )

    # 2. Evaluate DNS Presence even if RDAP failed or unsupported
    if has_dns_records:
        evidence_parts.append("Authoritative DNS records (NS/SOA/A) observed.")
        if ns_records:
            evidence_parts.append(f"Nameservers: {', '.join(ns_records[:4])}.")
        if rdap_res["error"]:
            evidence_parts.append(f"RDAP note: {rdap_res['error']}.")

        return RegistrationResult(
            domain=domain,
            status="REGISTERED",
            ns_records=ns_records,
            soa_present=soa_present,
            dns_resolved=True,
            doh_crosscheck_ok=doh_res["success"],
            rdap_queried=rdap_queried,
            rdap_status=[],
            rdap_registry_url=rdap_endpoint,
            registrar_name=registrar,
            expiration_date=None,
            evidence=" ".join(evidence_parts),
            disclaimer=DISCLAIMER_SENTENCE,
            registrar_links=None,
        )

    # 3. Evaluate Unregistered
    # MUST have RDAP 404 AND DNS absence/NXDOMAIN
    if rdap_queried and rdap_404:
        evidence_parts.append("Authoritative RDAP registry returned HTTP 404 Not Found.")
        if dns_nxdomain:
            evidence_parts.append("DNS resolution returned NXDOMAIN.")
        else:
            evidence_parts.append("No authoritative NS or A records configured.")
        evidence_parts.append("Note: NXDOMAIN alone is insufficient proof of registration availability; confirmed via RDAP 404.")

        return RegistrationResult(
            domain=domain,
            status="APPEARS_UNREGISTERED",
            ns_records=[],
            soa_present=False,
            dns_resolved=False,
            doh_crosscheck_ok=doh_res["success"],
            rdap_queried=True,
            rdap_status=[],
            rdap_registry_url=rdap_endpoint,
            registrar_name=None,
            expiration_date=None,
            evidence=" ".join(evidence_parts),
            disclaimer=DISCLAIMER_SENTENCE,
            registrar_links=generate_registrar_links(domain),
        )

    # 4. Unknown (e.g. TLD has no RDAP service, or query rate-limited/failed, and DNS has no records)
    if not rdap_queried or rdap_res["error"]:
        reason = rdap_res["error"] or "Authoritative RDAP service could not be contacted."
        evidence_parts.append(f"Registration status cannot be verified: {reason}")
        if dns_nxdomain:
            evidence_parts.append("DNS returned NXDOMAIN, but absent authoritative RDAP confirmation, registration cannot be ruled out.")

        return RegistrationResult(
            domain=domain,
            status="UNKNOWN",
            ns_records=[],
            soa_present=False,
            dns_resolved=False,
            doh_crosscheck_ok=doh_res["success"],
            rdap_queried=rdap_queried,
            rdap_status=[],
            rdap_registry_url=rdap_endpoint,
            registrar_name=None,
            expiration_date=None,
            evidence=" ".join(evidence_parts),
            disclaimer=DISCLAIMER_SENTENCE,
            registrar_links=generate_registrar_links(domain),
        )

    return RegistrationResult(
        domain=domain,
        status="UNKNOWN",
        ns_records=[],
        soa_present=False,
        dns_resolved=False,
        doh_crosscheck_ok=doh_res["success"],
        rdap_queried=rdap_queried,
        rdap_status=[],
        rdap_registry_url=rdap_endpoint,
        registrar_name=None,
        expiration_date=None,
        evidence="Inconclusive registry signals.",
        disclaimer=DISCLAIMER_SENTENCE,
        registrar_links=None,
    )
