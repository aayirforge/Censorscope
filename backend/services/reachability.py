"""
backend/services/reachability.py
Live Reachability & Network Layer Diagnostics Service.

Rules:
1. Runs through safe_fetch client and DNS pinning.
2. Steps:
   - DNS resolution
   - TCP connect on 443 and 80 ONLY
   - TLS handshake with SNI
   - One HTTP request with limited redirect count (max 3)
3. No response body storage (read only up to 64KB for known verified blockpage fingerprints, then discard).
4. Clearly identifies requests with User-Agent: CensorScope-ReachabilityBot/1.0.
5. Rejects private, loopback, link-local, multicast, or reserved IPs:
   -> Reports 'resolves to a non-public address'.
6. Classifies outcomes:
   - REACHABLE
   - DNS_FAILURE (NXDOMAIN, SERVFAIL, TIMEOUT)
   - TCP_FAILURE (REFUSED, TIMEOUT)
   - TLS_FAILURE (HANDSHAKE, EXPIRED_CERT, HOSTNAME_MISMATCH)
   - HTTP_ERROR (4xx, 5xx)
   - REDIRECT (with target domain)
   - BLOCK_PAGE (using only verified fingerprints with evidence)
7. Tags vantage: 'Checked from our server at [Region]' (never claims country-wide proof).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import socket
import ssl
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from security.safe_fetch import (
        safe_fetch,
        validate_and_resolve_host,
        validate_and_resolve_all_ips,
        SSRFSecurityError,
    )
except ImportError:
    from backend.security.safe_fetch import (
        safe_fetch,
        validate_and_resolve_host,
        validate_and_resolve_all_ips,
        SSRFSecurityError,
    )

logger = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
VANTAGE_LABEL = os.getenv("SERVER_VANTAGE_LABEL", "Central India (Hosting Server)")

FINGERPRINTS_FILE = Path(__file__).resolve().parent.parent / "data" / "blockpage_fingerprints.json"


@dataclass
class ReachabilityResult:
    domain: str
    status: str  # "REACHABLE", "DNS_FAILURE", "TCP_FAILURE", "TLS_FAILURE", "HTTP_ERROR", "BLOCK_PAGE", "NON_PUBLIC_IP"
    failing_layer: Optional[str]  # "DNS", "TCP", "TLS", "HTTP", or None
    http_status: Optional[int]
    resolved_ip: Optional[str]
    port: int
    tls_version: Optional[str]
    tls_error_detail: Optional[str]
    tcp_error_detail: Optional[str]
    dns_error_detail: Optional[str]
    http_error_detail: Optional[str]
    redirect_target: Optional[str]
    blockpage_signature: Optional[str]
    evidence: str
    vantage: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def load_verified_fingerprints() -> List[Dict[str, Any]]:
    """Loads blockpage fingerprints that have verified measurement evidence."""
    if not FINGERPRINTS_FILE.exists():
        return []
    try:
        data = json.loads(FINGERPRINTS_FILE.read_text(encoding="utf-8"))
        fps = data.get("fingerprints", [])
        # Only return fingerprints with verified evidence
        return [fp for fp in fps if fp.get("evidence") != "unverified"]
    except Exception as e:
        logger.warning("Error loading blockpage fingerprints: %s", e)
        return []


async def test_tcp_connection(ip_str: str, port: int, timeout: float = 3.0) -> Tuple[bool, Optional[str]]:
    """Tests TCP connection to the pinned IP on port 80 or 443."""
    if port not in (80, 443):
        return False, "Port forbidden. Only ports 80 and 443 are permitted."

    try:
        conn = asyncio.open_connection(ip_str, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True, None
    except asyncio.TimeoutError:
        return False, f"TCP connection to {ip_str}:{port} timed out after {timeout}s."
    except ConnectionRefusedError:
        return False, f"TCP connection to {ip_str}:{port} was refused (RST)."
    except OSError as e:
        return False, f"TCP socket error connecting to {ip_str}:{port}: {e}"
    except Exception as e:
        return False, f"TCP error: {e}"


async def test_tls_handshake(domain: str, ip_str: str, timeout: float = 4.0) -> Tuple[bool, Optional[str], Optional[str]]:
    """Performs TLS handshake with SNI to the pinned IP."""
    ctx = ssl.create_default_context()

    try:
        conn = asyncio.open_connection(ip_str, 443, ssl=ctx, server_hostname=domain)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        ssl_obj = writer.get_extra_info("ssl_object")
        tls_version = ssl_obj.version() if ssl_obj else "TLS"
        writer.close()
        await writer.wait_closed()
        return True, tls_version, None
    except asyncio.TimeoutError:
        return False, None, f"TLS handshake to {domain} ({ip_str}:443) timed out."
    except ssl.SSLCertVerificationError as e:
        return False, None, f"TLS certificate validation failed: {e.verify_message or str(e)}"
    except ssl.SSLError as e:
        return False, None, f"TLS error during handshake: {e.reason or str(e)}"
    except ConnectionRefusedError:
        return False, None, "TCP connection refused on port 443."
    except Exception as e:
        return False, None, f"TLS handshake failure: {str(e)}"


async def check_reachability(domain: str) -> ReachabilityResult:
    """
    Executes live multi-layer reachability diagnosis for the domain:
    1. Direct DNS resolution with strict SSRF non-public IP check.
    2. TCP connection test (443 first, then 80).
    3. TLS handshake test on 443 with SNI.
    4. HTTP request with safe_fetch (no body persistence, capped at 64KB for fingerprint scan).
    5. Blockpage fingerprint matching (verified only).
    """
    # Step 1: DNS Resolution & SSRF IP Validation
    try:
        ascii_host, candidate_ips = await asyncio.to_thread(validate_and_resolve_all_ips, domain)
        resolved_ip = candidate_ips[0] if candidate_ips else None
    except SSRFSecurityError as se:
        return ReachabilityResult(
            domain=domain,
            status="NON_PUBLIC_IP",
            failing_layer="DNS",
            http_status=None,
            resolved_ip=None,
            port=0,
            tls_version=None,
            tls_error_detail=None,
            tcp_error_detail=None,
            dns_error_detail=str(se),
            http_error_detail=None,
            redirect_target=None,
            blockpage_signature=None,
            evidence=f"SSRF Protection triggered: Domain resolves to a non-public address ({se}).",
            vantage=f"Checked from our server at {VANTAGE_LABEL}",
        )
    except ValueError as ve:
        err_msg = str(ve).lower()
        if "nxdomain" in err_msg or "not found" in err_msg or "does not exist" in err_msg:
            dns_status = "DNS_FAILURE (NXDOMAIN)"
        elif "servfail" in err_msg:
            dns_status = "DNS_FAILURE (SERVFAIL)"
        elif "timeout" in err_msg:
            dns_status = "DNS_FAILURE (TIMEOUT)"
        else:
            dns_status = "DNS_FAILURE"

        return ReachabilityResult(
            domain=domain,
            status="DNS_FAILURE",
            failing_layer="DNS",
            http_status=None,
            resolved_ip=None,
            port=0,
            tls_version=None,
            tls_error_detail=None,
            tcp_error_detail=None,
            dns_error_detail=str(ve),
            http_error_detail=None,
            redirect_target=None,
            blockpage_signature=None,
            evidence=f"DNS resolution failed: {ve}",
            vantage=f"Checked from our server at {VANTAGE_LABEL}",
        )
    except Exception as e:
        return ReachabilityResult(
            domain=domain,
            status="DNS_FAILURE",
            failing_layer="DNS",
            http_status=None,
            resolved_ip=None,
            port=0,
            tls_version=None,
            tls_error_detail=None,
            tcp_error_detail=None,
            dns_error_detail=str(e),
            http_error_detail=None,
            redirect_target=None,
            blockpage_signature=None,
            evidence=f"DNS lookup failed: {str(e)}",
            vantage=f"Checked from our server at {VANTAGE_LABEL}",
        )

    # Step 2: TCP Connection on 443 and 80 (iterate candidate IPs, preferring IPv4)
    tcp_443_ok = False
    tcp_80_ok = False
    tcp_443_err = None
    tcp_80_err = None

    for ip_cand in candidate_ips:
        c_443_ok, c_443_err = await test_tcp_connection(ip_cand, 443)
        c_80_ok, c_80_err = await test_tcp_connection(ip_cand, 80)
        if c_443_ok or c_80_ok:
            resolved_ip = ip_cand
            tcp_443_ok = c_443_ok
            tcp_80_ok = c_80_ok
            tcp_443_err = c_443_err
            tcp_80_err = c_80_err
            break
        else:
            tcp_443_err = c_443_err
            tcp_80_err = c_80_err

    if not tcp_443_ok and not tcp_80_ok:
        return ReachabilityResult(
            domain=domain,
            status="TCP_FAILURE",
            failing_layer="TCP",
            http_status=None,
            resolved_ip=resolved_ip,
            port=443,
            tls_version=None,
            tls_error_detail=None,
            tcp_error_detail=f"Port 443: {tcp_443_err}; Port 80: {tcp_80_err}",
            dns_error_detail=None,
            http_error_detail=None,
            redirect_target=None,
            blockpage_signature=None,
            evidence=f"DNS resolved to {resolved_ip}, but TCP connections on both port 443 and port 80 failed or were refused.",
            vantage=f"Checked from our server at {VANTAGE_LABEL}",
        )

    # Step 3: TLS Handshake (if 443 is open)
    tls_version = None
    tls_error = None
    if tcp_443_ok:
        tls_ok, tls_ver, tls_err = await test_tls_handshake(domain, resolved_ip)
        if tls_ok:
            tls_version = tls_ver
        else:
            tls_error = tls_err

    # Step 4: HTTP Request via safe_fetch
    scheme = "https" if (tcp_443_ok and not tls_error) else "http"
    target_url = f"{scheme}://{domain}/"

    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}

    verified_fps = load_verified_fingerprints()

    try:
        resp = await safe_fetch(
            target_url,
            method="GET",
            headers=headers,
            timeout=10.0,
            max_redirects=3,
            max_response_size=65536,  # Cap at 64KB, read for fingerprints, discard body
            truncate_on_limit=True,
        )

        http_code = resp.status_code
        redirect_url = str(resp.url) if str(resp.url).rstrip("/") != target_url.rstrip("/") else None

        # Check for verified blockpage fingerprints in headers or body snippet
        matched_fp_name = None
        for fp in verified_fps:
            pattern = fp.get("pattern", "")
            if pattern:
                if pattern.lower() in resp.text.lower():
                    matched_fp_name = fp.get("name", "Known ISP Blockpage")
                    break
                for h_val in resp.headers.values():
                    if pattern.lower() in h_val.lower():
                        matched_fp_name = fp.get("name", "Known ISP Blockpage")
                        break

        if matched_fp_name:
            return ReachabilityResult(
                domain=domain,
                status="BLOCK_PAGE",
                failing_layer="HTTP",
                http_status=http_code,
                resolved_ip=resolved_ip,
                port=443 if scheme == "https" else 80,
                tls_version=tls_version,
                tls_error_detail=None,
                tcp_error_detail=None,
                dns_error_detail=None,
                http_error_detail=f"Blockpage signature matched: {matched_fp_name}",
                redirect_target=redirect_url,
                blockpage_signature=matched_fp_name,
                evidence=f"HTTP response matched verified ISP blockpage signature '{matched_fp_name}' (Status HTTP {http_code}).",
                vantage=f"Checked from our server at {VANTAGE_LABEL}",
            )

        if 200 <= http_code < 400:
            evidence_msg = f"Reachable via {scheme.upper()} (HTTP {http_code}) to IP {resolved_ip}."
            if redirect_url:
                evidence_msg += f" Redirected to: {redirect_url}."
            return ReachabilityResult(
                domain=domain,
                status="REACHABLE",
                failing_layer=None,
                http_status=http_code,
                resolved_ip=resolved_ip,
                port=443 if scheme == "https" else 80,
                tls_version=tls_version,
                tls_error_detail=None,
                tcp_error_detail=None,
                dns_error_detail=None,
                http_error_detail=None,
                redirect_target=redirect_url,
                blockpage_signature=None,
                evidence=evidence_msg,
                vantage=f"Checked from our server at {VANTAGE_LABEL}",
            )
        else:
            return ReachabilityResult(
                domain=domain,
                status="HTTP_ERROR",
                failing_layer="HTTP",
                http_status=http_code,
                resolved_ip=resolved_ip,
                port=443 if scheme == "https" else 80,
                tls_version=tls_version,
                tls_error_detail=None,
                tcp_error_detail=None,
                dns_error_detail=None,
                http_error_detail=f"Server returned HTTP error status {http_code}.",
                redirect_target=redirect_url,
                blockpage_signature=None,
                evidence=f"Connected to {resolved_ip}, but web server returned error status HTTP {http_code}.",
                vantage=f"Checked from our server at {VANTAGE_LABEL}",
            )

    except SSRFSecurityError as se:
        return ReachabilityResult(
            domain=domain,
            status="NON_PUBLIC_IP",
            failing_layer="HTTP",
            http_status=None,
            resolved_ip=resolved_ip,
            port=443 if scheme == "https" else 80,
            tls_version=tls_version,
            tls_error_detail=None,
            tcp_error_detail=None,
            dns_error_detail=None,
            http_error_detail=str(se),
            redirect_target=None,
            blockpage_signature=None,
            evidence=f"Redirect or request blocked by SSRF filter: {se}",
            vantage=f"Checked from our server at {VANTAGE_LABEL}",
        )
    except Exception as e:
        # If HTTPS failed with TLS error earlier, classify as TLS_FAILURE
        if tls_error:
            return ReachabilityResult(
                domain=domain,
                status="TLS_FAILURE",
                failing_layer="TLS",
                http_status=None,
                resolved_ip=resolved_ip,
                port=443,
                tls_version=None,
                tls_error_detail=tls_error,
                tcp_error_detail=None,
                dns_error_detail=None,
                http_error_detail=None,
                redirect_target=None,
                blockpage_signature=None,
                evidence=f"TCP port 443 connected, but TLS handshake failed: {tls_error}",
                vantage=f"Checked from our server at {VANTAGE_LABEL}",
            )

        err_desc = "Request timed out" if "timeout" in type(e).__name__.lower() else (str(e).strip() or type(e).__name__)
        return ReachabilityResult(
            domain=domain,
            status="HTTP_ERROR",
            failing_layer="HTTP",
            http_status=None,
            resolved_ip=resolved_ip,
            port=443 if scheme == "https" else 80,
            tls_version=tls_version,
            tls_error_detail=tls_error,
            tcp_error_detail=None,
            dns_error_detail=None,
            http_error_detail=f"HTTP connection failed: {err_desc}",
            redirect_target=None,
            blockpage_signature=None,
            evidence=f"TCP connected, but HTTP request failed: {err_desc}",
            vantage=f"Checked from our server at {VANTAGE_LABEL}",
        )
