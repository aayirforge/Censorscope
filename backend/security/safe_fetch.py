"""
backend/security/safe_fetch.py
Enterprise-grade SSRF-safe HTTP client with DNS pinning and strict validation.
Defends against:
- IPv4/IPv6 private, loopback, link-local, multicast, and cloud metadata (169.254.169.254)
- IPv4-mapped IPv6, decimal, hex, and octal IP integer representations
- DNS rebinding attacks (pins resolved IP address on connection)
- Redirect attacks (re-validates target IP on every redirect)
- Protocol smuggling / scheme evasion (http/https only)
- Userinfo tricks (user:pass@host)
- Homograph/IDN spoofing (strict punycode conversion)
- Resource exhaustion (response size limits and connection timeouts)
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Dict, Optional, Set
from urllib.parse import urlparse, urlunparse

import httpcore
import httpx
import idna

DEFAULT_MAX_RESPONSE_SIZE = 1024 * 1024  # 1 MB
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_REDIRECTS = 3
ALLOWED_SCHEMES: Set[str] = {"http", "https"}

# Cloud metadata addresses to block explicitly
BLOCKED_IPS: Set[str] = {
    "169.254.169.254",  # AWS/GCP/Azure/DigitalOcean metadata
    "169.254.169.253",  # AWS DNS
    "100.100.100.200",  # Alibaba Cloud metadata
    "fd00:ec2::254",  # AWS IPv6 IMDSv2
}


class SSRFSecurityError(Exception):
    """Raised when an outbound URL violates SSRF security boundaries."""

    pass


class PinnedAsyncNetworkBackend(httpcore.AsyncNetworkBackend):
    """Network backend that connects directly to pre-resolved, validated IP address

    while preserving SNI and Host headers for TLS/HTTP verification.
    """

    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self._real_backend = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Any] = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._real_backend.connect_tcp(
            self.target_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_tls(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        ssl_context: Optional[Any] = None,
        server_hostname: Optional[str] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Any] = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._real_backend.connect_tls(
            self.target_ip,
            port,
            timeout=timeout,
            ssl_context=ssl_context,
            server_hostname=server_hostname or host,
            local_address=local_address,
            socket_options=socket_options,
        )


class PinnedAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    """Transport that pins socket connections to a validated IP."""

    def __init__(self, pinned_ip: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pinned_ip = pinned_ip
        self.backend = PinnedAsyncNetworkBackend(pinned_ip)
        self._pool._network_backend = self.backend


def is_ip_disallowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """
    Check if an IP address belongs to private, loopback, link-local, multicast,
    reserved, or cloud metadata ranges.
    """
    # Unpack IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    ip_str = str(ip)
    if ip_str in BLOCKED_IPS:
        return True

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True

    # Check 0.0.0.0/8 current network
    if isinstance(ip, ipaddress.IPv4Address):
        if ip in ipaddress.IPv4Network("0.0.0.0/8"):
            return True

    # Carrier-grade NAT (100.64.0.0/10)
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.IPv4Network("100.64.0.0/10"):
        return True

    return False


def validate_and_resolve_host(hostname: str) -> tuple[str, str]:
    """
    Validates hostname, rejects IP literals (decimal/octal/hex/IPv6/IPv4-mapped),
    normalizes IDN/punycode, and resolves DNS directly.
    Returns: (canonical_ascii_host, resolved_ip)
    """
    if not hostname:
        raise SSRFSecurityError("Hostname cannot be empty.")

    # 1. Reject IP literals in hostname
    try:
        parsed_ip = ipaddress.ip_address(hostname.strip("[]"))
        if is_ip_disallowed(parsed_ip):
            raise SSRFSecurityError(f"Direct IP literals to restricted range rejected: {hostname}")
        # Even public IP literals are rejected: require valid domain names
        raise SSRFSecurityError(f"Direct IP literals disallowed as hostnames: {hostname}")
    except ValueError:
        pass

    # Check decimal/octal/hex integer IP literals (e.g., 2130706433 for 127.0.0.1 or 0177.0.0.1)
    if hostname.replace(".", "").isdigit():
        try:
            parts = hostname.split(".")
            if len(parts) == 1:
                # 32-bit integer representation
                int_ip = ipaddress.IPv4Address(int(parts[0]))
                if is_ip_disallowed(int_ip):
                    raise SSRFSecurityError(
                        f"Numeric integer IP representation rejected: {hostname}"
                    )
            elif any(p.startswith("0") and len(p) > 1 for p in parts):
                raise SSRFSecurityError(f"Octal IP representation rejected: {hostname}")
        except Exception:
            raise SSRFSecurityError(f"Malformed numerical hostname rejected: {hostname}")

    # Check hex representation (e.g. 0x7f000001)
    if hostname.lower().startswith("0x"):
        raise SSRFSecurityError(f"Hexadecimal IP representation rejected: {hostname}")

    # Reject localhost / localdomain explicitly
    if hostname.lower() in ("localhost", "localhost.localdomain", "broadcasthost"):
        raise SSRFSecurityError(f"Loopback alias rejected: {hostname}")

    # 2. Convert IDN to Punycode
    try:
        ascii_host = idna.encode(hostname.lower(), uts46=True).decode("ascii")
    except Exception as exc:
        raise SSRFSecurityError(f"Invalid IDN / domain syntax: {exc}")

    # 3. Resolve DNS directly
    try:
        addr_info = socket.getaddrinfo(ascii_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFSecurityError(f"DNS resolution failure for host '{ascii_host}': {exc}")

    if not addr_info:
        raise SSRFSecurityError(f"DNS returned no addresses for host '{ascii_host}'")

    # Check all resolved IP addresses; if ANY resolves to a disallowed range, reject
    valid_ips: list[str] = []
    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_cand = sockaddr[0]
        parsed = ipaddress.ip_address(ip_cand)
        if is_ip_disallowed(parsed):
            raise SSRFSecurityError(
                f"DNS resolved '{ascii_host}' to restricted/internal IP address: {ip_cand}"
            )
        if ip_cand not in valid_ips:
            valid_ips.append(ip_cand)

    # Prefer IPv4 over IPv6 when both exist because many host networks lack working IPv6 egress routes
    valid_ips.sort(key=lambda x: 0 if ":" not in x else 1)
    resolved_ip = valid_ips[0] if valid_ips else None

    return ascii_host, resolved_ip


def validate_and_resolve_all_ips(hostname: str) -> tuple[str, list[str]]:
    """
    Validates hostname and returns canonical ASCII host along with ALL resolved public IPs
    ordered with IPv4 first, then IPv6 fallback.
    """
    ascii_host, first_ip = validate_and_resolve_host(hostname)
    # Re-resolve to get the sorted list
    addr_info = socket.getaddrinfo(ascii_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    valid_ips: list[str] = []
    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_cand = sockaddr[0]
        parsed = ipaddress.ip_address(ip_cand)
        if is_ip_disallowed(parsed):
            raise SSRFSecurityError(
                f"DNS resolved '{ascii_host}' to restricted/internal IP address: {ip_cand}"
            )
        if ip_cand not in valid_ips:
            valid_ips.append(ip_cand)
    valid_ips.sort(key=lambda x: 0 if ":" not in x else 1)
    return ascii_host, valid_ips


# SafeFetcher uses httpx.AsyncClient with explicit pre-resolved DNS verification and per-redirect checking


class SafeFetcher:
    """Executes validated, SSRF-safe outbound HTTP GET/POST requests."""

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        truncate_on_limit: bool = False,
    ):
        self.timeout = timeout
        self.max_response_size = max_response_size
        self.max_redirects = max_redirects
        self.truncate_on_limit = truncate_on_limit

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Any] = None,
    ) -> httpx.Response:
        current_url = url
        redirects_followed = 0

        while True:
            # 1. Parse URL
            parsed = urlparse(current_url)

            # Scheme validation
            scheme = parsed.scheme.lower()
            if scheme not in ALLOWED_SCHEMES:
                raise SSRFSecurityError(
                    f"Disallowed scheme '{parsed.scheme}'. Only http and https allowed."
                )

            # Reject userinfo tricks (e.g. http://good.com@127.0.0.1)
            if parsed.username or parsed.password:
                raise SSRFSecurityError(
                    "Userinfo (username/password credentials) in URL is forbidden."
                )

            raw_hostname = parsed.hostname
            if not raw_hostname:
                raise SSRFSecurityError("URL must contain a valid hostname.")

            # 2. Validate and resolve host
            ascii_host, resolved_ip = validate_and_resolve_host(raw_hostname)

            # Reconstruct clean URL
            port = parsed.port or (443 if scheme == "https" else 80)
            clean_url = urlunparse(
                (
                    scheme,
                    f"{ascii_host}:{port}",
                    parsed.path or "/",
                    parsed.params,
                    parsed.query,
                    parsed.fragment,
                )
            )

            req_headers = dict(headers or {})
            req_headers["Host"] = ascii_host

            # 3. Execute request using pinned transport to ensure socket connects to validated IP
            transport = PinnedAsyncHTTPTransport(pinned_ip=resolved_ip, verify=True)
            async with httpx.AsyncClient(
                transport=transport,
                timeout=self.timeout,
                verify=True,
                follow_redirects=False,
            ) as client:
                response = await client.request(
                    method=method,
                    url=clean_url,
                    headers=req_headers,
                    data=data,
                    json=json_data,
                )

                # Read content with strict size cap
                content = b""
                async for chunk in response.aiter_bytes():
                    content += chunk
                    if len(content) > self.max_response_size:
                        if self.truncate_on_limit:
                            content = content[: self.max_response_size]
                            break
                        raise SSRFSecurityError(
                            f"Response size exceeded limit of {self.max_response_size} bytes."
                        )
                # Attach buffered content
                response._content = content

                # 4. Handle Redirects safely
                if response.is_redirect:
                    redirects_followed += 1
                    if redirects_followed > self.max_redirects:
                        raise SSRFSecurityError(
                            f"Maximum redirects ({self.max_redirects}) exceeded."
                        )

                    redirect_url = response.headers.get("Location")
                    if not redirect_url:
                        break

                    # Re-resolve and re-validate destination URL
                    if redirect_url.startswith("/"):
                        current_url = urlunparse(
                            (scheme, f"{ascii_host}:{port}", redirect_url, "", "", "")
                        )
                    else:
                        current_url = redirect_url
                    continue

                return response


safe_fetcher = SafeFetcher()


async def safe_fetch(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Any] = None,
    json_data: Optional[Any] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    truncate_on_limit: bool = False,
) -> httpx.Response:
    """Convenience helper to execute SSRF-safe request via SafeFetcher instance."""
    fetcher = SafeFetcher(
        timeout=timeout,
        max_response_size=max_response_size,
        max_redirects=max_redirects,
        truncate_on_limit=truncate_on_limit,
    )
    return await fetcher.fetch(
        url=url,
        method=method,
        headers=headers,
        data=data,
        json_data=json_data,
    )
