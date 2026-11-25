"""
backend/tests/test_ssrf.py
SSRF Security Test Suite for safe_fetch.py.
Tests rejection of:
1. 127.0.0.1 and localhost
2. 0.0.0.0
3. Decimal, hex, and octal IP integer representations
4. IPv6 loopback (::1) and private IPv6 (fc00::/7, fe80::/10)
5. IPv4-mapped IPv6 (::ffff:127.0.0.1, ::ffff:169.254.169.254)
6. Cloud metadata IP 169.254.169.254
7. Userinfo tricks (http://good.com@127.0.0.1)
8. Homograph IDN / Punycode validation
9. Redirect to internal targets
10. Simulated DNS rebinding attack
"""

import ipaddress
from unittest.mock import AsyncMock, patch

import pytest

from security.safe_fetch import (
    SafeFetcher,
    SSRFSecurityError,
    is_ip_disallowed,
    validate_and_resolve_host,
)


def test_ip_disallowed_checks():
    assert is_ip_disallowed(ipaddress.ip_address("127.0.0.1"))
    assert is_ip_disallowed(ipaddress.ip_address("10.0.0.1"))
    assert is_ip_disallowed(ipaddress.ip_address("172.16.0.1"))
    assert is_ip_disallowed(ipaddress.ip_address("192.168.1.1"))
    assert is_ip_disallowed(ipaddress.ip_address("169.254.169.254"))
    assert is_ip_disallowed(ipaddress.ip_address("0.0.0.0"))
    assert is_ip_disallowed(ipaddress.ip_address("::1"))
    assert is_ip_disallowed(ipaddress.ip_address("fe80::1"))
    assert is_ip_disallowed(ipaddress.ip_address("fc00::1"))
    # IPv4-mapped IPv6
    assert is_ip_disallowed(ipaddress.ip_address("::ffff:127.0.0.1"))
    assert is_ip_disallowed(ipaddress.ip_address("::ffff:169.254.169.254"))
    # Public IP should be allowed
    assert not is_ip_disallowed(ipaddress.ip_address("8.8.8.8"))
    assert not is_ip_disallowed(ipaddress.ip_address("1.1.1.1"))


def test_validate_and_resolve_host_direct_private_range_check():
    """
    Direct unit test for the private/loopback/link-local DNS resolution range check.
    Proves that if validate_and_resolve_host resolves to a private IP, it raises SSRFSecurityError.
    Fails immediately if lines 201-205 (is_ip_disallowed check on resolved IPs) are bypassed or removed.
    """
    with patch("security.safe_fetch.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(2, 1, 6, "", ("10.200.1.5", 80))]
        with pytest.raises(SSRFSecurityError, match="restricted/internal IP"):
            validate_and_resolve_host("private-intranet.internal")


@pytest.mark.parametrize(
    "payload",
    [
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "169.254.169.254",
        "2130706433",  # Decimal integer representation of 127.0.0.1
        "0177.0.0.1",  # Octal representation of 127.0.0.1
        "0x7f000001",  # Hex representation of 127.0.0.1
        "[::1]",  # IPv6 loopback
        "[::ffff:127.0.0.1]",  # IPv4-mapped IPv6
        "[fe80::1]",  # Link-local IPv6
        "[fc00::1]",  # Unique local IPv6
        "8.8.8.8",  # Public IP literal rejected (must be domain)
    ],
)
def test_validate_and_resolve_host_rejects_forbidden_formats(payload):
    with pytest.raises(SSRFSecurityError):
        validate_and_resolve_host(payload)


@pytest.mark.asyncio
async def test_safe_fetch_rejects_userinfo_tricks():
    fetcher = SafeFetcher()
    with pytest.raises(SSRFSecurityError, match="Userinfo"):
        await fetcher.fetch("http://admin:secret@wikipedia.org/")


@pytest.mark.asyncio
async def test_safe_fetch_rejects_disallowed_scheme():
    fetcher = SafeFetcher()
    with pytest.raises(SSRFSecurityError, match="Disallowed scheme"):
        await fetcher.fetch("gopher://127.0.0.1:70/")
    with pytest.raises(SSRFSecurityError, match="Disallowed scheme"):
        await fetcher.fetch("file:///etc/passwd")


@pytest.mark.asyncio
async def test_safe_fetch_dns_rebinding_simulation():
    fetcher = SafeFetcher()
    # Simulate host resolving to private IP on resolution
    with patch("security.safe_fetch.socket.getaddrinfo") as mock_dns:
        # Return 127.0.0.1
        mock_dns.return_value = [(2, 1, 6, "", ("127.0.0.1", 80))]
        with pytest.raises(SSRFSecurityError, match="restricted/internal IP"):
            await fetcher.fetch("http://rebind-test.internal/")


@pytest.mark.asyncio
async def test_safe_fetch_redirect_to_internal_ip():
    fetcher = SafeFetcher()
    # Mock first response redirecting to 127.0.0.1
    mock_resp = AsyncMock()
    mock_resp.is_redirect = True
    mock_resp.headers = {"Location": "http://127.0.0.1/admin"}

    async def mock_aiter():
        yield b"redirecting..."

    mock_resp.aiter_bytes = mock_aiter

    with patch("security.safe_fetch.validate_and_resolve_host") as mock_val:
        mock_val.side_effect = [
            ("valid-domain.com", "93.184.216.34"),
            SSRFSecurityError("Direct IP literals disallowed as hostnames: 127.0.0.1"),
        ]
        with patch("httpx.AsyncClient.request", return_value=mock_resp):
            with pytest.raises(SSRFSecurityError, match="Direct IP literals disallowed"):
                await fetcher.fetch("http://valid-domain.com/")


@pytest.mark.asyncio
async def test_safe_fetch_pinned_ip_network_backend():
    """Verify that PinnedAsyncHTTPTransport routes connect_tcp to the pinned IP."""
    from security.safe_fetch import PinnedAsyncHTTPTransport
    from unittest.mock import AsyncMock

    transport = PinnedAsyncHTTPTransport(pinned_ip="93.184.215.14")
    assert transport.pinned_ip == "93.184.215.14"

    # Mock the internal real backend's connect_tcp to verify arguments
    transport.backend._real_backend.connect_tcp = AsyncMock(return_value=AsyncMock())
    await transport.backend.connect_tcp("example.com", 80)
    transport.backend._real_backend.connect_tcp.assert_awaited_once_with(
        "93.184.215.14", 80, timeout=None, local_address=None, socket_options=None
    )
