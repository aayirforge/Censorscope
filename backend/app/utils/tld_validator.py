"""
backend/app/utils/tld_validator.py
IANA TLD cache and domain validator.
Downloads and caches https://data.iana.org/TLD/tlds-alpha-by-domain.txt daily.
Rejects internal/reserved TLDs, IP literals, single-label names, and internal domains.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import time
from pathlib import Path
from typing import Optional, Set
import urllib.request

logger = logging.getLogger(__name__)

CACHE_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "cache"
TLD_CACHE_FILE = CACHE_DIR / "iana_tlds.txt"
CACHE_TTL_SECONDS = 86400  # 24 hours

# Reserved / internal names and testing TLDs per RFC 2606, RFC 6761, RFC 6762
RESERVED_TLDS: Set[str] = {
    "local",
    "internal",
    "intranet",
    "lan",
    "home",
    "corp",
    "test",
    "example",
    "invalid",
    "localhost",
    "onion",
    "arpa",
}

# CensorScope's own hostnames and loopback/internal services to block from self-scanning
BLOCKED_OWN_DOMAINS: Set[str] = {
    "censorscope.org",
    "censorscope.net",
    "censorscope.io",
    "censorscope.app",
    "localhost",
    "postgres",
    "redis",
    "backend",
    "fetcher",
    "fetcher_isolated",
    "censorscope_postgres",
    "censorscope_redis",
    "censorscope_backend",
}

# Built-in fallback common TLD list if network is unavailable on fresh initialization
FALLBACK_TLDS: Set[str] = {
    "COM", "NET", "ORG", "INFO", "BIZ", "IO", "CO", "IN", "US", "UK",
    "CA", "AU", "DE", "FR", "NL", "RU", "CN", "JP", "BR", "ME", "TV",
    "CC", "APP", "DEV", "TECH", "ONLINE", "SITE", "STORE", "XYZ", "TOP",
    "GOV", "EDU", "MIL", "INT", "AI", "SO", "SE", "CH", "ES", "IT"
}


class TLDManager:
    """Manages IANA TLD cache with automatic daily refresh."""

    _instance: Optional[TLDManager] = None
    _valid_tlds: Set[str] = set()
    _last_loaded: float = 0.0

    @classmethod
    def get_instance(cls) -> TLDManager:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self) -> None:
        self.refresh_cache_if_needed()

    def refresh_cache_if_needed(self, force: bool = False) -> None:
        """Loads cached TLDs or downloads fresh copy if expired (>24h)."""
        now = time.time()
        if not force and self._valid_tlds and (now - self._last_loaded < CACHE_TTL_SECONDS):
            return

        CACHE_DIR.mkdir(parents=True, exist_ok=True)

        if TLD_CACHE_FILE.exists():
            file_mtime = TLD_CACHE_FILE.stat().st_mtime
            if (now - file_mtime < CACHE_TTL_SECONDS) and not force:
                self._load_from_file()
                return

        # Attempt to fetch fresh from IANA
        try:
            url = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
            req = urllib.request.Request(url, headers={"User-Agent": "CensorScope-TLDUpdater/1.0"})
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    raw_content = resp.read().decode("utf-8")
                    TLD_CACHE_FILE.write_text(raw_content, encoding="utf-8")
                    self._parse_and_set(raw_content)
                    self._last_loaded = now
                    logger.info("Successfully refreshed IANA TLD list (%d TLDs).", len(self._valid_tlds))
                    return
        except Exception as e:
            logger.warning("Failed to download fresh IANA TLD list: %s. Using cached or fallback.", e)

        # Fallback to existing cache file
        if TLD_CACHE_FILE.exists():
            self._load_from_file()
        else:
            # Fallback to embedded default list
            self._valid_tlds = set(FALLBACK_TLDS)
            self._last_loaded = now

    def _load_from_file(self) -> None:
        try:
            content = TLD_CACHE_FILE.read_text(encoding="utf-8")
            self._parse_and_set(content)
            self._last_loaded = time.time()
        except Exception as e:
            logger.error("Failed to read TLD cache file: %s. Using fallback.", e)
            self._valid_tlds = set(FALLBACK_TLDS)

    def _parse_and_set(self, text: str) -> None:
        tlds = set()
        for line in text.splitlines():
            line = line.strip().upper()
            if not line or line.startswith("#"):
                continue
            tlds.add(line)
        if tlds:
            self._valid_tlds = tlds
        else:
            self._valid_tlds = set(FALLBACK_TLDS)

    def is_valid_tld(self, tld: str) -> bool:
        """Check if TLD is in authoritative IANA list."""
        if not self._valid_tlds:
            self.refresh_cache_if_needed()
        clean = tld.strip().upper()
        # Punycode TLDs start with XN--
        return clean in self._valid_tlds


def validate_and_normalize_target(raw_domain: str) -> str:
    """
    Normalizes domain and performs strict security validation:
    1. Rejects empty, whitespace, IP literals (IPv4 and IPv6).
    2. Rejects single-label hostnames.
    3. Normalizes via punycode IDNA.
    4. Validates TLD against authoritative IANA list.
    5. Rejects reserved, internal, or test TLDs.
    6. Rejects CensorScope own infrastructure names.
    """
    if not raw_domain or not isinstance(raw_domain, str):
        raise ValueError("Domain cannot be empty.")

    cleaned = raw_domain.strip().lower()

    # Rejection: Check if input is an IP literal
    # Strip brackets if IPv6
    check_ip = cleaned.strip("[]")
    if ":" in check_ip and "/" not in check_ip:
        # Possible IPv6 or host:port
        parts = check_ip.split(":")
        if len(parts) > 2 or all(p == "" or all(c in "0123456789abcdefABCDEF" for c in p) for p in parts):
            try:
                ipaddress.ip_address(check_ip)
                raise ValueError("IP literals are not permitted. Please enter a fully-qualified domain name.")
            except ValueError as ve:
                if "IP literals" in str(ve):
                    raise

    try:
        ipaddress.ip_address(check_ip)
        raise ValueError("IP literals are not permitted. Please enter a fully-qualified domain name.")
    except ValueError as ve:
        if "IP literals" in str(ve):
            raise
        # Not a valid IP, proceed to domain validation

    from backend.app.utils.domain import normalize_domain
    normalized = normalize_domain(cleaned)

    # Check for single-label
    labels = normalized.split(".")
    if len(labels) < 2:
        raise ValueError("Single-label hostnames are not permitted. Domain must contain at least a name and a valid TLD.")

    # Check against blocked own domains / internal service names
    if normalized in BLOCKED_OWN_DOMAINS:
        raise ValueError(f"Probing internal infrastructure or self-domain '{normalized}' is forbidden.")

    # TLD validation
    tld = labels[-1]
    if tld in RESERVED_TLDS:
        raise ValueError(f"TLD '.{tld}' is reserved or internal and cannot be probed publicly.")

    mgr = TLDManager.get_instance()
    if not mgr.is_valid_tld(tld):
        raise ValueError(f"Top-level domain '.{tld}' is not recognized in the official IANA TLD registry.")

    return normalized
