"""
backend/app/utils/domain.py
Domain parsing, validation, and punycode/IDNA normalization.
"""

from __future__ import annotations

import re
import urllib.parse

# RFC 1035 / RFC 1123 label regex
LABEL_REGEX = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def normalize_domain(raw_value: str) -> str:
    """
    Normalizes a domain string:
    - Strips leading/trailing whitespace
    - Strips protocols/schemes (http, https, etc.)
    - Strips credentials, path, port, queries, and fragments
    - Strips trailing dots
    - Lowercases
    - Converts to punycode (ASCII IDNA)
    - Validates label lengths and character rules

    Raises ValueError if input is not a syntactically valid domain name.
    """
    if not raw_value or not isinstance(raw_value, str):
        raise ValueError("Domain cannot be empty")

    cleaned = raw_value.strip().lower()

    # If scheme is missing, urlparse might put the domain in path
    if "://" not in cleaned:
        cleaned = "http://" + cleaned

    parsed = urllib.parse.urlparse(cleaned)
    netloc = parsed.netloc or parsed.path

    # Strip user info (e.g. user:pass@domain.com)
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]

    # Strip port (e.g. domain.com:443 or [::1]:80)
    if ":" in netloc:
        netloc = netloc.split(":", 1)[0]

    # Strip any residual path or trailing dots
    domain = netloc.strip("/.").strip()

    # Strip standard www. prefix for canonical domain matching
    if domain.startswith("www.") and domain.count(".") >= 2:
        domain = domain[4:]

    if not domain:
        raise ValueError(f"Could not extract a valid domain from: '{raw_value}'")

    # Punycode / IDNA encoding conversion
    try:
        domain_ascii = domain.encode("idna").decode("ascii")
    except Exception as exc:
        raise ValueError(f"Invalid IDNA domain encoding for '{domain}': {exc}")

    # Check overall domain length
    if len(domain_ascii) > 253:
        raise ValueError("Domain exceeds maximum allowed length of 253 characters")

    # Split labels
    labels = domain_ascii.split(".")
    if len(labels) < 2:
        raise ValueError("Domain must contain at least one dot separating labels")

    # Validate each label
    for label in labels:
        if not label:
            raise ValueError("Domain contains empty label")
        if len(label) > 63:
            raise ValueError(f"Label '{label}' exceeds maximum length of 63 characters")
        if not LABEL_REGEX.match(label):
            raise ValueError(f"Label '{label}' contains invalid characters")

    # TLD validation (must be at least 2 chars and not purely numeric)
    tld = labels[-1]
    if tld.isdigit():
        raise ValueError(f"Top-level domain '{tld}' cannot be purely numeric")

    return domain_ascii
