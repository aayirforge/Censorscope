"""
backend/utils/canonical.py
Canonical JSON serialization shared by probe clients, ingestion APIs, and evidence anchoring.

Deterministic JSON rules (RFC 8785 / ECMAScript JSON compatible):
1. Object keys sorted lexicographically by UTF-8 bytes.
2. Compact separators without trailing or separating whitespace (',' and ':').
3. Strict UTF-8 encoding (ensure_ascii=False) preserving native Unicode strings.
4. Floats represented consistently without unnecessary exponents or trailing zeros (.0 integers canonicalize to integer format matching JS JSON.stringify).
"""

from __future__ import annotations

import json
from typing import Any


def _normalize_numbers(obj: Any) -> Any:
    """Normalize floats such that whole-number floats serialize identically to JS JSON.stringify (e.g. 0.0 -> 0)."""
    if isinstance(obj, float):
        if obj.is_integer():
            return int(obj)
        return obj
    elif isinstance(obj, dict):
        return {k: _normalize_numbers(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_normalize_numbers(v) for v in obj]
    return obj


def canonical_json_dumps(obj: Any) -> bytes:
    """
    Serialize any JSON-encodable dictionary or structure into canonical, deterministic bytes.
    Shared across probe clients, backend ingestion, and Merkle leaf generation.
    """
    normalized = _normalize_numbers(obj)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
