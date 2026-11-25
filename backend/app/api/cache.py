"""
backend/app/api/cache.py
Caching layer for domain verdicts with Redis and in-memory fallback.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any, Tuple

import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "300"))
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
CACHE_HMAC_SECRET = os.getenv("CACHE_HMAC_SECRET", "")

if ENVIRONMENT == "production":
    if not CACHE_HMAC_SECRET or len(CACHE_HMAC_SECRET) < 32:
        raise RuntimeError(
            "CACHE_HMAC_SECRET environment variable must be set and at least 32 characters in production mode."
        )

# Fallback secret for local development/testing if unset
_EFFECTIVE_SECRET = CACHE_HMAC_SECRET.encode("utf-8") if CACHE_HMAC_SECRET else b"censorscope_default_dev_hmac_secret_32b!"

# Redis client with fast timeout
_redis_client: redis.Redis | None = None
try:
    _redis_client = redis.Redis.from_url(REDIS_URL, socket_timeout=1.0, socket_connect_timeout=1.0)
    # Test connection
    _redis_client.ping()
except Exception:
    _redis_client = None

# In-memory LRU-like fallback dictionary
_memory_cache: dict[str, Tuple[float, Any]] = {}


def _domain_cache_key(domain: str) -> str:
    """
    Hash domain in cache keys using HMAC-SHA256 keyed with a server secret.
    Prevents plaintext leakage in Redis dumps AND prevents external adversaries
    from pre-computing or guessing cache keys without the secret key.
    """
    norm_domain = domain.strip().lower().encode("utf-8")
    mac = hmac.new(_EFFECTIVE_SECRET, norm_domain, hashlib.sha256).hexdigest()
    return f"censorscope:domain_h:{mac}"


def get_hmac_cache_key(raw_key: str) -> str:
    """Public helper to compute HMAC-SHA256 cache key using the effective secret."""
    norm = raw_key.strip().lower().encode("utf-8")
    return hmac.new(_EFFECTIVE_SECRET, norm, hashlib.sha256).hexdigest()


def get_cached_verdict(domain: str) -> dict[str, Any] | None:
    """Retrieve cached domain verdict."""
    key = _domain_cache_key(domain)
    if _redis_client:
        try:
            cached_bytes = _redis_client.get(key)
            if cached_bytes:
                return json.loads(cached_bytes.decode("utf-8"))
        except Exception:
            pass

    # Check in-memory fallback
    import time

    if key in _memory_cache:
        expire_at, data = _memory_cache[key]
        if time.time() < expire_at:
            return data
        del _memory_cache[key]
    return None


def set_cached_verdict(domain: str, data: dict[str, Any], ttl: int = CACHE_TTL_SECONDS) -> None:
    """Store domain verdict in cache."""
    key = _domain_cache_key(domain)
    serialized = json.dumps(data)

    if _redis_client:
        try:
            _redis_client.setex(key, ttl, serialized)
            return
        except Exception:
            pass

    import time

    _memory_cache[key] = (time.time() + ttl, data)
