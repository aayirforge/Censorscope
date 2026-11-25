"""
backend/app/api/limiter.py
Privacy-preserving client rate limiting.
Ensures fair usage while strictly enforcing zero linkage between client IP
and requested domain names in logs.
"""

from __future__ import annotations

import os
import time

from fastapi import HTTPException, Request, status

# Default rate limit: 60 requests per 60 seconds per IP
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW", "60"))

# Configurable list of trusted reverse proxy IPs (e.g., local ingress, Cloudflare, load balancer)
_raw_trusted = os.getenv("TRUSTED_PROXIES", "127.0.0.1,::1")
TRUSTED_PROXIES: set[str] = {ip.strip() for ip in _raw_trusted.split(",") if ip.strip()}

# In-memory sliding window fallback
_ip_buckets: dict[str, list[float]] = {}


def get_client_ip(request: Request) -> str:
    """
    Extract client IP securely.
    Only honor X-Forwarded-For if the direct TCP peer is in TRUSTED_PROXIES.
    Otherwise, strictly return the direct socket IP to prevent header spoofing bypasses.
    When behind a trusted proxy, take the client IP immediately preceding the trusted hop(s).
    """
    socket_ip = request.client.host if (request.client and request.client.host) else "unknown"

    # If the direct TCP peer is NOT a trusted proxy, ignore all forwarding headers
    if socket_ip not in TRUSTED_PROXIES:
        return socket_ip

    # Peer is a trusted proxy: parse X-Forwarded-For
    xff = request.headers.get("x-forwarded-for")
    if xff:
        # X-Forwarded-For: client, proxy1, proxy2
        hops = [h.strip() for h in xff.split(",") if h.strip()]
        # Walk backwards from right to left to find the first untrusted IP
        for hop in reversed(hops):
            if hop not in TRUSTED_PROXIES:
                return hop
        # If all hops are trusted, return the earliest hop
        if hops:
            return hops[0]

    return socket_ip


def check_rate_limit(request: Request) -> None:
    """
    Enforce sliding-window rate limit strictly on client IP.
    The domain being searched is intentionally omitted here to prevent correlation.
    """
    client_ip = get_client_ip(request)
    now = time.time()

    # Clean up expired timestamps
    timestamps = _ip_buckets.setdefault(client_ip, [])
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    _ip_buckets[client_ip] = [ts for ts in timestamps if ts > cutoff]

    if len(_ip_buckets[client_ip]) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again shortly.",
            headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
        )

    _ip_buckets[client_ip].append(now)
