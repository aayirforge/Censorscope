"""
backend/app/main.py
FastAPI application entrypoint for CensorScope.
"""

import sys
from pathlib import Path

# Ensure backend directory and project root are in sys.path
_backend_dir = str(Path(__file__).resolve().parent.parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)
_root_dir = str(Path(__file__).resolve().parent.parent.parent)
if _root_dir not in sys.path:
    sys.path.insert(0, _root_dir)

import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.check_routes import router as check_router
from app.api.probe_routes import probe_router
from app.api.routes import router as api_router

app = FastAPI(
    title="CensorScope API",
    description="Empirical domain accessibility and censorship intelligence telemetry API",
    version="0.1.0",
)

# CORS configuration: allow local development and LAN testing on any dev port
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept"],
)


@app.middleware("http")
async def security_and_privacy_headers_middleware(request: Request, call_next):
    """
    1. Privacy-first HTTP logging: Zero-linkage policy. Never record requested domain with client IP.
    2. Comprehensive security headers:
       - Content-Security-Policy (CSP)
       - Strict-Transport-Security (HSTS)
       - X-Content-Type-Options: nosniff
       - X-Frame-Options: DENY
       - Referrer-Policy: strict-origin-when-cross-origin
       - Permissions-Policy: camera=(), microphone=(), geolocation=()
    """
    start_time = time.time()
    response = await call_next(request)
    _duration = time.time() - start_time

    # Redact path for domain searches to preserve query privacy
    path = request.url.path
    if path.startswith("/api/v1/domain/") or path.startswith("/api/v1/domains/"):
        path = "/api/v1/domain/[REDACTED_FOR_PRIVACY]"
    elif path.startswith("/api/v1/check"):
        path = "/api/v1/check/[REDACTED_FOR_PRIVACY]"

    # Attach hardened security headers
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; object-src 'none';"
    )
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"

    return response


# Include API routes
app.include_router(api_router)
app.include_router(probe_router)
app.include_router(check_router)


@app.get("/health")
async def health_check():
    """Health check endpoint returning service status."""
    return {"status": "ok", "service": "censorscope-backend"}
