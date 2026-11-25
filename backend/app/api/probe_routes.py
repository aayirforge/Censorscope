"""
backend/app/api/probe_routes.py
Server-side report ingestion endpoint for CensorScope signed probe clients.
Verifies:
1. Ed25519 cryptographic signature over RFC 8785 canonical JSON
2. Timestamp window validation (+/- 10 minutes from current UTC)
3. Nonce uniqueness (anti-replay check via Redis / memory cache)
4. Known / authorized probe public keys registry
5. Payload size cap (<= 64 KB)
6. Normalized schema validation
Stores verified reports in the measurements table with source = 'signed_probe'.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Set

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
import redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ASN, Domain, Measurement, Source
from app.db.session import get_db
from app.utils.domain import normalize_domain
from utils.canonical import canonical_json_dumps

logger = logging.getLogger(__name__)

probe_router = APIRouter(prefix="/api/v1")

TIMESTAMP_WINDOW_SECONDS = 600  # 10 minutes
MAX_REPORT_SIZE_BYTES = 65536  # 64 KB
NONCE_KEY_PREFIX = "censorscope:probe_nonce:"

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
_redis_client: Optional[redis.Redis] = None


def get_redis_client() -> redis.Redis:
    """Returns connected Redis client or raises ConnectionError."""
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis.from_url(
            REDIS_URL, socket_timeout=1.0, socket_connect_timeout=1.0
        )
    # Ping to ensure it is alive; must fail closed if unavailable
    _redis_client.ping()
    return _redis_client


# Known authorized probe public keys registry (static in-memory / config; placeholder for on-chain registry)
# Probes created by default for testing or volunteer keys
AUTHORIZED_PROBES: Set[str] = set()

# In-memory fallback ONLY used in unit test environments when explicitly configured
ALLOW_TEST_MEMORY_NONCE: bool = False
SEEN_NONCES: Set[str] = set()


def register_authorized_probe(pubkey_hex: str) -> None:
    AUTHORIZED_PROBES.add(pubkey_hex.lower().strip())


class TestPayload(BaseModel):
    dns: Dict[str, Any] = Field(default_factory=dict)
    tcp: Dict[str, Any] = Field(default_factory=dict)
    tls: Dict[str, Any] = Field(default_factory=dict)
    http: Dict[str, Any] = Field(default_factory=dict)


class ResultPayload(BaseModel):
    anomaly: bool
    technique_labels: List[str] = Field(default_factory=list)
    signals: Dict[str, bool] = Field(default_factory=dict)


class SignedReportRequest(BaseModel):
    domain: str
    asn: int
    country: str = "IN"
    test: TestPayload
    result: ResultPayload
    control: Dict[str, Any] = Field(default_factory=dict)
    probe_pubkey: str
    nonce: str
    timestamp: int
    software_version: str
    signature: str



@probe_router.post("/reports", status_code=status.HTTP_201_CREATED)
async def submit_signed_report(
    report: SignedReportRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest cryptographically signed measurement telemetry from an authorized probe node.
    """
    # 1. Enforce payload size limit (defend against memory exhaustion)
    raw_body = await request.body()
    if len(raw_body) > MAX_REPORT_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Report size exceeds maximum limit of {MAX_REPORT_SIZE_BYTES} bytes.",
        )

    # 2. Check Timestamp Window (+/- 10 minutes)
    now = int(time.time())
    if abs(now - report.timestamp) > TIMESTAMP_WINDOW_SECONDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Timestamp expired or in future (skew: {abs(now - report.timestamp)}s > {TIMESTAMP_WINDOW_SECONDS}s).",
        )

    # 3. Check Replayed Nonce (Fail-closed on Redis unavailability)
    if ALLOW_TEST_MEMORY_NONCE:
        if report.nonce in SEEN_NONCES:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Replay attack detected: nonce '{report.nonce}' has already been processed.",
            )
    else:
        try:
            r = get_redis_client()
            nonce_key = f"{NONCE_KEY_PREFIX}{report.nonce}"
            # Atomically set nonce with TTL equal to 2x timestamp window (20 mins)
            # SET NX returns True if key was set, None/False if key already exists
            is_new = r.set(nonce_key, "1", nx=True, ex=TIMESTAMP_WINDOW_SECONDS * 2)
            if not is_new:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Replay attack detected: nonce '{report.nonce}' has already been processed.",
                )
        except HTTPException:
            raise
        except Exception as exc:
            logger.error(f"Nonce store failure (Redis unavailable): {exc}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Nonce store unavailable. Reports rejected to prevent replay attacks.",
            )

    # 4. Check Authorized Probe Key
    probe_key_hex = report.probe_pubkey.lower().strip()
    if AUTHORIZED_PROBES and probe_key_hex not in AUTHORIZED_PROBES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized probe public key. Key not registered in probe authority list.",
        )

    # 5. Verify Ed25519 Cryptographic Signature
    try:
        pubkey_bytes = bytes.fromhex(probe_key_hex)
        verify_key = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        signature_bytes = bytes.fromhex(report.signature)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed cryptographic key or signature hex: {exc}",
        )

    # Reconstruct canonical payload without the signature field
    payload_dict = report.model_dump()
    payload_dict.pop("signature", None)
    canonical_bytes = canonical_json_dumps(payload_dict)

    try:
        verify_key.verify(signature_bytes, canonical_bytes)
    except InvalidSignature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Cryptographic verification failed: invalid signature for measurement payload.",
        )

    # Record seen nonce if memory mode enabled
    if ALLOW_TEST_MEMORY_NONCE:
        SEEN_NONCES.add(report.nonce)

    # 6. Normalize Domain & Persist into Database with source = 'signed_probe'
    norm_domain = normalize_domain(report.domain)

    # Find or create Domain
    dom_q = await db.execute(select(Domain).where(Domain.domain == norm_domain))
    dom_rec = dom_q.scalar_one_or_none()
    if not dom_rec:
        dom_rec = Domain(domain=norm_domain, category="general")
        db.add(dom_rec)
        await db.flush()

    # Find or create ASN
    asn_q = await db.execute(select(ASN).where(ASN.asn == report.asn))
    asn_rec = asn_q.scalar_one_or_none()
    if not asn_rec:
        asn_rec = ASN(asn=report.asn, isp=f"AS{report.asn}")
        db.add(asn_rec)
        await db.flush()

    # Find or create Source
    src_q = await db.execute(select(Source).where(Source.name == "signed_probe"))
    src_rec = src_q.scalar_one_or_none()
    if not src_rec:
        src_rec = Source(
            name="signed_probe",
            description="Cryptographically signed telemetry from authorized volunteer probes",
            url="https://censorscope.org/probes",
        )
        db.add(src_rec)
        await db.flush()

    # Store measurement
    measurement_id = f"signed_{report.nonce}"
    meas_rec = Measurement(
        domain_id=dom_rec.id,
        asn_id=asn_rec.id,
        source_id=src_rec.id,
        source_measurement_id=measurement_id,
        test_type="signed_probe_connectivity",
        measured_at=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(report.timestamp)),
        raw_json=payload_dict,
        anomaly=report.result.anomaly,
        signals=report.result.signals,
        technique_labels=report.result.technique_labels,
    )
    db.add(meas_rec)
    await db.commit()

    return {
        "status": "accepted",
        "measurement_id": measurement_id,
        "source": "signed_probe",
        "verified": True,
    }
