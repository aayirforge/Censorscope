"""
backend/app/api/routes.py
API endpoints for CensorScope (Phase 2).
Provides:
- Domain accessibility verdicts & confidence scores
- Technique labels & evidence mappings per ISP
- Root cause category (censorship_suspected, security_related, infrastructure_failure, inconclusive)
- Verified legal / statutory context with confidence labels
- Global view for domains accessible in India
- Top 5 related news articles (title, source, date, link only)
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from analysis.category import CategoryClassifier
from analysis.global_view import GlobalViewAggregator
from app.analysis.verdict import VerdictEngine
from app.api.cache import get_cached_verdict, set_cached_verdict
from app.api.limiter import check_rate_limit
from app.db.models import ASN, Domain, LegalContext, Measurement, Batch, MeasurementProof
from app.db.session import get_db
from app.services.articles import ArticleService
from app.services.threat_intel import ThreatIntelService
from app.utils.domain import normalize_domain

router = APIRouter(prefix="/api/v1")
verdict_engine = VerdictEngine()
category_classifier = CategoryClassifier()
threat_intel_service = ThreatIntelService()
article_service = ArticleService()
global_view_aggregator = GlobalViewAggregator()


class TimelineBucket(BaseModel):
    date: str
    total: int
    anomalies: int
    accessible: int


class ExplanationModel(BaseModel):
    total_measurements: int
    distinct_days: int
    anomalies_detected: int
    anomaly_ratio: float
    dns_anomalies: int
    tcp_failures: int
    http_failures: int
    tls_failures: int
    primary_technique: Optional[str]
    has_strong_signature: bool
    control_agreement_ratio: float
    factors: List[str]


class ISPVerdictModel(BaseModel):
    asn: int
    isp_name: str
    country_code: str = "IN"
    country_name: str = "India"
    verdict: str
    category: str
    confidence: float
    evidence_count: int
    primary_technique: Optional[str]
    technique_labels: List[str]
    explanation: ExplanationModel


class LegalContextModel(BaseModel):
    summary: str
    source_url: Optional[str]
    source_type: Optional[str]
    confidence: str  # Confirmed order, Reported, Unknown
    published_at: Optional[str]


class GlobalCountryModel(BaseModel):
    country_code: str
    country_name: str
    total_measurements: int
    anomaly_count: int
    anomaly_rate: float
    cautious_status: str


class ArticleModel(BaseModel):
    title: str
    source: str
    date: str
    link: str


class DomainVerdictResponse(BaseModel):
    domain: str
    overall_verdict: str
    category: str
    confidence: float
    evidence_count: int
    last_updated: str
    disclaimer: str
    legal_context: Optional[LegalContextModel]
    global_view: List[GlobalCountryModel]
    articles: List[ArticleModel]
    timeline: List[TimelineBucket]
    isp_verdicts: List[ISPVerdictModel]
    summary_explanation: dict[str, Any]


@router.get("/domain/{domain:path}", response_model=DomainVerdictResponse)
async def get_domain_verdict(
    domain: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _rate_limit: None = Depends(check_rate_limit),
):
    """
    Retrieve empirical accessibility telemetry, technique classification,
    category diagnosis, legal context, global view, and news for a domain.
    """
    # 1. Domain normalization
    try:
        norm_domain = normalize_domain(domain)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain syntax: {val_err}",
        )

    # 2. Check cache
    cached = get_cached_verdict(norm_domain)
    if cached:
        return cached

    # 3. Check Threat Intelligence (works even if zero OONI data)
    threat_intel = await threat_intel_service.check_domain(norm_domain)

    # 4. Query Legal Context
    legal_res = await db.execute(
        select(LegalContext)
        .join(Domain)
        .where(Domain.domain == norm_domain)
        .order_by(LegalContext.created_at.desc())
    )
    legal_record = legal_res.scalars().all()
    legal_record = legal_record[0] if legal_record else None
    legal_context_data = None
    if legal_record:
        legal_context_data = {
            "summary": legal_record.summary,
            "source_url": legal_record.source_url,
            "source_type": legal_record.source_type,
            "confidence": legal_record.confidence,
            "published_at": legal_record.published_at.isoformat()
            if legal_record.published_at
            else None,
        }

    # 5. Query domain and measurements
    query_dom = await db.execute(select(Domain).where(Domain.domain == norm_domain))
    dom_record = query_dom.scalar_one_or_none()

    # Query articles in background
    articles_task = article_service.get_articles_for_domain(norm_domain)

    if not dom_record:
        articles = await articles_task
        default_cat = "security_related" if threat_intel.is_flagged else "inconclusive"
        response_payload = {
            "domain": norm_domain,
            "overall_verdict": "Insufficient data",
            "category": default_cat,
            "confidence": 0.0,
            "evidence_count": 0,
            "last_updated": datetime.utcnow().isoformat(),
            "disclaimer": "Measurements are consistent with lack of recorded telemetry in curated repository. Observations do not constitute legal determinations.",
            "legal_context": legal_context_data,
            "global_view": [],
            "articles": [a.__dict__ for a in articles],
            "timeline": [],
            "isp_verdicts": [],
            "summary_explanation": {
                "summary": "No measurement data available for this domain in the curated test repository.",
                "total_isps": 0,
            },
        }
        set_cached_verdict(norm_domain, response_payload, ttl=120)
        return response_payload

    query_meas = await db.execute(
        select(Measurement)
        .options(selectinload(Measurement.asn_rel))
        .where(Measurement.domain_id == dom_record.id)
        .order_by(Measurement.measured_at.asc())
    )
    measurements = query_meas.scalars().all()

    if not measurements:
        articles = await articles_task
        default_cat = "security_related" if threat_intel.is_flagged else "inconclusive"
        response_payload = {
            "domain": norm_domain,
            "overall_verdict": "Insufficient data",
            "category": default_cat,
            "confidence": 0.0,
            "evidence_count": 0,
            "last_updated": dom_record.updated_at.isoformat()
            if dom_record.updated_at
            else datetime.utcnow().isoformat(),
            "disclaimer": "No empirical measurements have been collected yet for this domain.",
            "legal_context": legal_context_data,
            "global_view": [],
            "articles": [a.__dict__ for a in articles],
            "timeline": [],
            "isp_verdicts": [],
            "summary_explanation": {
                "summary": "No measurement records found for this domain.",
                "total_isps": 0,
            },
        }
        set_cached_verdict(norm_domain, response_payload, ttl=120)
        return response_payload

    # 6. Group measurements by ASN and compute per-ISP verdicts & techniques
    meas_by_asn: dict[int, list[Measurement]] = defaultdict(list)
    asn_names: dict[int, str] = {}
    for m in measurements:
        meas_by_asn[m.asn_id].append(m)
        if m.asn_rel:
            asn_names[m.asn_id] = m.asn_rel.isp or f"AS{m.asn_rel.asn}"

    missing_asn_ids = set(meas_by_asn.keys()) - set(asn_names.keys())
    if missing_asn_ids:
        query_asns = await db.execute(select(ASN).where(ASN.id.in_(missing_asn_ids)))
        for a in query_asns.scalars().all():
            asn_names[a.id] = a.isp or f"AS{a.asn}"

    isp_results = []
    isp_category_results = []
    isp_verdicts_payload = []

    for a_id, m_list in meas_by_asn.items():
        isp_name = asn_names.get(a_id, f"ISP-{a_id}")
        asn_num = m_list[0].asn_rel.asn if (m_list and m_list[0].asn_rel) else a_id
        res = verdict_engine.compute_isp_verdict(asn_num, isp_name, m_list)
        isp_results.append(res)

        # Categorization for ISP
        cat_res = category_classifier.classify_isp(
            m_list,
            is_threat_intel_flagged=threat_intel.is_flagged,
            threat_intel_sources=threat_intel.sources,
        )
        isp_category_results.append(cat_res)

        # Aggregate technique labels
        tech_set = set()
        for m in m_list:
            if m.technique_labels:
                tech_set.update(m.technique_labels)
        # Filter out unknown if specific labels exist
        if len(tech_set) > 1 and "unknown" in tech_set:
            tech_set.remove("unknown")

        # If single scattered noise, suppress false positive blocking
        verdict_str = res.verdict
        if cat_res.category == "inconclusive" and verdict_str in ("Blocked", "Likely blocked"):
            verdict_str = "Insufficient data"
            res.confidence = min(0.40, res.confidence)

        isp_verdicts_payload.append(
            {
                "asn": res.asn,
                "isp_name": res.isp_name,
                "country_code": "IN",
                "country_name": "India",
                "verdict": verdict_str,
                "category": cat_res.category,
                "confidence": res.confidence,
                "evidence_count": res.evidence_count,
                "primary_technique": res.primary_technique,
                "technique_labels": sorted(list(tech_set)),
                "explanation": {
                    "total_measurements": res.explanation.total_measurements,
                    "distinct_days": res.explanation.distinct_days,
                    "anomalies_detected": res.explanation.anomalies_detected,
                    "anomaly_ratio": round(res.explanation.anomaly_ratio, 4),
                    "dns_anomalies": res.explanation.dns_anomalies,
                    "tcp_failures": res.explanation.tcp_failures,
                    "http_failures": res.explanation.http_failures,
                    "tls_failures": res.explanation.tls_failures,
                    "primary_technique": res.explanation.primary_technique,
                    "has_strong_signature": res.explanation.has_strong_signature,
                    "control_agreement_ratio": round(res.explanation.control_agreement_ratio, 4),
                    "factors": res.explanation.factors,
                },
            }
        )

    # Overall Domain Category & Verdict
    overall_res = verdict_engine.compute_domain_overall_verdict(norm_domain, isp_results)
    domain_cat = category_classifier.classify_domain(
        isp_category_results,
        is_threat_intel_flagged=threat_intel.is_flagged,
        threat_intel_sources=threat_intel.sources,
    )

    # 7. Check Global View if Accessible in India
    global_telemetry = []
    if overall_res.overall_verdict == "Accessible":
        global_telemetry = await global_view_aggregator.get_global_status(norm_domain)

    articles = await articles_task

    # 8. Timeline
    daily_stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "anomalies": 0, "accessible": 0}
    )
    for m in measurements:
        day_str = (
            m.measured_at.strftime("%Y-%m-%d")
            if isinstance(m.measured_at, datetime)
            else str(m.measured_at)[:10]
        )
        daily_stats[day_str]["total"] += 1
        if m.anomaly:
            daily_stats[day_str]["anomalies"] += 1
        else:
            daily_stats[day_str]["accessible"] += 1

    timeline_buckets = [
        TimelineBucket(
            date=d,
            total=v["total"],
            anomalies=v["anomalies"],
            accessible=v["accessible"],
        )
        for d, v in sorted(daily_stats.items())
    ]

    latest_time = max((m.measured_at for m in measurements), default=datetime.utcnow())

    response_payload = {
        "domain": norm_domain,
        "overall_verdict": overall_res.overall_verdict,
        "category": domain_cat.category,
        "confidence": overall_res.confidence,
        "evidence_count": overall_res.total_evidence_count,
        "last_updated": latest_time.isoformat()
        if isinstance(latest_time, datetime)
        else str(latest_time),
        "disclaimer": (
            "Empirical observations reflect measured network responses and do not constitute legal determinations. "
            "Findings are reported with confidence labels based strictly on technical telemetry."
        ),
        "legal_context": legal_context_data,
        "global_view": [g.__dict__ for g in global_telemetry],
        "articles": [a.__dict__ for a in articles],
        "timeline": [b.model_dump() for b in timeline_buckets],
        "isp_verdicts": isp_verdicts_payload,
        "summary_explanation": overall_res.summary_explanation,
    }

    set_cached_verdict(norm_domain, response_payload)
    return response_payload


@router.get("/evidence/{measurement_id}")
async def get_measurement_evidence(
    measurement_id: int,
    db: AsyncSession = Depends(get_db),
    _rate_limit: None = Depends(check_rate_limit),
):
    """
    Retrieve cryptographic Merkle evidence for an anchored measurement.
    Strictly validates measurement_id (positive integer).
    Returns:
    - leaf_fields (canonical payload dictionary)
    - leaf_hash (double-keccak256 hash)
    - proof (array of 32-byte hex sibling hashes)
    - batch_id (onchain batch id)
    - root (merkle root)
    - cid (IPFS or mock storage identifier)
    - tx_hash (anchoring transaction hash)
    - block_number
    - chain_id
    - contract_address
    - is_mock_storage
    """
    if measurement_id <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid measurement ID. ID must be a strictly positive integer.",
        )

    # Query proof
    stmt = (
        select(MeasurementProof, Batch)
        .join(Batch, MeasurementProof.batch_id == Batch.id)
        .where(MeasurementProof.measurement_id == measurement_id)
    )
    res = await db.execute(stmt)
    row = res.first()

    if not row:
        # Check if measurement exists but not yet anchored
        m_stmt = select(Measurement.id).where(Measurement.id == measurement_id)
        m_res = await db.execute(m_stmt)
        if m_res.scalar_one_or_none():
            return {
                "status": "Not yet anchored",
                "measurement_id": measurement_id,
                "message": "Measurement exists in database but has not yet been included in an anchored batch.",
            }
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Measurement {measurement_id} not found.",
        )

    proof_rec, batch_rec = row
    return {
        "status": "Anchored",
        "measurement_id": measurement_id,
        "batch_id": batch_rec.onchain_batch_id if batch_rec.onchain_batch_id is not None else batch_rec.id,
        "merkle_root": batch_rec.merkle_root,
        "ipfs_cid": batch_rec.ipfs_cid,
        "leaf_hash": proof_rec.leaf_hash,
        "leaf_fields": proof_rec.leaf_data_json,
        "proof": proof_rec.proof,
        "tx_hash": batch_rec.tx_hash,
        "block_number": batch_rec.block_number,
        "chain_id": batch_rec.chain_id,
        "contract_address": batch_rec.contract_address,
        "is_mock_storage": batch_rec.is_mock_storage,
        "anchoring_explainer": (
            "Anchoring proves that our stored copy of a record has not changed since the batch was published. "
            "It does not prove the measurement was true, and for OONI data it does not prove OONI said it; "
            "it proves what we stored from OONI at the time."
        ),
    }

