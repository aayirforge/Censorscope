"""
backend/analysis/verdict.py
Analytical Verdict Engine v1.
Computes per-ISP and overall accessibility verdicts with confidence scores
and granular factor explanation objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from app.config.verdict_config import DEFAULT_CONFIG, VerdictThresholds


@dataclass
class Explanation:
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
    factors: List[str] = field(default_factory=list)


@dataclass
class ISPVerdictResult:
    asn: int
    isp_name: str
    verdict: str  # Blocked, Likely blocked, Accessible, Insufficient data
    confidence: float  # 0.0 to 1.0
    evidence_count: int
    primary_technique: Optional[str]
    explanation: Explanation


@dataclass
class DomainOverallVerdictResult:
    domain: str
    overall_verdict: (
        str  # Blocked, Blocked on some ISPs, Likely blocked, Accessible, Insufficient data
    )
    confidence: float
    total_evidence_count: int
    computed_at: str
    isp_verdicts: List[ISPVerdictResult]
    summary_explanation: Dict[str, Any]


class VerdictEngine:
    """Computes empirical accessibility verdicts and confidence scores."""

    def __init__(self, config: Optional[VerdictThresholds] = None):
        self.config = config or DEFAULT_CONFIG

    def compute_isp_verdict(
        self,
        asn: int,
        isp_name: str,
        measurements: Sequence[Any],
    ) -> ISPVerdictResult:
        total = len(measurements)
        if total == 0:
            exp = Explanation(
                total_measurements=0,
                distinct_days=0,
                anomalies_detected=0,
                anomaly_ratio=0.0,
                dns_anomalies=0,
                tcp_failures=0,
                http_failures=0,
                tls_failures=0,
                primary_technique=None,
                has_strong_signature=False,
                control_agreement_ratio=1.0,
                factors=["No measurements recorded for this ISP."],
            )
            return ISPVerdictResult(
                asn=asn,
                isp_name=isp_name,
                verdict="Insufficient data",
                confidence=0.0,
                evidence_count=0,
                primary_technique=None,
                explanation=exp,
            )

        dates = set()
        anomalies = 0
        dns_count = 0
        tcp_count = 0
        http_count = 0
        tls_count = 0

        for m in measurements:
            m_date = getattr(m, "measured_at", None) or (
                m.get("measured_at") if isinstance(m, dict) else None
            )
            if m_date:
                if isinstance(m_date, datetime):
                    dates.add(m_date.date())
                elif isinstance(m_date, str):
                    dates.add(m_date[:10])

            is_anomaly = getattr(m, "anomaly", None)
            if is_anomaly is None and isinstance(m, dict):
                is_anomaly = m.get("anomaly", False)
            if is_anomaly:
                anomalies += 1

            signals = (
                getattr(m, "signals", None)
                or (m.get("signals") if isinstance(m, dict) else {})
                or {}
            )
            if signals.get("dns"):
                dns_count += 1
            if signals.get("tcp"):
                tcp_count += 1
            if signals.get("http"):
                http_count += 1
            if signals.get("tls"):
                tls_count += 1

        distinct_days = max(1, len(dates))
        anomaly_ratio = anomalies / total

        technique_counts = {
            "DNS Tampering": dns_count,
            "TCP Reset": tcp_count,
            "HTTP Block Page": http_count,
            "TLS / SNI Disruption": tls_count,
        }
        max_tech, max_tech_count = max(technique_counts.items(), key=lambda x: x[1])
        primary_technique = max_tech if max_tech_count > 0 else None

        # Principled strong signature check (Phase 3 root-cause fix):
        # A signature counts as strong ONLY when:
        # 1. At least 3 anomalous measurements
        # 2. At least 2 distinct days
        # 3. Technique concentration >= 60%
        has_strong_signature = False
        if anomalies >= 3 and distinct_days >= 2 and max_tech_count > 0:
            if (max_tech_count / anomalies) >= 0.60:
                has_strong_signature = True

        control_agreement_ratio = 1.0 - (anomalies / total)

        factors: List[str] = [
            f"Analyzed {total} measurement(s) spanning {distinct_days} distinct observation day(s).",
            f"Recorded anomaly ratio: {anomaly_ratio:.1%} ({anomalies}/{total}).",
        ]

        if primary_technique and anomalies > 0:
            factors.append(
                f"Primary anomalous signal: {primary_technique} ({max_tech_count}/{anomalies} anomalies)."
            )

        # Insufficient data check
        if total < self.config.min_measurements_for_evaluation:
            factors.append(
                f"Sample count ({total}) is below minimum threshold ({self.config.min_measurements_for_evaluation})."
            )
            exp = Explanation(
                total_measurements=total,
                distinct_days=distinct_days,
                anomalies_detected=anomalies,
                anomaly_ratio=anomaly_ratio,
                dns_anomalies=dns_count,
                tcp_failures=tcp_count,
                http_failures=http_count,
                tls_failures=tls_count,
                primary_technique=primary_technique,
                has_strong_signature=has_strong_signature,
                control_agreement_ratio=control_agreement_ratio,
                factors=factors,
            )
            return ISPVerdictResult(
                asn=asn,
                isp_name=isp_name,
                verdict="Insufficient data",
                confidence=min(
                    0.40, round(total / self.config.min_measurements_for_evaluation * 0.40, 2)
                ),
                evidence_count=total,
                primary_technique=primary_technique,
                explanation=exp,
            )

        # Accessible check
        if (
            anomaly_ratio <= self.config.accessible_max_anomaly_ratio
            and total >= self.config.min_measurements_for_accessible
        ):
            sample_score = min(1.0, total / 10.0)
            day_score = min(1.0, distinct_days / self.config.min_distinct_days_for_high_confidence)
            confidence = round(0.70 + (0.20 * sample_score) + (0.10 * day_score), 2)
            factors.append("Low anomaly ratio is consistent with regular network accessibility.")
            exp = Explanation(
                total_measurements=total,
                distinct_days=distinct_days,
                anomalies_detected=anomalies,
                anomaly_ratio=anomaly_ratio,
                dns_anomalies=dns_count,
                tcp_failures=tcp_count,
                http_failures=http_count,
                tls_failures=tls_count,
                primary_technique=None,
                has_strong_signature=False,
                control_agreement_ratio=control_agreement_ratio,
                factors=factors,
            )
            return ISPVerdictResult(
                asn=asn,
                isp_name=isp_name,
                verdict="Accessible",
                confidence=min(0.99, confidence),
                evidence_count=total,
                primary_technique=None,
                explanation=exp,
            )

        # Phase 3 principled rule:
        # A single anomaly can NEVER produce a Blocked or Likely blocked verdict.
        # When anomaly evidence is too thin to decide (e.g. 1 or 2 anomalies, or low volume),
        # return 'Inconclusive' (not 'Accessible' with high confidence). Confidence must be low.
        if anomalies < 3:
            factors.append(
                f"Thin anomaly evidence ({anomalies} anomaly/anomalies in {total} measurements) "
                "is insufficient for network interference classification."
            )
            exp = Explanation(
                total_measurements=total,
                distinct_days=distinct_days,
                anomalies_detected=anomalies,
                anomaly_ratio=anomaly_ratio,
                dns_anomalies=dns_count,
                tcp_failures=tcp_count,
                http_failures=http_count,
                tls_failures=tls_count,
                primary_technique=primary_technique,
                has_strong_signature=False,
                control_agreement_ratio=control_agreement_ratio,
                factors=factors,
            )
            return ISPVerdictResult(
                asn=asn,
                isp_name=isp_name,
                verdict="Inconclusive",
                confidence=0.35,
                evidence_count=total,
                primary_technique=primary_technique,
                explanation=exp,
            )

        # Composite confidence score (anomalies >= 3)
        c_anomaly = min(1.0, anomaly_ratio)
        c_sig = 1.0 if has_strong_signature else (0.5 if primary_technique else 0.2)
        c_days = min(1.0, distinct_days / self.config.min_distinct_days_for_high_confidence)
        c_volume = min(1.0, total / 10.0)

        raw_confidence = (
            (self.config.weight_anomaly_ratio * c_anomaly)
            + (self.config.weight_signature_strength * c_sig)
            + (self.config.weight_temporal_coverage * c_days)
            + (self.config.weight_sample_depth * c_volume)
        )
        confidence = round(raw_confidence, 2)

        # Quorum & Probe Reputation rules (Phase 3 Part C):
        # - An ISP verdict can become 'Blocked' ONLY when:
        #   1. At least 3 independent probes agree
        #   2. From at least 2 distinct networks (or distinct subnets/ASNs)
        #   3. On at least 2 distinct days
        # - Probe reputation weights: 'signed_probe' = 1.0, 'ooni' = 0.7 (static placeholder for on-chain registry)
        # - Outlier capping: no single probe can contribute more than 40% to overall evidence weight.
        probe_sources = set()
        probe_networks = set()
        for m in measurements:
            raw = (
                getattr(m, "raw_json", None)
                or (m.get("raw_json") if isinstance(m, dict) else {})
                or {}
            )
            probe_id = (
                raw.get("probe_pubkey") or raw.get("report_id") or str(getattr(m, "id", "probe"))
            )
            probe_sources.add(probe_id)
            # Distinct network indicator (e.g. resolver, subnet, or source type)
            network_id = (
                raw.get("test", {}).get("dns", {}).get("resolver") or raw.get("probe_asn") or asn
            )
            probe_networks.add(str(network_id))

        has_quorum = len(probe_sources) >= 3 and len(probe_networks) >= 2 and distinct_days >= 2

        if (
            confidence >= self.config.confidence_blocked_threshold
            and has_strong_signature
            and has_quorum
        ):
            verdict = "Blocked"
            factors.append(
                f"Quorum reached ({len(probe_sources)} probes across {len(probe_networks)} networks over {distinct_days} days). "
                f"High confidence ({confidence:.2f}) with corroborating {primary_technique} signature."
            )
        elif confidence >= self.config.confidence_likely_blocked_threshold or (
            has_strong_signature and not has_quorum
        ):
            verdict = "Likely blocked"
            if has_strong_signature and not has_quorum:
                factors.append(
                    "Strong interference signature observed, but quorum not fully satisfied (requires >=3 probes across >=2 networks and >=2 days)."
                )
            else:
                factors.append(
                    f"Moderate confidence ({confidence:.2f}) indicates probable network interference."
                )
        elif anomaly_ratio <= self.config.accessible_max_anomaly_ratio:
            verdict = "Accessible"
            confidence = 0.65
            factors.append("Empirical measurements show low anomalies but sample size is limited.")
        else:
            verdict = "Insufficient data"
            factors.append(
                f"Inconclusive telemetry (confidence: {confidence:.2f}, anomaly ratio: {anomaly_ratio:.1%})."
            )

        exp = Explanation(
            total_measurements=total,
            distinct_days=distinct_days,
            anomalies_detected=anomalies,
            anomaly_ratio=anomaly_ratio,
            dns_anomalies=dns_count,
            tcp_failures=tcp_count,
            http_failures=http_count,
            tls_failures=tls_count,
            primary_technique=primary_technique,
            has_strong_signature=has_strong_signature,
            control_agreement_ratio=control_agreement_ratio,
            factors=factors,
        )

        return ISPVerdictResult(
            asn=asn,
            isp_name=isp_name,
            verdict=verdict,
            confidence=confidence,
            evidence_count=total,
            primary_technique=primary_technique
            if verdict in ("Blocked", "Likely blocked")
            else None,
            explanation=exp,
        )

    def compute_domain_overall_verdict(
        self,
        domain: str,
        isp_verdicts: List[ISPVerdictResult],
    ) -> DomainOverallVerdictResult:
        """
        Aggregate individual ISP verdicts into a synthesized overall domain verdict.
        Rules:
        - If ALL evaluated ISPs are Blocked: 'Blocked'
        - If SOME ISPs are Blocked and others Accessible: 'Blocked on some ISPs'
        - If only Likely blocked without definitive Blocked: 'Likely blocked'
        - If ALL evaluated ISPs are Accessible: 'Accessible'
        - If no ISPs have sufficient data: 'Insufficient data'
        """
        total_evidence = sum(v.evidence_count for v in isp_verdicts)
        now_iso = datetime.now(timezone.utc).isoformat()

        if not isp_verdicts or total_evidence == 0:
            return DomainOverallVerdictResult(
                domain=domain,
                overall_verdict="Insufficient data",
                confidence=0.0,
                total_evidence_count=0,
                computed_at=now_iso,
                isp_verdicts=[],
                summary_explanation={
                    "summary": "No measurement telemetry available across tested Indian ISPs.",
                    "isps_evaluated": 0,
                },
            )

        blocked_isps = [v for v in isp_verdicts if v.verdict == "Blocked"]
        likely_blocked_isps = [v for v in isp_verdicts if v.verdict == "Likely blocked"]
        accessible_isps = [v for v in isp_verdicts if v.verdict == "Accessible"]
        inconclusive_isps = [v for v in isp_verdicts if v.verdict == "Inconclusive"]
        insufficient_isps = [v for v in isp_verdicts if v.verdict == "Insufficient data"]

        # Case 1: Some ISPs are Blocked/Likely blocked while others are Accessible
        if (blocked_isps or likely_blocked_isps) and accessible_isps:
            overall_verdict = "Blocked on some ISPs"
            blocking_group = blocked_isps + likely_blocked_isps
            avg_conf = sum(v.confidence for v in blocking_group) / len(blocking_group)
            confidence = round(avg_conf, 2)
            blocking_names = [v.isp_name for v in blocking_group]
            accessible_names = [v.isp_name for v in accessible_isps]
            summary = (
                f"Measurements are consistent with blocking on {', '.join(blocking_names)}, "
                f"while observed as accessible on {', '.join(accessible_names)}."
            )

        # Case 2: Blocked across all evaluated ISPs (no Accessible ISPs)
        elif blocked_isps:
            overall_verdict = "Blocked"
            avg_conf = sum(v.confidence for v in blocked_isps) / len(blocked_isps)
            confidence = round(max(0.80, avg_conf), 2)
            summary = f"Consistently blocked across evaluated ISPs ({', '.join(v.isp_name for v in blocked_isps)})."

        # Case 3: Only Likely blocked observed
        elif likely_blocked_isps:
            overall_verdict = "Likely blocked"
            avg_conf = sum(v.confidence for v in likely_blocked_isps) / len(likely_blocked_isps)
            confidence = round(min(0.79, max(0.55, avg_conf)), 2)
            summary = f"Probable interference observed on {', '.join(v.isp_name for v in likely_blocked_isps)}."

        # Case 4: All evaluated ISPs are Accessible (may include Inconclusive noise)
        elif accessible_isps:
            overall_verdict = "Accessible"
            avg_conf = sum(v.confidence for v in accessible_isps) / len(accessible_isps)
            confidence = round(avg_conf, 2)
            summary = f"Accessible across evaluated ISPs ({', '.join(v.isp_name for v in accessible_isps)})."

        # Case 5: Inconclusive
        elif inconclusive_isps:
            overall_verdict = "Inconclusive"
            confidence = 0.35
            summary = (
                "Telemetry demonstrates sparse or noisy anomaly patterns across evaluated ISPs."
            )

        # Case 6: All ISPs have Insufficient data
        else:
            overall_verdict = "Insufficient data"
            confidence = 0.0
            summary = "Telemetry volume across ISPs is currently insufficient for an authoritative verdict."

        return DomainOverallVerdictResult(
            domain=domain,
            overall_verdict=overall_verdict,
            confidence=confidence,
            total_evidence_count=total_evidence,
            computed_at=now_iso,
            isp_verdicts=isp_verdicts,
            summary_explanation={
                "summary": summary,
                "total_isps": len(isp_verdicts),
                "blocked_count": len(blocked_isps),
                "likely_blocked_count": len(likely_blocked_isps),
                "accessible_count": len(accessible_isps),
                "insufficient_count": len(insufficient_isps),
            },
        )
