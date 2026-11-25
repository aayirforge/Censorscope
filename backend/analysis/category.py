"""
backend/analysis/category.py
Result category classifier per domain and ISP:
- censorship_suspected: Systematic, reproducible failure matching censorship signatures with control agreement
- security_related: Known threat intelligence match (URLhaus, Google Safe Browsing, PhishTank)
- infrastructure_failure: Both target and control measurements failed, or server errors (5xx/timeouts) without blocking signatures
- inconclusive: Scattered noise (e.g. single isolated failure out of many tests, like nytimes.com) or low volume without strong signal
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional, Sequence


@dataclass
class CategoryResult:
    category: str  # censorship_suspected, security_related, infrastructure_failure, inconclusive
    confidence: float
    reasons: List[str]


class CategoryClassifier:
    """Classifies measurement results into root category."""

    def classify_isp(
        self,
        measurements: Sequence[Any],
        is_threat_intel_flagged: bool = False,
        threat_intel_sources: Optional[List[str]] = None,
    ) -> CategoryResult:
        """
        Classifies telemetry for an ISP:
        - If threat intel flags domain -> security_related
        - If single scattered failure (e.g., 1 anomaly out of >= 3 total, with low anomaly ratio) -> inconclusive
        - If target and control both fail, or generic server/timeout errors -> infrastructure_failure
        - If reproducible anomalies matching censorship signatures -> censorship_suspected
        - Else inconclusive / accessible
        """
        # 1. Threat Intel Check
        if is_threat_intel_flagged:
            sources_str = ", ".join(threat_intel_sources or ["Threat Intel"])
            return CategoryResult(
                category="security_related",
                confidence=0.95,
                reasons=[
                    f"Domain identified in security intelligence feed ({sources_str}). Block may be security protection."
                ],
            )

        total = len(measurements)
        if total == 0:
            return CategoryResult(
                category="inconclusive",
                confidence=0.0,
                reasons=["No measurements available."],
            )

        anomalies = 0
        server_5xx_or_transient = 0
        control_failures = 0
        strong_censorship_signals = 0

        for m in measurements:
            is_anomaly = getattr(m, "anomaly", None)
            if is_anomaly is None and isinstance(m, dict):
                is_anomaly = m.get("anomaly", False)

            if is_anomaly:
                anomalies += 1

            raw = (
                getattr(m, "raw_json", None)
                or (m.get("raw_json") if isinstance(m, dict) else {})
                or {}
            )
            test_keys = raw.get("test_keys") or {}

            # Check control failure
            control = test_keys.get("control") or {}
            control_failure = test_keys.get("control_failure") or control.get("failure")
            if control_failure:
                control_failures += 1

            # Check server transient/5xx errors
            status_code = test_keys.get("response_code") or test_keys.get("status_code")
            if status_code and 500 <= int(status_code) < 600:
                server_5xx_or_transient += 1

            # Check technique labels or strong signals
            labels = getattr(m, "technique_labels", None) or (
                m.get("technique_labels") if isinstance(m, dict) else None
            )
            if labels and any(
                lbl in ("dns_tampering", "http_block_page", "tcp_reset", "tls_sni_filtering")
                for lbl in labels
            ):
                strong_censorship_signals += 1

        anomaly_ratio = anomalies / total

        # If zero anomalies
        if anomalies == 0:
            return CategoryResult(
                category="inconclusive",  # Normal accessible is not censorship/failure
                confidence=0.90,
                reasons=["All measurements observed normal network accessibility."],
            )

        # 2. Single scattered failure rule (e.g. nytimes.com 1 anomaly out of 7)
        # Requirement: "A single scattered failure must lead to inconclusive."
        if anomalies == 1 and total >= 3 and anomaly_ratio <= 0.35:
            return CategoryResult(
                category="inconclusive",
                confidence=0.30,
                reasons=[
                    f"Single isolated anomaly observed ({anomalies}/{total} measurements). "
                    "Scattered anomaly pattern is consistent with transient network noise rather than systematic blocking."
                ],
            )

        # 3. Infrastructure failure rule
        # If control also failed, or transient 5xx server errors dominate the anomalies
        if control_failures > 0 and (control_failures / anomalies) >= 0.50:
            return CategoryResult(
                category="infrastructure_failure",
                confidence=0.85,
                reasons=[
                    f"Control measurements failed alongside target ({control_failures}/{anomalies} anomalies). "
                    "Consistent with upstream transit or hosting provider outage."
                ],
            )

        if server_5xx_or_transient > 0 and (server_5xx_or_transient / anomalies) >= 0.50:
            return CategoryResult(
                category="infrastructure_failure",
                confidence=0.80,
                reasons=["Server responded with HTTP 5xx error or internal failure."],
            )

        # 4. Censorship suspected
        if anomalies >= 2 and (anomaly_ratio >= 0.50 or strong_censorship_signals >= 2):
            return CategoryResult(
                category="censorship_suspected",
                confidence=round(min(0.99, max(0.80, anomaly_ratio)), 2),
                reasons=[
                    f"Reproducible interference pattern ({anomalies}/{total} anomalies, {strong_censorship_signals} with strong tampering signatures).",
                    "Target endpoints failed while control measurements succeeded.",
                ],
            )

        if anomaly_ratio > 0.30:
            return CategoryResult(
                category="censorship_suspected",
                confidence=0.65,
                reasons=[
                    f"Multiple anomalous measurements detected ({anomalies}/{total}), possible network filtering."
                ],
            )

        # Fallback
        return CategoryResult(
            category="inconclusive",
            confidence=0.50,
            reasons=[
                f"Anomaly pattern ({anomalies}/{total}) lacks sufficient reproducibility for definitive categorization."
            ],
        )

    def classify_domain(
        self,
        isp_categories: List[CategoryResult],
        is_threat_intel_flagged: bool = False,
        threat_intel_sources: Optional[List[str]] = None,
    ) -> CategoryResult:
        if is_threat_intel_flagged:
            sources_str = ", ".join(threat_intel_sources or ["Threat Intel"])
            return CategoryResult(
                category="security_related",
                confidence=0.95,
                reasons=[f"Domain flagged in threat intelligence feeds ({sources_str})."],
            )

        censorship_count = sum(1 for c in isp_categories if c.category == "censorship_suspected")
        infra_count = sum(1 for c in isp_categories if c.category == "infrastructure_failure")
        security_count = sum(1 for c in isp_categories if c.category == "security_related")

        if security_count > 0:
            return CategoryResult(
                category="security_related",
                confidence=0.90,
                reasons=["Security-related interference identified on one or more ISPs."],
            )

        if censorship_count > 0:
            return CategoryResult(
                category="censorship_suspected",
                confidence=0.85,
                reasons=[
                    f"Network interference consistent with censorship observed across {censorship_count} ISP network(s)."
                ],
            )

        if infra_count > 0:
            return CategoryResult(
                category="infrastructure_failure",
                confidence=0.80,
                reasons=[
                    f"Infrastructure or upstream connectivity failures observed across {infra_count} ISP network(s)."
                ],
            )

        return CategoryResult(
            category="inconclusive",
            confidence=0.70,
            reasons=[
                "No definitive censorship or infrastructure failure pattern identified across evaluated ISPs."
            ],
        )
