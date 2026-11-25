"""
backend/analysis/explain.py
Unified Explanation Engine for CensorScope Live Domain Check.

Combines:
  A. Registration status (Registered, Appears unregistered, Unknown)
  B. Live reachability from our server (Reachable, DNS/TCP/TLS/HTTP failures, Blockpage)
  C. Country-level OONI telemetry and Indian ISP verdicts

Classifies into principled reason labels:
  - 'not registered / expired / on hold'
  - 'DNS failure not seen elsewhere'
  - 'site down for everyone'
  - 'anomalies concentrated in specific countries or ISPs'
  - 'only our server cannot reach it'
  - 'accessible and healthy'
  - 'cannot determine'

Rules:
- Every statement carries evidence and a confidence level:
  - Confirmed order, Reported, Unknown (legal context only)
  - High, Medium, Low (measurement-based statements)
- Uses cautious, empirical wording: 'measurements are consistent with ...'
- Never names who is responsible without a cited source.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from backend.services.country_data import GlobalInterferenceSummary
from backend.services.reachability import ReachabilityResult
from backend.services.registration import RegistrationResult


@dataclass
class ReasonItem:
    label: str
    confidence: str  # "High", "Medium", "Low", or for legal: "Confirmed order", "Reported", "Unknown"
    description: str
    evidence: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExplanationResult:
    domain: str
    overall_status: str  # "HEALTHY", "DISRUPTED_REGIONALLY", "SITE_DOWN", "UNREGISTERED", "LOCAL_FAILURE_ONLY", "INCONCLUSIVE"
    summary_sentence: str
    reasons: List[ReasonItem]
    limitations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "overall_status": self.overall_status,
            "summary_sentence": self.summary_sentence,
            "reasons": [r.to_dict() for r in self.reasons],
            "limitations": self.limitations,
        }


def explain_domain_status(
    registration: RegistrationResult,
    reachability: ReachabilityResult,
    country_data: GlobalInterferenceSummary,
) -> ExplanationResult:
    """
    Synthesizes registration, live reachability, and country-level OONI data
    into an empirical explanation.
    """
    domain = registration.domain
    reasons: List[ReasonItem] = []
    limitations: List[str] = [
        "Vantage Point Limitation: Live reachability was checked from a single hosting location and does not represent local ISP network conditions in all countries.",
        "Telemetry Coverage: OONI data relies on volunteer test runs; countries without active probes have zero telemetry.",
        "Cautious Interpretation: Technical anomalies are consistent with potential interference or server misconfiguration, but do not prove intentional censorship without corroborating legal documentation.",
    ]

    # Case 1: Unregistered or lifecycle hold
    if registration.status == "APPEARS_UNREGISTERED":
        reasons.append(
            ReasonItem(
                label="not registered / expired / on hold",
                confidence="High",
                description="The domain does not have active DNS nameservers and returned HTTP 404 from the authoritative TLD RDAP registry.",
                evidence=registration.evidence,
            )
        )
        return ExplanationResult(
            domain=domain,
            overall_status="UNREGISTERED",
            summary_sentence=f"Domain {domain} appears to be unregistered or expired based on registry RDAP and DNS checks.",
            reasons=reasons,
            limitations=limitations,
        )

    # Check for RDAP lifecycle holds on registered domain
    has_hold = any(s in registration.rdap_status for s in ["clienthold", "serverhold", "pendingdelete", "redemptionperiod"])
    if has_hold:
        reasons.append(
            ReasonItem(
                label="not registered / expired / on hold",
                confidence="High",
                description="The domain is registered but currently subject to a registry hold or pending deletion status.",
                evidence=f"RDAP statuses: {', '.join(registration.rdap_status)}.",
            )
        )

    # Case 2: Reachable from server and no global anomalies
    if reachability.status == "REACHABLE" and country_data.countries_with_anomalies == 0:
        reasons.append(
            ReasonItem(
                label="accessible and healthy",
                confidence="High" if registration.status == "REGISTERED" else "Medium",
                description="The site responded with standard HTTP status and valid TLS certificate from our server vantage point, with no elevated anomalies reported in OONI telemetry.",
                evidence=reachability.evidence,
            )
        )
        return ExplanationResult(
            domain=domain,
            overall_status="HEALTHY",
            summary_sentence=f"Domain {domain} is accessible from our server vantage point with no widespread interference anomalies observed.",
            reasons=reasons,
            limitations=limitations,
        )

    # Case 3: Block page detected on our server
    if reachability.status == "BLOCK_PAGE":
        reasons.append(
            ReasonItem(
                label="anomalies concentrated in specific countries or ISPs",
                confidence="High",
                description="Live HTTP inspection encountered a verified ISP regulatory blockpage signature.",
                evidence=reachability.evidence,
            )
        )
        return ExplanationResult(
            domain=domain,
            overall_status="DISRUPTED_REGIONALLY",
            summary_sentence=f"Access to {domain} was intercepted by an ISP blockpage from our testing vantage point.",
            reasons=reasons,
            limitations=limitations,
        )

    # Case 4: Non-public IP (SSRF trigger)
    if reachability.status == "NON_PUBLIC_IP":
        reasons.append(
            ReasonItem(
                label="resolves to non-public address",
                confidence="High",
                description="The domain resolved to an RFC-1918, loopback, or link-local IP address and was blocked by outbound security policy.",
                evidence=reachability.evidence,
            )
        )
        return ExplanationResult(
            domain=domain,
            overall_status="LOCAL_FAILURE_ONLY",
            summary_sentence=f"Domain {domain} cannot be reached because it resolves to a private or internal IP address.",
            reasons=reasons,
            limitations=limitations,
        )

    # Case 5: Widespread global anomalies across multiple countries (Site down for everyone)
    if country_data.countries_observed >= 3 and country_data.countries_with_anomalies >= 2:
        anom_countries = [c.country_code for c in country_data.country_data if c.anomaly_rate >= 0.40]
        if reachability.status != "REACHABLE":
            reasons.append(
                ReasonItem(
                    label="site down for everyone",
                    confidence="High" if len(anom_countries) >= 3 else "Medium",
                    description=f"Failures observed from our server, and measurements across multiple countries ({', '.join(anom_countries[:5])}) show high anomaly rates (>40%). Measurements are consistent with widespread service outage or origin server downtime.",
                    evidence=f"Server status: {reachability.status}. Global anomalies: {len(anom_countries)} countries affected out of {country_data.countries_observed} observed.",
                )
            )
            return ExplanationResult(
                domain=domain,
                overall_status="SITE_DOWN",
                summary_sentence=f"Measurements are consistent with a global service outage or server downtime for {domain}.",
                reasons=reasons,
                limitations=limitations,
            )
        else:
            # Server reached it, but high anomalies in specific countries
            reasons.append(
                ReasonItem(
                    label="anomalies concentrated in specific countries or ISPs",
                    confidence="Medium",
                    description=f"Our server reached the site, but elevated anomaly rates (>40%) were observed in {', '.join(anom_countries[:5])}.",
                    evidence=f"Anomalous countries: {', '.join(anom_countries[:5])}. Server reachability: {reachability.status}.",
                )
            )
            return ExplanationResult(
                domain=domain,
                overall_status="DISRUPTED_REGIONALLY",
                summary_sentence=f"Domain {domain} is accessible from our server, but exhibits concentrated anomalies in {len(anom_countries)} countries.",
                reasons=reasons,
                limitations=limitations,
            )

    # Case 6: Concentrated India ISP anomalies from stored DB
    if country_data.india_isp_data:
        india_verdict = country_data.india_isp_data.get("verdict", "")
        if india_verdict in ("Blocked", "Likely blocked", "Blocked on some ISPs"):
            reasons.append(
                ReasonItem(
                    label="anomalies concentrated in specific countries or ISPs",
                    confidence="High" if country_data.india_isp_data.get("confidence", 0) >= 0.8 else "Medium",
                    description=f"Audited multi-probe India telemetry indicates network interference (Verdict: {india_verdict}).",
                    evidence=f"Analyzed {country_data.india_isp_data.get('total_measurements', 0)} measurements across {country_data.india_isp_data.get('asns_analyzed', 0)} ASNs.",
                )
            )
            return ExplanationResult(
                domain=domain,
                overall_status="DISRUPTED_REGIONALLY",
                summary_sentence=f"Telemetry indicates access to {domain} is restricted on major Indian telecommunications providers.",
                reasons=reasons,
                limitations=limitations,
            )

    # Case 7: Single server vantage failure with no corroborating global data
    if reachability.status in ("DNS_FAILURE", "TCP_FAILURE", "TLS_FAILURE", "HTTP_ERROR"):
        if country_data.countries_observed == 0:
            reasons.append(
                ReasonItem(
                    label="only our server cannot reach it",
                    confidence="Low",
                    description=f"Our server encountered a {reachability.failing_layer or 'network'} failure, but zero external OONI country data is available to corroborate whether this is localized or widespread.",
                    evidence=reachability.evidence,
                )
            )
            reasons.append(
                ReasonItem(
                    label="cannot determine",
                    confidence="Low",
                    description="Insufficient independent vantage points available to determine whether the issue is host-specific, transit routing, or censorship.",
                    evidence="No external multi-vantage measurements exist for this domain.",
                )
            )
            return ExplanationResult(
                domain=domain,
                overall_status="INCONCLUSIVE",
                summary_sentence=f"Access to {domain} failed from our server vantage point, but lack of multi-country telemetry prevents determining the root cause.",
                reasons=reasons,
                limitations=limitations,
            )
        elif country_data.countries_with_anomalies == 0:
            # DNS failure not seen elsewhere
            if reachability.status == "DNS_FAILURE":
                reasons.append(
                    ReasonItem(
                        label="DNS failure not seen elsewhere",
                        confidence="Medium",
                        description="DNS resolution failed from our server resolver, while other regions reported successful connectivity.",
                        evidence=reachability.evidence,
                    )
                )
            else:
                reasons.append(
                    ReasonItem(
                        label="only our server cannot reach it",
                        confidence="Medium",
                        description=f"Our server experienced a {reachability.failing_layer} failure, but measurements in other countries show successful connections.",
                        evidence=reachability.evidence,
                    )
                )
            return ExplanationResult(
                domain=domain,
                overall_status="LOCAL_FAILURE_ONLY",
                summary_sentence=f"Domain {domain} failed from our server, but appears accessible in other observed countries.",
                reasons=reasons,
                limitations=limitations,
            )

    # Default fallback: Inconclusive
    reasons.append(
        ReasonItem(
            label="cannot determine",
            confidence="Low",
            description="Available measurements and registry data are insufficient to make a high-confidence determination.",
            evidence=f"Reachability: {reachability.status}, Registration: {registration.status}.",
        )
    )
    return ExplanationResult(
        domain=domain,
        overall_status="INCONCLUSIVE",
        summary_sentence=f"Available telemetry for {domain} is inconclusive.",
        reasons=reasons,
        limitations=limitations,
    )
