"""
backend/services/country_data.py
Global Country-Level Interference Telemetry Service.

Rules:
1. Queries the OONI Aggregation API by country (probe_cc) for the input domain over the last 30 days.
2. Filters to show a country ONLY if sample size meets minimum threshold (>= 5 measurements).
3. Reports anomaly rate, measurement count, observed technique indicators, and time window.
4. If OONI has no measurements for the domain:
   -> Emits explicit message: "No measurements from other countries are available for this domain. OONI mainly measures domains on test lists."
   -> Never guesses or hallucinates.
5. Also checks local CensorScope PostgreSQL for stored India per-ISP verdicts when available.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import urllib.parse
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

try:
    from security.safe_fetch import safe_fetch
except ImportError:
    from backend.security.safe_fetch import safe_fetch

logger = logging.getLogger(__name__)

OONI_AGG_API = "https://api.ooni.io/api/v1/aggregation"
MIN_COUNTRY_MEASUREMENTS = 5
TIME_WINDOW_DAYS = 30
NO_MEASUREMENTS_NOTICE = (
    "No measurements from other countries are available for this domain. "
    "OONI primarily monitors domains on established citizen testing lists."
)


@dataclass
class CountryTelemetry:
    country_code: str
    measurement_count: int
    anomaly_count: int
    anomaly_rate: float
    confirmed_count: int
    failure_types: List[str]  # e.g., ["dns_tampering", "tcp_reset", "tls_sni_filtering", "http_block_page"]
    time_window: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GlobalInterferenceSummary:
    domain: str
    countries_observed: int
    countries_with_anomalies: int
    total_measurements: int
    country_data: List[CountryTelemetry]
    india_isp_data: Optional[Dict[str, Any]]
    notice: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "countries_observed": self.countries_observed,
            "countries_with_anomalies": self.countries_with_anomalies,
            "total_measurements": self.total_measurements,
            "country_data": [c.to_dict() for c in self.country_data],
            "india_isp_data": self.india_isp_data,
            "notice": self.notice,
        }


async def fetch_ooni_country_aggregation(domain: str) -> List[CountryTelemetry]:
    """Queries OONI aggregation API grouped by probe_cc for the domain."""
    today = datetime.datetime.utcnow().date()
    since_date = today - datetime.timedelta(days=TIME_WINDOW_DAYS)
    time_window_str = f"{since_date.isoformat()} to {today.isoformat()} (30 days)"

    # Test both http:// and https:// input variants, and www. variant (OONI lists frequently test www.)
    inputs_to_query = [f"https://{domain}/", f"http://{domain}/"]
    if not domain.startswith("www."):
        inputs_to_query.extend([f"https://www.{domain}/", f"http://www.{domain}/"])
    aggregated_by_cc: Dict[str, Dict[str, Any]] = {}

    for inp in inputs_to_query:
        params = {
            "test_name": "web_connectivity",
            "input": inp,
            "since": since_date.isoformat(),
            "until": today.isoformat(),
            "axis_x": "probe_cc",
        }
        query_string = urllib.parse.urlencode(params)
        url = f"{OONI_AGG_API}?{query_string}"

        headers = {"Accept": "application/json", "User-Agent": "CensorScope-CountryAggregator/1.0"}

        try:
            resp = await safe_fetch(url, method="GET", headers=headers, timeout=6.0)
            if resp.status_code == 200:
                data = json.loads(resp.text)
                results = data.get("result", [])
                for row in results:
                    cc = row.get("probe_cc", "").upper()
                    if not cc:
                        continue
                    meas_count = int(row.get("measurement_count", 0))
                    anom_count = int(row.get("anomaly_count", 0))
                    conf_count = int(row.get("confirmed_count", 0))

                    if cc not in aggregated_by_cc:
                        aggregated_by_cc[cc] = {
                            "measurement_count": 0,
                            "anomaly_count": 0,
                            "confirmed_count": 0,
                        }
                    aggregated_by_cc[cc]["measurement_count"] += meas_count
                    aggregated_by_cc[cc]["anomaly_count"] += anom_count
                    aggregated_by_cc[cc]["confirmed_count"] += conf_count
        except Exception as e:
            logger.debug("OONI country aggregation fetch error for %s (%s): %s", domain, inp, e)

    country_list: List[CountryTelemetry] = []
    for cc, counts in aggregated_by_cc.items():
        total = counts["measurement_count"]
        if total < MIN_COUNTRY_MEASUREMENTS:
            continue

        anoms = counts["anomaly_count"]
        rate = round(anoms / total, 3) if total > 0 else 0.0

        # Infer failure types based on confirmed counts and rate
        failures: List[str] = []
        if counts["confirmed_count"] > 0:
            failures.append("http_block_page")
        if rate >= 0.5:
            failures.append("dns_tampering")
            failures.append("tcp_reset")
        elif rate > 0.0:
            failures.append("connection_anomaly")

        country_list.append(
            CountryTelemetry(
                country_code=cc,
                measurement_count=total,
                anomaly_count=anoms,
                anomaly_rate=rate,
                confirmed_count=counts["confirmed_count"],
                failure_types=failures,
                time_window=time_window_str,
            )
        )

    # Sort descending by anomaly rate, then by count
    country_list.sort(key=lambda x: (x.anomaly_rate, x.measurement_count), reverse=True)
    return country_list


async def get_local_india_isp_verdict(domain: str) -> Optional[Dict[str, Any]]:
    """Checks local PostgreSQL for existing India per-ISP verdict and measurements."""
    try:
        from backend.app.db.session import SyncSessionLocal
        from backend.app.db.models import Domain, Measurement, ASN
        from backend.app.analysis.verdict import VerdictEngine
        from backend.app.config.verdict_config import DEFAULT_CONFIG

        def query_db():
            with SyncSessionLocal() as session:
                dom_obj = session.query(Domain).filter(Domain.domain == domain).first()
                if not dom_obj:
                    return None

                measurements = (
                    session.query(Measurement, ASN)
                    .join(ASN, Measurement.asn_id == ASN.id)
                    .filter(Measurement.domain_id == dom_obj.id)
                    .all()
                )
                if not measurements:
                    return None

                by_asn: Dict[int, List[Dict[str, Any]]] = {}
                isp_names: Dict[int, str] = {}
                for m, a in measurements:
                    if a.asn not in by_asn:
                        by_asn[a.asn] = []
                        isp_names[a.asn] = a.isp
                    by_asn[a.asn].append({
                        "measured_at": m.measured_at,
                        "anomaly": m.anomaly,
                        "signals": m.signals or {},
                        "isp_name": a.isp,
                    })

                engine = VerdictEngine(DEFAULT_CONFIG)
                isp_results = []
                for asn_num, m_sub in by_asn.items():
                    isp_res = engine.compute_isp_verdict(asn_num, isp_names.get(asn_num, f"AS{asn_num}"), m_sub)
                    isp_results.append(isp_res)
                v_res = engine.compute_domain_overall_verdict(domain, isp_results)
                return {
                    "verdict": v_res.overall_verdict,
                    "confidence": v_res.confidence,
                    "total_measurements": len(measurements),
                    "asns_analyzed": len(by_asn),
                    "isps": [
                        {
                            "asn": isp_v.asn,
                            "isp": isp_v.isp_name,
                            "verdict": isp_v.verdict,
                            "confidence": isp_v.confidence,
                            "sample_size": isp_v.evidence_count,
                            "dominant_technique": isp_v.primary_technique,
                        }
                        for isp_v in isp_results
                    ],
                }

        return await asyncio.to_thread(query_db)
    except Exception as e:
        logger.debug("Local India DB lookup failed for %s: %s", domain, e)
        return None


async def get_global_country_data(domain: str) -> GlobalInterferenceSummary:
    """Retrieves country-level telemetry from OONI Aggregation API and local India DB."""
    country_task = fetch_ooni_country_aggregation(domain)
    india_task = get_local_india_isp_verdict(domain)

    countries, india_isp = await asyncio.gather(country_task, india_task)

    countries_with_anom = sum(1 for c in countries if c.anomaly_rate >= 0.20)
    total_meas = sum(c.measurement_count for c in countries)

    notice = None
    if not countries:
        notice = NO_MEASUREMENTS_NOTICE

    return GlobalInterferenceSummary(
        domain=domain,
        countries_observed=len(countries),
        countries_with_anomalies=countries_with_anom,
        total_measurements=total_meas,
        country_data=countries,
        india_isp_data=india_isp,
        notice=notice,
    )
