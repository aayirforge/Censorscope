"""
backend/analysis/global_view.py
Global censorship telemetry aggregator for domains accessible in India.
Queries OONI aggregation API to discover whether domains are flagged with anomalies
in other jurisdictions.
Filters out countries with sample count below minimum threshold (default: 5).
Formats results with cautious wording ('measurements consistent with blocking').
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List

import httpx

logger = logging.getLogger(__name__)

MIN_SAMPLE_THRESHOLD = 5


@dataclass
class CountryTelemetry:
    country_code: str
    country_name: str
    total_measurements: int
    anomaly_count: int
    anomaly_rate: float
    cautious_status: str


class GlobalViewAggregator:
    """Aggregates multi-country telemetry from OONI."""

    def __init__(self, min_sample: int = MIN_SAMPLE_THRESHOLD):
        self.min_sample = min_sample

    async def get_global_status(self, domain: str) -> List[CountryTelemetry]:
        """
        Fetch country-level aggregation for domain from OONI API.
        Excludes India ('IN') to present external jurisdictions.
        """
        results: List[CountryTelemetry] = []
        # Query OONI aggregation API: https://api.ooni.io/api/v1/aggregation
        # Parameters: input=https://{domain}/ or domain
        url = "https://api.ooni.io/api/v1/aggregation"
        params = {
            "input": f"https://{domain}/",
            "axis_x": "probe_cc",
        }

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(url, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    raw_results = data.get("result", [])
                    for item in raw_results:
                        cc = (item.get("probe_cc") or "").upper()
                        if not cc or cc == "IN":
                            continue

                        total = item.get("measurement_count", 0)
                        anomalies = item.get("anomaly_count", 0)

                        # Filter out countries with low sample depth
                        if total < self.min_sample:
                            continue

                        rate = anomalies / total if total > 0 else 0.0

                        if rate >= 0.50 and anomalies >= 3:
                            status_desc = "Measurements consistent with blocking"
                        elif rate >= 0.20:
                            status_desc = "Measurements show intermittent anomalies"
                        else:
                            status_desc = "Measurements consistent with accessibility"

                        results.append(
                            CountryTelemetry(
                                country_code=cc,
                                country_name=cc,  # Country code
                                total_measurements=total,
                                anomaly_count=anomalies,
                                anomaly_rate=round(rate, 3),
                                cautious_status=status_desc,
                            )
                        )
        except Exception as e:
            logger.warning(f"Global OONI aggregation lookup failed for {domain}: {e}")

        # Sort descending by anomaly rate and total measurements
        results.sort(key=lambda x: (x.anomaly_rate, x.total_measurements), reverse=True)
        return results
