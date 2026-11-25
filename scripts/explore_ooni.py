#!/usr/bin/env python3
"""
scripts/explore_ooni.py
Explore OONI web_connectivity measurements for India (IN).
Extracts and displays key blocking technique detection fields:
- domain (input)
- probe_asn
- anomaly
- dns_consistency
- tcp_connect
- http_failure
- blocking (or scores/verdict)
Saves sample measurement data to data/samples/ooni_sample.json.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

OONI_API_BASE = "https://api.ooni.io/api/v1"
SAMPLE_OUTPUT_PATH = Path(__file__).resolve().parent.parent / "data" / "samples" / "ooni_sample.json"


def fetch_ooni_measurements(
    probe_cc: str = "IN",
    test_name: str = "web_connectivity",
    limit: int = 5,
    timeout: int = 15,
) -> Dict[str, Any]:
    """Fetch measurement list from the public OONI API."""
    params = urllib.parse.urlencode({
        "probe_cc": probe_cc,
        "test_name": test_name,
        "limit": limit,
    })
    url = f"{OONI_API_BASE}/measurements?{params}"
    headers = {"User-Agent": "CensorScope-Explorer/1.0 (Research)"}
    req = urllib.request.Request(url, headers=headers)
    
    with urllib.request.urlopen(req, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"OONI API returned HTTP {response.status}")
        raw_body = response.read().decode("utf-8")
        return json.loads(raw_body)


def fetch_measurement_detail(measurement_url: str, timeout: int = 15) -> Optional[Dict[str, Any]]:
    """Fetch full measurement detail if available."""
    try:
        req = urllib.request.Request(
            measurement_url,
            headers={"User-Agent": "CensorScope-Explorer/1.0 (Research)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except Exception:
        pass
    return None


def extract_technique_fields(item: Dict[str, Any], detail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Extract the specific fields relevant to detecting blocking techniques."""
    scores = item.get("scores") or {}
    test_keys = item.get("test_keys") or {}
    
    if detail and "test_keys" in detail:
        test_keys = detail.get("test_keys") or test_keys

    # Extract technique indicators
    domain = item.get("input") or item.get("measurement_meta", {}).get("input") or "N/A"
    asn = item.get("probe_asn") or "N/A"
    anomaly = item.get("anomaly", False)
    
    # DNS consistency
    dns_consistency = (
        test_keys.get("dns_consistency")
        or scores.get("dns_consistency")
        or test_keys.get("dns_experiment_failure")
        or "consistent" if not anomaly else "unknown"
    )
    
    # TCP connect
    tcp_connect = (
        test_keys.get("tcp_connect")
        or scores.get("tcp_connect")
        or ("failure" if test_keys.get("tcp_experiment_failure") else "successful")
    )
    
    # HTTP failure
    http_failure = (
        test_keys.get("http_experiment_failure")
        or test_keys.get("failure")
        or scores.get("http_experiment_failure")
        or None
    )
    
    # Blocking determination
    blocking = (
        test_keys.get("blocking")
        or scores.get("analysis", {}).get("blocking_type")
        or ("dns" if dns_consistency in ("inconsistent", "failure") else None)
        or ("tcp" if tcp_connect in ("failure", False) else None)
        or ("http" if http_failure else None)
        or ("none" if not anomaly else "likely_blocked")
    )

    return {
        "domain": domain,
        "probe_asn": asn,
        "anomaly": anomaly,
        "dns_consistency": dns_consistency,
        "tcp_connect": tcp_connect,
        "http_failure": http_failure,
        "blocking": blocking,
        "measurement_id": item.get("measurement_id"),
        "measurement_start_time": item.get("measurement_start_time"),
    }


def generate_fallback_sample() -> Dict[str, Any]:
    """Generate representative sample data if offline or in restricted sandbox."""
    return {
        "metadata": {
            "source": "OONI Web Connectivity Synthesized Indian Telemetry",
            "probe_cc": "IN",
            "note": "Representative sample illustrating blocking technique signatures",
        },
        "results": [
            {
                "domain": "https://example-blocked-news.org",
                "probe_asn": "AS55836",
                "anomaly": True,
                "dns_consistency": "inconsistent",
                "tcp_connect": "successful",
                "http_failure": None,
                "blocking": "dns",
                "measurement_id": "ooni-sample-in-001",
                "measurement_start_time": "2026-03-01T10:00:00Z",
            },
            {
                "domain": "https://example-blocked-forum.net",
                "probe_asn": "AS45609",
                "anomaly": True,
                "dns_consistency": "consistent",
                "tcp_connect": "connection_refused_error",
                "http_failure": None,
                "blocking": "tcp_reset",
                "measurement_id": "ooni-sample-in-002",
                "measurement_start_time": "2026-03-01T10:05:00Z",
            },
            {
                "domain": "https://example-gov-redirect.org",
                "probe_asn": "AS9829",
                "anomaly": True,
                "dns_consistency": "consistent",
                "tcp_connect": "successful",
                "http_failure": "http_diff_failure",
                "blocking": "http-diff",
                "measurement_id": "ooni-sample-in-003",
                "measurement_start_time": "2026-03-01T10:10:00Z",
            },
            {
                "domain": "https://wikipedia.org",
                "probe_asn": "AS55836",
                "anomaly": False,
                "dns_consistency": "consistent",
                "tcp_connect": "successful",
                "http_failure": None,
                "blocking": "none",
                "measurement_id": "ooni-sample-in-004",
                "measurement_start_time": "2026-03-01T10:15:00Z",
            },
        ],
    }


def main() -> int:
    print("=================================================================")
    print(" CensorScope - OONI Telemetry Exploration for India (probe_cc=IN)")
    print("=================================================================\n")

    sample_data: Dict[str, Any] = {}
    extracted_records: List[Dict[str, Any]] = []

    try:
        print("[*] Contacting OONI API (probe_cc=IN, test_name=web_connectivity)...")
        raw_resp = fetch_ooni_measurements(probe_cc="IN", limit=5)
        raw_results = raw_resp.get("results", [])
        print(f"[+] Retrieved {len(raw_results)} measurement entries from OONI.\n")

        for item in raw_results:
            meas_url = item.get("measurement_url")
            detail = fetch_measurement_detail(meas_url) if meas_url else None
            record = extract_technique_fields(item, detail)
            extracted_records.append(record)

        sample_data = {
            "metadata": {
                "source": "OONI API Live Query",
                "probe_cc": "IN",
                "count": len(extracted_records),
            },
            "results": extracted_records,
            "raw_sample": raw_results,
        }

    except Exception as exc:
        print(f"[!] Live query failed ({exc}). Using representative OONI sample for offline verification.")
        fallback = generate_fallback_sample()
        sample_data = fallback
        extracted_records = fallback["results"]

    # Print table of important fields
    header_fmt = "{:<32} {:<10} {:<9} {:<16} {:<16} {:<15} {:<12}"
    row_fmt = "{:<32} {:<10} {:<9} {:<16} {:<16} {:<15} {:<12}"

    print(header_fmt.format("DOMAIN", "ASN", "ANOMALY", "DNS_CONSISTENCY", "TCP_CONNECT", "HTTP_FAILURE", "BLOCKING"))
    print("-" * 115)
    for r in extracted_records:
        domain_str = (r["domain"][:29] + "...") if len(r["domain"]) > 32 else r["domain"]
        dns_str = str(r["dns_consistency"])[:15]
        tcp_str = str(r["tcp_connect"])[:15]
        http_str = str(r["http_failure"] or "-")[:14]
        blocking_str = str(r["blocking"] or "none")[:11]

        print(row_fmt.format(
            domain_str,
            str(r["probe_asn"]),
            str(r["anomaly"]),
            dns_str,
            tcp_str,
            http_str,
            blocking_str,
        ))

    # Persist sample JSON
    SAMPLE_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(SAMPLE_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(sample_data, f, indent=2)

    print(f"\n[+] Saved sample JSON to: {SAMPLE_OUTPUT_PATH}")
    print("[+] Technique field exploration complete.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
