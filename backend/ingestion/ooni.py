"""
backend/ingestion/ooni.py
Ingestion worker for OONI web_connectivity measurements in India.
Pulls real measurements incrementally from the OONI API, normalizes domains,
extracts signals, deduplicates records, and populates PostgreSQL.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

PROJECT_BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_BACKEND))

from app.db.base import Base
from app.db.models import ASN, Domain, Measurement, Source
from app.db.session import SyncSessionLocal, sync_engine
from app.utils.domain import normalize_domain

OONI_API_BASE = os.getenv("OONI_API_BASE_URL", "https://api.ooni.io/api/v1")


def load_allowed_domains(file_path: Path) -> Set[str]:
    """Load curated domains from CSV file."""
    allowed = set()
    if not file_path.exists():
        print(f"[!] Warning: Domains file {file_path} not found.")
        return allowed

    with open(file_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_d = row.get("domain", "").strip()
            if raw_d:
                try:
                    norm_d = normalize_domain(raw_d)
                    allowed.add(norm_d)
                except ValueError:
                    pass
    return allowed


def fetch_with_retry(
    url: str,
    max_retries: int = 4,
    initial_backoff: float = 1.0,
    timeout: int = 20,
) -> Dict[str, Any]:
    """Fetch URL with exponential backoff on HTTP 429 or 5xx."""
    headers = {"User-Agent": "CensorScope-Ingestion/1.0 (Research/Civil-Society)"}
    backoff = initial_backoff

    for attempt in range(1, max_retries + 1):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    body = resp.read().decode("utf-8")
                    return json.loads(body)
                raise urllib.error.HTTPError(url, resp.status, "HTTP Error", resp.headers, None)
        except urllib.error.HTTPError as err:
            if err.code in (429, 500, 502, 503, 504) and attempt < max_retries:
                sleep_sec = backoff * (2 ** (attempt - 1))
                print(
                    f"[!] HTTP {err.code} for {url}. Backing off {sleep_sec:.1f}s (attempt {attempt}/{max_retries})..."
                )
                time.sleep(sleep_sec)
            else:
                raise
        except (urllib.error.URLError, TimeoutError) as net_err:
            if attempt < max_retries:
                sleep_sec = backoff * (2 ** (attempt - 1))
                print(f"[!] Network error ({net_err}). Retrying in {sleep_sec:.1f}s...")
                time.sleep(sleep_sec)
            else:
                raise
    raise RuntimeError(f"Failed to fetch {url} after {max_retries} retries")


def parse_signals(raw_item: Dict[str, Any]) -> Dict[str, bool]:
    """Extract granular blocking technique signals from OONI measurement item."""
    test_keys = raw_item.get("test_keys") or {}
    scores = raw_item.get("scores") or {}

    dns_anomaly = (
        test_keys.get("dns_consistency") in ("inconsistent", "failure")
        or scores.get("dns_consistency") in ("inconsistent", "failure")
        or bool(test_keys.get("dns_experiment_failure"))
        or any(fp.get("location_found") == "dns" for fp in scores.get("fingerprints", []))
    )

    tcp_connect = test_keys.get("tcp_connect") or scores.get("tcp_connect")
    tcp_failure = tcp_connect in (
        "failure",
        False,
        "connection_refused_error",
        "tcp_timed_out_error",
    ) or bool(test_keys.get("tcp_experiment_failure"))

    http_failure = bool(
        test_keys.get("http_experiment_failure")
        or test_keys.get("failure")
        or scores.get("http_experiment_failure")
        or (scores.get("analysis", {}).get("blocking_type") == "http-failure")
    )

    tls_failure = bool(
        test_keys.get("tls_handshake_read_status") not in (None, "success")
        or test_keys.get("tls_handshake_write_status") not in (None, "success")
    )

    return {
        "dns": dns_anomaly,
        "tcp": tcp_failure,
        "http": http_failure,
        "tls": tls_failure,
    }


def trim_raw_json(raw_item: Dict[str, Any]) -> Dict[str, Any]:
    """Store only essential analytical fields to preserve storage and avoid bloating."""
    test_keys = raw_item.get("test_keys") or {}
    return {
        "measurement_id": raw_item.get("measurement_uid")
        or raw_item.get("measurement_id")
        or raw_item.get("report_id"),
        "probe_asn": raw_item.get("probe_asn"),
        "probe_cc": raw_item.get("probe_cc", "IN"),
        "measurement_start_time": raw_item.get("measurement_start_time"),
        "scores": raw_item.get("scores"),
        "blocking": test_keys.get("blocking")
        or raw_item.get("scores", {}).get("analysis", {}).get("blocking_type"),
        "dns_consistency": test_keys.get("dns_consistency"),
        "tcp_connect": test_keys.get("tcp_connect"),
        "http_experiment_failure": test_keys.get("http_experiment_failure"),
    }


def process_measurement_items(
    items: List[Dict[str, Any]],
    session: Session,
    source_id: int,
    asn_cache: Dict[int, int],
    domain_cache: Dict[str, int],
    dry_run: bool = False,
) -> int:
    """Process a list of OONI measurement items into the database."""
    inserted = 0

    for item in items:
        raw_input = item.get("input")
        if not raw_input:
            continue

        try:
            norm_d = normalize_domain(raw_input)
        except ValueError:
            continue

        meas_id = item.get("measurement_uid") or item.get("measurement_id") or item.get("report_id")
        if not meas_id:
            continue

        # Check deduplication
        exists = session.execute(
            select(Measurement.id).where(
                Measurement.source_id == source_id,
                Measurement.source_measurement_id == meas_id,
            )
        ).scalar_one_or_none()

        if exists:
            continue

        # Resolve domain
        if norm_d not in domain_cache:
            new_dom = Domain(domain=norm_d)
            session.add(new_dom)
            session.flush()
            domain_cache[norm_d] = new_dom.id
        dom_id = domain_cache[norm_d]

        # Resolve ASN
        raw_asn = str(item.get("probe_asn", "0")).replace("AS", "").strip()
        asn_int = int(raw_asn) if raw_asn.isdigit() else 0
        if asn_int not in asn_cache:
            new_asn = ASN(
                asn=asn_int,
                name=f"AS{asn_int}",
                isp=f"AS{asn_int}",
                organization="Discovered via OONI Telemetry",
                verification_status="needs_verification",
            )
            session.add(new_asn)
            session.flush()
            asn_cache[asn_int] = new_asn.id
        asn_id = asn_cache[asn_int]

        # Parse timestamp
        raw_time = item.get("measurement_start_time")
        try:
            measured_at = (
                datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
                if raw_time
                else datetime.now(timezone.utc)
            )
        except Exception:
            measured_at = datetime.now(timezone.utc)

        anomaly = bool(item.get("anomaly", False))
        signals = parse_signals(item)
        trimmed_json = trim_raw_json(item)

        if not dry_run:
            meas_record = Measurement(
                domain_id=dom_id,
                asn_id=asn_id,
                source_id=source_id,
                source_measurement_id=meas_id,
                test_type="web_connectivity",
                measured_at=measured_at,
                raw_json=trimmed_json,
                anomaly=anomaly,
                signals=signals,
            )
            session.add(meas_record)

        inserted += 1

    if not dry_run:
        session.commit()

    return inserted


def ingest_ooni_measurements(
    session: Session,
    since_date: Optional[str] = None,
    allowed_domains: Optional[Set[str]] = None,
    limit_per_page: int = 50,
    max_pages: int = 10,
    dry_run: bool = False,
) -> Tuple[int, int]:
    """Ingest measurements from OONI API."""
    source = session.execute(select(Source).where(Source.name == "ooni")).scalar_one_or_none()
    if not source:
        source = Source(name="ooni", description="OONI Web Connectivity", url="https://api.ooni.io")
        session.add(source)
        session.commit()

    asn_cache: Dict[int, int] = {
        row.asn: row.id for row in session.execute(select(ASN)).scalars().all()
    }
    domain_cache: Dict[str, int] = {
        row.domain: row.id for row in session.execute(select(Domain)).scalars().all()
    }

    total_processed = 0
    total_inserted = 0

    # Targeted Ingestion per Domain
    if allowed_domains:
        print(f"[*] Starting targeted OONI ingestion for {len(allowed_domains)} curated domains...")
        for idx, dom in enumerate(sorted(allowed_domains), 1):
            dom_items: List[Dict[str, Any]] = []
            variants = [f"https://{dom}/", f"https://www.{dom}/", f"http://{dom}/"]

            for url_variant in variants:
                params = {
                    "probe_cc": "IN",
                    "test_name": "web_connectivity",
                    "input": url_variant,
                    "limit": limit_per_page,
                }
                if since_date:
                    params["since"] = since_date

                query_url = f"{OONI_API_BASE}/measurements?{urllib.parse.urlencode(params)}"
                try:
                    resp_data = fetch_with_retry(query_url, timeout=12)
                    res = resp_data.get("results", [])
                    if res:
                        dom_items.extend(res)
                        break  # Found active measurements for primary variant
                except Exception:
                    pass
                time.sleep(0.15)  # Politeness interval

            total_processed += len(dom_items)
            ins = process_measurement_items(
                dom_items, session, source.id, asn_cache, domain_cache, dry_run=dry_run
            )
            total_inserted += ins
            print(
                f"[{idx}/{len(allowed_domains)}] {dom}: {len(dom_items)} fetched, {ins} inserted into DB."
            )

        print(
            f"[+] Targeted ingestion complete. Total fetched: {total_processed}, Inserted: {total_inserted}."
        )
        return total_processed, total_inserted

    # General Feed Ingestion
    params = {
        "probe_cc": "IN",
        "test_name": "web_connectivity",
        "limit": limit_per_page,
    }
    if since_date:
        params["since"] = since_date

    next_url = f"{OONI_API_BASE}/measurements?{urllib.parse.urlencode(params)}"
    page_count = 0

    while next_url and page_count < max_pages:
        page_count += 1
        print(f"[*] Ingesting general page {page_count}...")
        try:
            resp_data = fetch_with_retry(next_url)
        except Exception as exc:
            print(f"[!] Error fetching page {page_count}: {exc}")
            break

        results = resp_data.get("results", [])
        if not results:
            break

        total_processed += len(results)
        ins = process_measurement_items(
            results, session, source.id, asn_cache, domain_cache, dry_run=dry_run
        )
        total_inserted += ins
        next_url = resp_data.get("metadata", {}).get("next_url")
        time.sleep(0.5)

    print(
        f"[+] General ingestion complete. Evaluated: {total_processed}, Inserted: {total_inserted}."
    )
    return total_processed, total_inserted


def main() -> int:
    parser = argparse.ArgumentParser(description="OONI Web Connectivity Telemetry Ingestion Worker")
    parser.add_argument(
        "--since", default="2026-10-24", help="Fetch measurements starting from date (YYYY-MM-DD)"
    )
    parser.add_argument(
        "--domains-file",
        default="data/test_domains.csv",
        help="Path to CSV containing curated domains to filter ingestion",
    )
    parser.add_argument("--limit", type=int, default=30, help="Measurements per target domain/page")
    parser.add_argument(
        "--max-pages",
        type=int,
        default=5,
        help="Maximum number of pages to pull (for general feed)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Perform checks without saving to DB"
    )

    args = parser.parse_args()

    Base.metadata.create_all(bind=sync_engine)

    allowed = None
    if args.domains_file:
        allowed = load_allowed_domains(Path(args.domains_file))
        print(f"[*] Loaded {len(allowed)} curated filter domains from {args.domains_file}")

    with SyncSessionLocal() as session:
        ingest_ooni_measurements(
            session=session,
            since_date=args.since,
            allowed_domains=allowed,
            limit_per_page=args.limit,
            max_pages=args.max_pages,
            dry_run=args.dry_run,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
