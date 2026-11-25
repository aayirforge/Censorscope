"""
backend/app/db/seed.py
Seeds baseline data:
1. Sources (OONI, Citizen Lab, Censored Planet, URLhaus)
2. ASNs from data/isp_asn_mapping.csv
3. Domains from data/test_domains.csv
"""

from __future__ import annotations

import csv
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import Base
from app.db.models import ASN, Domain, Source
from app.db.session import SyncSessionLocal, sync_engine

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
ISP_CSV_PATH = PROJECT_ROOT / "data" / "isp_asn_mapping.csv"
DOMAINS_CSV_PATH = PROJECT_ROOT / "data" / "test_domains.csv"


def seed_sources(session: Session) -> None:
    sources_data = [
        {
            "name": "ooni",
            "description": "Open Observatory of Network Interference - Web Connectivity measurements",
            "url": "https://api.ooni.io",
        },
        {
            "name": "citizenlab",
            "description": "Citizen Lab Global and Country-Specific Test Lists",
            "url": "https://github.com/citizenlab/test-lists",
        },
        {
            "name": "censored_planet",
            "description": "Censored Planet Observatory - Remote Vantage Point Telemetry",
            "url": "https://censoredplanet.org",
        },
        {
            "name": "urlhaus",
            "description": "abuse.ch URLhaus malware and security intelligence feed",
            "url": "https://urlhaus.abuse.ch",
        },
    ]

    for item in sources_data:
        existing = session.execute(
            select(Source).where(Source.name == item["name"])
        ).scalar_one_or_none()
        if not existing:
            source = Source(name=item["name"], description=item["description"], url=item["url"])
            session.add(source)
    session.commit()
    print("[+] Sources seeded successfully.")


def seed_asns(session: Session) -> None:
    if not ISP_CSV_PATH.exists():
        print(f"[!] Warning: {ISP_CSV_PATH} not found, skipping ASN seeding.")
        return

    with open(ISP_CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            asn_val = int(row["asn"].strip().replace("AS", ""))
            isp_name = row["isp"].strip()
            org_name = row["organization"].strip()
            v_status = row.get("verification_status", "verified").strip()

            existing = session.execute(select(ASN).where(ASN.asn == asn_val)).scalar_one_or_none()
            if not existing:
                asn_obj = ASN(
                    asn=asn_val,
                    name=org_name,
                    isp=isp_name,
                    organization=org_name,
                    verification_status=v_status,
                )
                session.add(asn_obj)
            else:
                existing.isp = isp_name
                existing.organization = org_name
                existing.verification_status = v_status
    session.commit()
    print("[+] ASNs seeded successfully from data/isp_asn_mapping.csv.")


def seed_domains(session: Session) -> None:
    if not DOMAINS_CSV_PATH.exists():
        print(f"[!] Warning: {DOMAINS_CSV_PATH} not found, skipping domain seeding.")
        return

    with open(DOMAINS_CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain_name = row["domain"].strip().lower()
            category = row.get("category", "").strip() or None
            expected_status = row.get("expected_status", "unknown").strip()

            existing = session.execute(
                select(Domain).where(Domain.domain == domain_name)
            ).scalar_one_or_none()
            if not existing:
                domain_obj = Domain(
                    domain=domain_name,
                    category=category,
                    expected_status=expected_status,
                )
                session.add(domain_obj)
            else:
                existing.category = category
                existing.expected_status = expected_status
    session.commit()
    print("[+] Domains seeded successfully from data/test_domains.csv.")


def run_seed() -> None:
    # Ensure tables exist
    Base.metadata.create_all(bind=sync_engine)
    with SyncSessionLocal() as session:
        seed_sources(session)
        seed_asns(session)
        seed_domains(session)


if __name__ == "__main__":
    run_seed()
