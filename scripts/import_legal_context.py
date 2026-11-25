"""
scripts/import_legal_context.py
Imports legal context and statutory reason records from CSV into PostgreSQL.
Validates confidence labels against: Confirmed order, Reported, Unknown.
Uses parameterized queries to prevent SQL injection.
"""

from __future__ import annotations

import argparse
import csv
import sys
from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.db.models import Domain, LegalContext
from app.db.session import sync_engine
from app.utils.domain import normalize_domain

VALID_CONFIDENCES = {"Confirmed order", "Reported", "Unknown"}


def import_legal_context(csv_path: Path) -> int:
    if not csv_path.exists():
        print(f"Error: {csv_path} does not exist.")
        return 0

    imported_count = 0
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        with Session(sync_engine) as session:
            for row in reader:
                raw_domain = row.get("domain", "").strip()
                summary = row.get("summary", "").strip()
                source_url = row.get("source_url", "").strip() or None
                source_type = row.get("source_type", "").strip() or None
                confidence = row.get("confidence", "Unknown").strip()
                pub_date_str = row.get("published_at", "").strip()

                if not raw_domain or not summary:
                    continue

                if confidence not in VALID_CONFIDENCES:
                    confidence = "Unknown"

                published_at = None
                if pub_date_str:
                    try:
                        published_at = datetime.fromisoformat(pub_date_str)
                    except Exception:
                        pass

                try:
                    norm_domain = normalize_domain(raw_domain)
                except Exception:
                    continue

                # Query or create domain
                dom = session.execute(select(Domain).where(Domain.domain == norm_domain)).scalar_one_or_none()
                if not dom:
                    dom = Domain(domain=norm_domain, category="general")
                    session.add(dom)
                    session.flush()

                # Check if legal context already exists for domain
                existing = session.execute(
                    select(LegalContext).where(LegalContext.domain_id == dom.id)
                ).scalars().first()

                if existing:
                    existing.summary = summary
                    existing.source_url = source_url
                    existing.source_type = source_type
                    existing.confidence = confidence
                    existing.published_at = published_at
                else:
                    new_ctx = LegalContext(
                        domain_id=dom.id,
                        summary=summary,
                        source_url=source_url,
                        source_type=source_type,
                        confidence=confidence,
                        published_at=published_at,
                    )
                    session.add(new_ctx)

                imported_count += 1

            session.commit()

    print(f"Successfully imported/updated {imported_count} legal context records.")
    return imported_count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Import legal context records from CSV")
    parser.add_argument(
        "--file",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "data" / "legal_context.csv",
        help="Path to legal context CSV",
    )
    args = parser.parse_args()
    import_legal_context(args.file)
