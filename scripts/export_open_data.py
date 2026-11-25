"""
scripts/export_open_data.py
Exports CensorScope measurement records and evidence batches to standardized JSONL / CSV formats
for open scientific research, offline analysis, and archive mirror hosting.
"""

import asyncio
import csv
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add backend directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.db.session import AsyncSessionLocal
from app.db.models import Measurement, Domain, ASN, Batch
from sqlalchemy import select
from sqlalchemy.orm import selectinload


async def export_open_data(output_dir: str = "data/open_data"):
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    today_str = datetime.utcnow().strftime("%Y-%m-%d")

    jsonl_file = out_path / f"censorscope_measurements_{today_str}.jsonl"
    csv_file = out_path / f"censorscope_measurements_{today_str}.csv"
    batches_file = out_path / f"censorscope_batches_{today_str}.json"

    print(f"[*] Starting open data export to {out_path}...")

    async with AsyncSessionLocal() as session:
        # 1. Export measurements
        stmt = (
            select(Measurement)
            .options(selectinload(Measurement.domain), selectinload(Measurement.asn_rel))
            .order_by(Measurement.id.asc())
        )
        result = await session.execute(stmt)
        measurements = result.scalars().all()

        print(f"[*] Exporting {len(measurements)} measurements to JSONL and CSV...")

        with open(jsonl_file, "w", encoding="utf-8") as f_jsonl, open(
            csv_file, "w", newline="", encoding="utf-8"
        ) as f_csv:
            csv_writer = csv.writer(f_csv)
            csv_writer.writerow([
                "id",
                "domain",
                "asn",
                "isp",
                "anomaly",
                "technique",
                "measured_at",
            ])

            for m in measurements:
                domain_name = m.domain.domain if m.domain else ""
                asn_num = m.asn_rel.asn if m.asn_rel else 0
                isp_name = m.asn_rel.isp if m.asn_rel else ""
                tech = (m.technique_labels[0] if m.technique_labels else "unknown") if m.anomaly else "none"

                # Write JSONL record
                rec = {
                    "id": m.id,
                    "domain": domain_name,
                    "asn": asn_num,
                    "isp": isp_name,
                    "anomaly": m.anomaly,
                    "technique": tech,
                    "measured_at": m.measured_at.isoformat() if m.measured_at else None,
                    "signals": m.signals,
                }
                f_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")

                # Write CSV record
                csv_writer.writerow([
                    m.id,
                    domain_name,
                    asn_num,
                    isp_name,
                    m.anomaly,
                    tech,
                    m.measured_at.isoformat() if m.measured_at else "",
                ])

        # 2. Export evidence batches
        stmt_batches = select(Batch).order_by(Batch.id.asc())
        b_res = await session.execute(stmt_batches)
        batches = b_res.scalars().all()

        batches_data = [
            {
                "id": b.id,
                "onchain_batch_id": b.onchain_batch_id,
                "merkle_root": b.merkle_root,
                "ipfs_cid": b.ipfs_cid,
                "record_count": b.record_count,
                "from_timestamp": b.from_timestamp.isoformat() if b.from_timestamp else None,
                "to_timestamp": b.to_timestamp.isoformat() if b.to_timestamp else None,
                "tx_hash": b.tx_hash,
                "block_number": b.block_number,
                "chain_id": b.chain_id,
                "contract_address": b.contract_address,
                "is_mock_storage": b.is_mock_storage,
                "created_at": b.created_at.isoformat() if b.created_at else None,
            }
            for b in batches
        ]

        with open(batches_file, "w", encoding="utf-8") as f_batch:
            json.dump(batches_data, f_batch, indent=2)

    print(f"[+] Open data export complete:")
    print(f"    - JSONL: {jsonl_file}")
    print(f"    - CSV:   {csv_file}")
    print(f"    - Batches: {batches_file}")


if __name__ == "__main__":
    asyncio.run(export_open_data())
