"""0001_initial_schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-24 10:35:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Domains table
    op.create_table(
        "domains",
        sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=True),
        sa.Column("expected_status", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_domains_id", "domains", ["id"])
    op.create_index("ix_domains_domain", "domains", ["domain"], unique=True)
    op.create_index("ix_domains_category", "domains", ["category"])

    # 2. ASNs table
    op.create_table(
        "asns",
        sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
        sa.Column("asn", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("isp", sa.String(length=128), nullable=False),
        sa.Column("organization", sa.String(length=255), nullable=True),
        sa.Column(
            "verification_status", sa.String(length=32), nullable=False, server_default="verified"
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_asns_id", "asns", ["id"])
    op.create_index("ix_asns_asn", "asns", ["asn"], unique=True)
    op.create_index("ix_asns_isp", "asns", ["isp"])

    # 3. Sources table
    op.create_table(
        "sources",
        sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("url", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_sources_id", "sources", ["id"])
    op.create_index("ix_sources_name", "sources", ["name"], unique=True)

    # 4. Measurements table
    op.create_table(
        "measurements",
        sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("asn_id", sa.Integer(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=True),
        sa.Column("source_measurement_id", sa.String(length=255), nullable=False),
        sa.Column(
            "test_type", sa.String(length=64), nullable=False, server_default="web_connectivity"
        ),
        sa.Column("measured_at", sa.DateTime(), nullable=False),
        sa.Column("raw_json", sa.JSON(), nullable=False),
        sa.Column("anomaly", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("signals", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asn_id"], ["asns.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_id"], ["sources.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("source_id", "source_measurement_id", name="uq_source_measurement_id"),
    )
    op.create_index("ix_measurements_id", "measurements", ["id"])
    op.create_index("ix_measurements_domain_id", "measurements", ["domain_id"])
    op.create_index("ix_measurements_asn_id", "measurements", ["asn_id"])
    op.create_index("ix_measurements_source_id", "measurements", ["source_id"])
    op.create_index(
        "ix_measurements_source_measurement_id", "measurements", ["source_measurement_id"]
    )
    op.create_index("ix_measurements_measured_at", "measurements", ["measured_at"])
    op.create_index("ix_measurements_anomaly", "measurements", ["anomaly"])
    op.create_index(
        "ix_measurements_domain_asn_time", "measurements", ["domain_id", "asn_id", "measured_at"]
    )
    op.create_index("ix_measurements_domain_time", "measurements", ["domain_id", "measured_at"])

    # 5. Verdicts table
    op.create_table(
        "verdicts",
        sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("asn_id", sa.Integer(), nullable=True),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("explanation_json", sa.JSON(), nullable=False),
        sa.Column("computed_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("evidence_count", sa.Integer(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asn_id"], ["asns.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_verdicts_id", "verdicts", ["id"])
    op.create_index("ix_verdicts_domain_id", "verdicts", ["domain_id"])
    op.create_index("ix_verdicts_asn_id", "verdicts", ["asn_id"])
    op.create_index("ix_verdicts_domain_asn", "verdicts", ["domain_id", "asn_id"])
    op.create_index("ix_verdicts_computed_at", "verdicts", ["computed_at"])


def downgrade() -> None:
    op.drop_table("verdicts")
    op.drop_table("measurements")
    op.drop_table("sources")
    op.drop_table("asns")
    op.drop_table("domains")
