"""
0003_evidence_batches.py

Revision ID: 0003_evidence_batches
Revises: 0002_add_technique_and_category
Create Date: 2026-11-24 17:56:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0003_evidence_batches"
down_revision = "0002_add_technique_and_category"
branch_labels = None
depends_on = None

JsonType = sa.JSON().with_variant(postgresql.JSONB, "postgresql")


def upgrade() -> None:
    # 1. Batches Table
    op.create_table(
        "batches",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("onchain_batch_id", sa.BigInteger(), nullable=True, unique=True, index=True),
        sa.Column("merkle_root", sa.String(66), nullable=False, unique=True, index=True),
        sa.Column("ipfs_cid", sa.String(255), nullable=False),
        sa.Column("from_timestamp", sa.DateTime(), nullable=False),
        sa.Column("to_timestamp", sa.DateTime(), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("tx_hash", sa.String(66), nullable=True, index=True),
        sa.Column("block_number", sa.BigInteger(), nullable=True),
        sa.Column("chain_id", sa.BigInteger(), nullable=False, server_default="31337"),
        sa.Column("contract_address", sa.String(42), nullable=True),
        sa.Column("is_mock_storage", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )

    # 2. Measurement Proofs Table
    op.create_table(
        "measurement_proofs",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("measurement_id", sa.Integer(), sa.ForeignKey("measurements.id", ondelete="CASCADE"), nullable=False, unique=True, index=True),
        sa.Column("batch_id", sa.Integer(), sa.ForeignKey("batches.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("leaf_hash", sa.String(66), nullable=False, index=True),
        sa.Column("leaf_data_json", JsonType, nullable=False),
        sa.Column("proof", JsonType, nullable=False), # Array of hex 32-byte strings
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("measurement_proofs")
    op.drop_table("batches")
