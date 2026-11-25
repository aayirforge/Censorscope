"""0002_add_technique_and_category

Revision ID: 0002_add_technique_and_category
Revises: 0001_initial_schema
Create Date: 2026-11-24 11:28:00.000000

"""

from collections.abc import Sequence
from typing import Union

import sqlalchemy as sa

from alembic import op

revision: str = "0002_add_technique_and_category"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add technique_labels to measurements
    op.add_column("measurements", sa.Column("technique_labels", sa.JSON(), nullable=True))

    # 2. Add category to verdicts (censorship_suspected, security_related, infrastructure_failure, inconclusive)
    op.add_column("verdicts", sa.Column("category", sa.String(length=32), nullable=True))
    op.create_index("ix_verdicts_category", "verdicts", ["category"])

    # 3. Create legal_context table
    op.create_table(
        "legal_context",
        sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
        sa.Column("domain_id", sa.Integer(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("source_url", sa.String(length=512), nullable=True),
        sa.Column("source_type", sa.String(length=64), nullable=True),
        sa.Column("confidence", sa.String(length=32), nullable=False, server_default="Unknown"),
        sa.Column("published_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_legal_context_id", "legal_context", ["id"])
    op.create_index("ix_legal_context_domain_id", "legal_context", ["domain_id"])


def downgrade() -> None:
    op.drop_table("legal_context")
    op.drop_index("ix_verdicts_category", table_name="verdicts")
    op.drop_column("verdicts", "category")
    op.drop_column("measurements", "technique_labels")
