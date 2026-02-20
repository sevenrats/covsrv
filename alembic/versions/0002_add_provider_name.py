"""Add provider_name column to reports.

Revision ID: 0002
Revises: 0001
Create Date: 2026-02-20
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str = "0001"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "reports",
        sa.Column(
            "provider_name",
            sa.Text,
            nullable=False,
            server_default=sa.text("''"),
        ),
    )


def downgrade() -> None:
    op.drop_column("reports", "provider_name")
