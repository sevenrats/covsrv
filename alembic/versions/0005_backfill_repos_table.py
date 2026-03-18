"""Backfill repos table from reports for databases with missing entries.

The ``repos`` table is populated by ``upsert_repo_seen`` during report
ingestion, but databases created before this logic was added (or where
the table was cleared) may have reports with no corresponding ``repos``
row.  This migration inserts any missing entries derived from the
``reports`` table.

Revision ID: 0005
Revises: 0004
Create Date: 2026-03-18
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: str = "0004"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text(
            "INSERT OR IGNORE INTO repos (provider_id, repo, first_seen_ts, last_seen_ts) "
            "SELECT provider_id, repo, MIN(received_ts), MAX(received_ts) "
            "FROM reports "
            "GROUP BY provider_id, repo"
        )
    )


def downgrade() -> None:
    # Nothing to undo — the rows are valid data that would have been
    # created by normal report ingestion.
    pass
