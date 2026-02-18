"""Initial schema.

Revision ID: 0001
Revises:
Create Date: 2026-02-18
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("repo", sa.Text, nullable=False),
        sa.Column("branch_name", sa.Text, nullable=False),
        sa.Column("git_hash", sa.Text, nullable=False),
        sa.Column("received_ts", sa.Integer, nullable=False),
        sa.Column("overall_percent", sa.Float, nullable=False),
        sa.Column("report_dir", sa.Text, nullable=False),
        sa.Column(
            "provider_url",
            sa.Text,
            nullable=False,
            server_default=sa.text("'https://github.com'"),
        ),
        sa.UniqueConstraint("repo", "git_hash", name="uq_reports_repo_hash"),
    )
    op.create_index(
        "idx_reports_repo_branch_ts", "reports", ["repo", "branch_name", "received_ts"]
    )
    op.create_index(
        "idx_reports_repo_hash_ts", "reports", ["repo", "git_hash", "received_ts"]
    )

    op.create_table(
        "branch_heads",
        sa.Column("repo", sa.Text, primary_key=True),
        sa.Column("branch_name", sa.Text, primary_key=True),
        sa.Column("current_hash", sa.Text, nullable=False),
        sa.Column("updated_ts", sa.Integer, nullable=False),
    )
    op.create_index(
        "idx_branch_heads_repo_hash", "branch_heads", ["repo", "current_hash"]
    )

    op.create_table(
        "branch_events",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("repo", sa.Text, nullable=False),
        sa.Column("branch_name", sa.Text, nullable=False),
        sa.Column("git_hash", sa.Text, nullable=False),
        sa.Column("updated_ts", sa.Integer, nullable=False),
    )
    op.create_index(
        "idx_branch_events_repo_branch_ts",
        "branch_events",
        ["repo", "branch_name", "updated_ts"],
    )
    op.create_index(
        "idx_branch_events_repo_hash_ts",
        "branch_events",
        ["repo", "git_hash", "updated_ts"],
    )

    op.create_table(
        "repos",
        sa.Column("repo", sa.Text, primary_key=True),
        sa.Column("first_seen_ts", sa.Integer, nullable=False),
        sa.Column("last_seen_ts", sa.Integer, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("repos")
    op.drop_index("idx_branch_events_repo_hash_ts", table_name="branch_events")
    op.drop_index("idx_branch_events_repo_branch_ts", table_name="branch_events")
    op.drop_table("branch_events")
    op.drop_index("idx_branch_heads_repo_hash", table_name="branch_heads")
    op.drop_table("branch_heads")
    op.drop_index("idx_reports_repo_hash_ts", table_name="reports")
    op.drop_index("idx_reports_repo_branch_ts", table_name="reports")
    op.drop_table("reports")
