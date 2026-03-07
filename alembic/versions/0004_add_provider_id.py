"""Add provider_id column to all tables for multi-provider disambiguation.

Every table that references a repository now includes a ``provider_id``
column to scope data per provider.  The stable id is set in the TOML
config (defaults to the provider's TOML key).  Backfills existing rows
from the ``provider_name`` column on reports and cross-references for
the remaining tables.

Revision ID: 0004
Revises: 0003
Create Date: 2026-03-07
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str = "0003"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    conn = op.get_bind()

    # ---- reports --------------------------------------------------------
    # Add provider_id column, backfill from provider_name.
    with op.batch_alter_table("reports", recreate="always") as batch_op:
        batch_op.add_column(
            sa.Column(
                "provider_id",
                sa.Text,
                nullable=False,
                server_default=sa.text("''"),
            ),
        )
        batch_op.drop_constraint("uq_reports_repo_hash")
        batch_op.create_unique_constraint(
            "uq_reports_provider_repo_hash",
            ["provider_id", "repo", "git_hash"],
        )
        batch_op.drop_index("idx_reports_repo_branch_ts")
        batch_op.drop_index("idx_reports_repo_hash_ts")
        batch_op.create_index(
            "idx_reports_prov_repo_branch_ts",
            ["provider_id", "repo", "branch_name", "received_ts"],
        )
        batch_op.create_index(
            "idx_reports_prov_repo_hash_ts",
            ["provider_id", "repo", "git_hash", "received_ts"],
        )

    # Backfill: copy provider_name → provider_id.
    conn.execute(
        sa.text(
            "UPDATE reports SET provider_id = provider_name "
            "WHERE provider_id = '' AND provider_name != ''"
        )
    )

    # ---- branch_heads ---------------------------------------------------
    # PK changes from (repo, branch_name) → (provider_id, repo, branch_name).
    # SQLite cannot ALTER PRIMARY KEY so we recreate the table via raw DDL.
    op.drop_index("idx_branch_heads_repo_hash", table_name="branch_heads")
    conn.execute(
        sa.text(
            "CREATE TABLE _branch_heads_new ("
            "  provider_id TEXT NOT NULL DEFAULT '',"
            "  repo TEXT NOT NULL,"
            "  branch_name TEXT NOT NULL,"
            "  current_hash TEXT NOT NULL,"
            "  updated_ts INTEGER NOT NULL,"
            "  PRIMARY KEY (provider_id, repo, branch_name)"
            ")"
        )
    )
    conn.execute(
        sa.text(
            "INSERT INTO _branch_heads_new "
            "(provider_id, repo, branch_name, current_hash, updated_ts) "
            "SELECT "
            "  COALESCE("
            "    (SELECT r.provider_name FROM reports r "
            "     WHERE r.repo = branch_heads.repo "
            "     ORDER BY r.received_ts DESC LIMIT 1), ''"
            "  ), repo, branch_name, current_hash, updated_ts "
            "FROM branch_heads"
        )
    )
    op.drop_table("branch_heads")
    op.rename_table("_branch_heads_new", "branch_heads")
    op.create_index(
        "idx_branch_heads_prov_repo_hash",
        "branch_heads",
        ["provider_id", "repo", "current_hash"],
    )

    # ---- branch_events --------------------------------------------------
    with op.batch_alter_table("branch_events", recreate="always") as batch_op:
        batch_op.add_column(
            sa.Column(
                "provider_id",
                sa.Text,
                nullable=False,
                server_default=sa.text("''"),
            ),
        )
        batch_op.drop_index("idx_branch_events_repo_branch_ts")
        batch_op.drop_index("idx_branch_events_repo_hash_ts")
        batch_op.create_index(
            "idx_branch_events_prov_repo_branch_ts",
            ["provider_id", "repo", "branch_name", "updated_ts"],
        )
        batch_op.create_index(
            "idx_branch_events_prov_repo_hash_ts",
            ["provider_id", "repo", "git_hash", "updated_ts"],
        )

    # Backfill from matching report (same repo + git_hash).
    conn.execute(
        sa.text(
            "UPDATE branch_events SET provider_id = COALESCE("
            "  (SELECT r.provider_name FROM reports r "
            "   WHERE r.repo = branch_events.repo "
            "     AND r.git_hash = branch_events.git_hash "
            "   LIMIT 1), "
            "  ''"
            ") WHERE provider_id = ''"
        )
    )

    # ---- repos -----------------------------------------------------------
    # PK changes from (repo,) → (provider_id, repo).
    # SQLite cannot ALTER PRIMARY KEY so we recreate the table via raw DDL.
    conn.execute(
        sa.text(
            "CREATE TABLE _repos_new ("
            "  provider_id TEXT NOT NULL DEFAULT '',"
            "  repo TEXT NOT NULL,"
            "  first_seen_ts INTEGER NOT NULL,"
            "  last_seen_ts INTEGER NOT NULL,"
            "  PRIMARY KEY (provider_id, repo)"
            ")"
        )
    )
    conn.execute(
        sa.text(
            "INSERT INTO _repos_new "
            "(provider_id, repo, first_seen_ts, last_seen_ts) "
            "SELECT "
            "  COALESCE("
            "    (SELECT r.provider_name FROM reports r "
            "     WHERE r.repo = repos.repo "
            "     ORDER BY r.received_ts DESC LIMIT 1), ''"
            "  ), repo, first_seen_ts, last_seen_ts "
            "FROM repos"
        )
    )
    op.drop_table("repos")
    op.rename_table("_repos_new", "repos")


def downgrade() -> None:
    conn = op.get_bind()

    # ---- repos -----------------------------------------------------------
    conn.execute(
        sa.text(
            "CREATE TABLE _repos_old ("
            "  repo TEXT NOT NULL PRIMARY KEY,"
            "  first_seen_ts INTEGER NOT NULL,"
            "  last_seen_ts INTEGER NOT NULL"
            ")"
        )
    )
    conn.execute(
        sa.text(
            "INSERT OR IGNORE INTO _repos_old (repo, first_seen_ts, last_seen_ts) "
            "SELECT repo, first_seen_ts, last_seen_ts FROM repos"
        )
    )
    op.drop_table("repos")
    op.rename_table("_repos_old", "repos")

    # ---- branch_events --------------------------------------------------
    with op.batch_alter_table("branch_events", recreate="always") as batch_op:
        batch_op.drop_column("provider_id")
        batch_op.drop_index("idx_branch_events_prov_repo_branch_ts")
        batch_op.drop_index("idx_branch_events_prov_repo_hash_ts")
        batch_op.create_index(
            "idx_branch_events_repo_branch_ts",
            ["repo", "branch_name", "updated_ts"],
        )
        batch_op.create_index(
            "idx_branch_events_repo_hash_ts",
            ["repo", "git_hash", "updated_ts"],
        )

    # ---- branch_heads ---------------------------------------------------
    op.drop_index("idx_branch_heads_prov_repo_hash", table_name="branch_heads")
    conn.execute(
        sa.text(
            "CREATE TABLE _branch_heads_old ("
            "  repo TEXT NOT NULL,"
            "  branch_name TEXT NOT NULL,"
            "  current_hash TEXT NOT NULL,"
            "  updated_ts INTEGER NOT NULL,"
            "  PRIMARY KEY (repo, branch_name)"
            ")"
        )
    )
    conn.execute(
        sa.text(
            "INSERT OR IGNORE INTO _branch_heads_old "
            "(repo, branch_name, current_hash, updated_ts) "
            "SELECT repo, branch_name, current_hash, updated_ts FROM branch_heads"
        )
    )
    op.drop_table("branch_heads")
    op.rename_table("_branch_heads_old", "branch_heads")
    op.create_index(
        "idx_branch_heads_repo_hash", "branch_heads", ["repo", "current_hash"]
    )

    # ---- reports --------------------------------------------------------
    with op.batch_alter_table("reports", recreate="always") as batch_op:
        batch_op.drop_column("provider_id")
        batch_op.drop_constraint("uq_reports_provider_repo_hash")
        batch_op.create_unique_constraint(
            "uq_reports_repo_hash",
            ["repo", "git_hash"],
        )
        batch_op.drop_index("idx_reports_prov_repo_branch_ts")
        batch_op.drop_index("idx_reports_prov_repo_hash_ts")
        batch_op.create_index(
            "idx_reports_repo_branch_ts",
            ["repo", "branch_name", "received_ts"],
        )
        batch_op.create_index(
            "idx_reports_repo_hash_ts",
            ["repo", "git_hash", "received_ts"],
        )
