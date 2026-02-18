"""Tests for covsrv.sql module."""

from __future__ import annotations

import pytest

from covsrv import sql

# -----------------------------------------------------------------------
# configure / _get_path
# -----------------------------------------------------------------------


class TestConfigure:
    def test_configure_sets_path(self, tmp_path):
        db_path = tmp_path / "test.db"
        sql.configure(db_path)
        assert sql._get_path() == db_path

    def test_get_path_raises_if_not_configured(self):
        original = sql._DB_PATH
        try:
            sql._DB_PATH = None
            with pytest.raises(RuntimeError, match="not configured"):
                sql._get_path()
        finally:
            sql._DB_PATH = original


# -----------------------------------------------------------------------
# init_db
# -----------------------------------------------------------------------


class TestInitDb:
    async def test_creates_tables(self, db):
        """After init_db, the expected tables should exist."""
        async with sql.connection() as conn:
            cur = await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
            )
            tables = {row["name"] for row in await cur.fetchall()}

        assert "reports" in tables
        assert "branch_heads" in tables
        assert "branch_events" in tables
        assert "repos" in tables

    async def test_idempotent(self, db):
        """Calling init_db twice should not raise."""
        await sql.init_db()  # already called once by the fixture


# -----------------------------------------------------------------------
# upsert_repo_seen
# -----------------------------------------------------------------------


class TestUpsertRepoSeen:
    async def test_insert_new(self, db):
        async with sql.connection() as conn:
            await sql.upsert_repo_seen(conn, "alice/foo", 1000)

        async with sql.connection() as conn:
            cur = await conn.execute(
                "SELECT * FROM repos WHERE repo = ?;", ("alice/foo",)
            )
            row = await cur.fetchone()
            assert row is not None
            assert row["first_seen_ts"] == 1000
            assert row["last_seen_ts"] == 1000

    async def test_upsert_updates_last_seen(self, db):
        async with sql.connection() as conn:
            await sql.upsert_repo_seen(conn, "alice/foo", 1000)
        async with sql.connection() as conn:
            await sql.upsert_repo_seen(conn, "alice/foo", 2000)

        async with sql.connection() as conn:
            cur = await conn.execute(
                "SELECT * FROM repos WHERE repo = ?;", ("alice/foo",)
            )
            row = await cur.fetchone()
            assert row["first_seen_ts"] == 1000
            assert row["last_seen_ts"] == 2000


# -----------------------------------------------------------------------
# latest_report_for_repo_hash
# -----------------------------------------------------------------------


class TestLatestReportForRepoHash:
    async def test_returns_none_when_empty(self, db):
        result = await sql.latest_report_for_repo_hash("owner/repo", "abc1234")
        assert result is None

    async def test_returns_row(self, db):
        async with sql.connection() as conn:
            await conn.execute(
                "INSERT INTO reports(repo, branch_name, git_hash, received_ts, overall_percent, report_dir) "
                "VALUES(?,?,?,?,?,?);",
                ("owner/repo", "main", "abc1234567", 1000, 85.5, "/tmp/r"),
            )

        row = await sql.latest_report_for_repo_hash("owner/repo", "abc1234567")
        assert row is not None
        assert row["overall_percent"] == 85.5
        assert row["git_hash"] == "abc1234567"

    async def test_different_hash_not_found(self, db):
        async with sql.connection() as conn:
            await conn.execute(
                "INSERT INTO reports(repo, branch_name, git_hash, received_ts, overall_percent, report_dir) "
                "VALUES(?,?,?,?,?,?);",
                ("owner/repo", "main", "abc1234567", 1000, 85.5, "/tmp/r"),
            )

        result = await sql.latest_report_for_repo_hash("owner/repo", "deadbeef123")
        assert result is None


# -----------------------------------------------------------------------
# latest_branch_head_hash
# -----------------------------------------------------------------------


class TestLatestBranchHeadHash:
    async def test_returns_none_when_empty(self, db):
        result = await sql.latest_branch_head_hash("owner/repo", "main")
        assert result is None

    async def test_returns_hash(self, db):
        async with sql.connection() as conn:
            await conn.execute(
                "INSERT INTO branch_heads(repo, branch_name, current_hash, updated_ts) "
                "VALUES(?,?,?,?);",
                ("owner/repo", "main", "abc1234567", 1000),
            )

        result = await sql.latest_branch_head_hash("owner/repo", "main")
        assert result == "abc1234567"


# -----------------------------------------------------------------------
# branch_events_for
# -----------------------------------------------------------------------


class TestBranchEventsFor:
    async def test_empty(self, db):
        result = await sql.branch_events_for("owner/repo", "main", 10)
        assert result == []

    async def test_returns_events_ordered(self, db):
        async with sql.connection() as conn:
            await conn.execute(
                "INSERT INTO branch_events(repo, branch_name, git_hash, updated_ts) VALUES(?,?,?,?);",
                ("owner/repo", "main", "aaa1234567", 1000),
            )
            await conn.execute(
                "INSERT INTO branch_events(repo, branch_name, git_hash, updated_ts) VALUES(?,?,?,?);",
                ("owner/repo", "main", "bbb1234567", 2000),
            )

        events = await sql.branch_events_for("owner/repo", "main", 10)
        assert len(events) == 2
        assert events[0]["git_hash"] == "aaa1234567"
        assert events[1]["git_hash"] == "bbb1234567"

    async def test_limit_applied(self, db):
        async with sql.connection() as conn:
            for i in range(5):
                await conn.execute(
                    "INSERT INTO branch_events(repo, branch_name, git_hash, updated_ts) VALUES(?,?,?,?);",
                    ("owner/repo", "main", f"hash{i:010d}", 1000 + i),
                )

        events = await sql.branch_events_for("owner/repo", "main", 3)
        assert len(events) == 3


# -----------------------------------------------------------------------
# reports_trend_for_repo_hash
# -----------------------------------------------------------------------


class TestReportsTrendForRepoHash:
    async def test_empty(self, db):
        result = await sql.reports_trend_for_repo_hash("owner/repo", "abc1234567", 10)
        assert result == []

    async def test_returns_matching_records(self, db):
        async with sql.connection() as conn:
            await conn.execute(
                "INSERT INTO reports(repo, branch_name, git_hash, received_ts, overall_percent, report_dir) "
                "VALUES(?,?,?,?,?,?);",
                ("owner/repo", "main", "abc1234567", 1000, 85.5, "/tmp/r"),
            )

        result = await sql.reports_trend_for_repo_hash("owner/repo", "abc1234567", 10)
        assert len(result) == 1
        assert result[0]["overall_percent"] == 85.5


# -----------------------------------------------------------------------
# report_percent_for_hashes
# -----------------------------------------------------------------------


class TestReportPercentForHashes:
    async def test_empty_pairs(self, db):
        result = await sql.report_percent_for_hashes("owner/repo", [])
        assert result == []

    async def test_resolves_percent(self, db):
        async with sql.connection() as conn:
            await conn.execute(
                "INSERT INTO reports(repo, branch_name, git_hash, received_ts, overall_percent, report_dir) "
                "VALUES(?,?,?,?,?,?);",
                ("owner/repo", "main", "abc1234567", 1000, 85.5, "/tmp/r"),
            )

        result = await sql.report_percent_for_hashes(
            "owner/repo", [("abc1234567", 1000)]
        )
        assert len(result) == 1
        assert result[0]["overall_percent"] == 85.5
        assert result[0]["git_hash"] == "abc1234567"

    async def test_missing_hash_returns_zero(self, db):
        result = await sql.report_percent_for_hashes(
            "owner/repo", [("nonexistent1", 1000)]
        )
        assert len(result) == 1
        assert result[0]["overall_percent"] == 0.0


# -----------------------------------------------------------------------
# connection context manager
# -----------------------------------------------------------------------


class TestConnection:
    async def test_commits_on_success(self, db):
        async with sql.connection() as conn:
            await conn.execute(
                "INSERT INTO repos(repo, first_seen_ts, last_seen_ts) VALUES(?,?,?);",
                ("test/repo", 100, 100),
            )

        # Read back in a separate connection
        async with sql.connection() as conn:
            cur = await conn.execute(
                "SELECT * FROM repos WHERE repo = ?;", ("test/repo",)
            )
            row = await cur.fetchone()
            assert row is not None

    async def test_closes_connection(self, db):
        conn_ref = None
        async with sql.connection() as conn:
            conn_ref = conn
        # After exiting the context, the connection object's _connection should be None (closed)
        # aiosqlite sets _connection to None on close
        assert conn_ref._connection is None
