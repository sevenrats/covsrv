"""Tests for covsrv.db module."""

from __future__ import annotations

import pytest
from sqlalchemy import select, text

from covsrv import db
from covsrv.models import BranchEvent, BranchHead, Repo, Report

# -----------------------------------------------------------------------
# configure / _get_session_factory
# -----------------------------------------------------------------------


class TestConfigure:
    def test_configure_creates_engine(self, tmp_path):
        db_path = tmp_path / "test.db"
        db.configure(db_path)
        assert db._engine is not None
        assert db._session_factory is not None

    def test_session_factory_raises_if_not_configured(self):
        original_factory = db._session_factory
        original_engine = db._engine
        try:
            db._session_factory = None
            db._engine = None
            with pytest.raises(RuntimeError, match="not configured"):
                db._get_session_factory()
        finally:
            db._session_factory = original_factory
            db._engine = original_engine


# -----------------------------------------------------------------------
# init_db
# -----------------------------------------------------------------------


class TestInitDb:
    async def test_creates_tables(self, initialized_db):
        """After init_db, the expected tables should exist."""
        async with db.session() as sess:
            result = await sess.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
            )
            tables = {row[0] for row in result.all()}

        assert "reports" in tables
        assert "branch_heads" in tables
        assert "branch_events" in tables
        assert "repos" in tables

    async def test_idempotent(self, initialized_db):
        """Calling init_db twice should not raise."""
        await db.init_db()  # already called once by the fixture


# -----------------------------------------------------------------------
# upsert_repo_seen
# -----------------------------------------------------------------------


class TestUpsertRepoSeen:
    async def test_insert_new(self, initialized_db):
        async with db.session() as sess:
            await db.upsert_repo_seen(sess, "alice/foo", 1000)

        async with db.session() as sess:
            result = await sess.execute(select(Repo).where(Repo.repo == "alice/foo"))
            row = result.scalars().first()
            assert row is not None
            assert row.first_seen_ts == 1000
            assert row.last_seen_ts == 1000

    async def test_upsert_updates_last_seen(self, initialized_db):
        async with db.session() as sess:
            await db.upsert_repo_seen(sess, "alice/foo", 1000)
        async with db.session() as sess:
            await db.upsert_repo_seen(sess, "alice/foo", 2000)

        async with db.session() as sess:
            result = await sess.execute(select(Repo).where(Repo.repo == "alice/foo"))
            row = result.scalars().first()
            assert row is not None
            assert row.first_seen_ts == 1000
            assert row.last_seen_ts == 2000


# -----------------------------------------------------------------------
# latest_report_for_repo_hash
# -----------------------------------------------------------------------


class TestLatestReportForRepoHash:
    async def test_returns_none_when_empty(self, initialized_db):
        result = await db.latest_report_for_repo_hash("owner/repo", "abc1234")
        assert result is None

    async def test_returns_row(self, initialized_db):
        async with db.session() as sess:
            sess.add(
                Report(
                    repo="owner/repo",
                    branch_name="main",
                    git_hash="abc1234567",
                    received_ts=1000,
                    overall_percent=85.5,
                    report_dir="/tmp/r",
                )
            )

        row = await db.latest_report_for_repo_hash("owner/repo", "abc1234567")
        assert row is not None
        assert row["overall_percent"] == 85.5
        assert row["git_hash"] == "abc1234567"

    async def test_different_hash_not_found(self, initialized_db):
        async with db.session() as sess:
            sess.add(
                Report(
                    repo="owner/repo",
                    branch_name="main",
                    git_hash="abc1234567",
                    received_ts=1000,
                    overall_percent=85.5,
                    report_dir="/tmp/r",
                )
            )

        result = await db.latest_report_for_repo_hash("owner/repo", "deadbeef123")
        assert result is None


# -----------------------------------------------------------------------
# latest_branch_head_hash
# -----------------------------------------------------------------------


class TestLatestBranchHeadHash:
    async def test_returns_none_when_empty(self, initialized_db):
        result = await db.latest_branch_head_hash("owner/repo", "main")
        assert result is None

    async def test_returns_hash(self, initialized_db):
        async with db.session() as sess:
            sess.add(
                BranchHead(
                    repo="owner/repo",
                    branch_name="main",
                    current_hash="abc1234567",
                    updated_ts=1000,
                )
            )

        result = await db.latest_branch_head_hash("owner/repo", "main")
        assert result == "abc1234567"


# -----------------------------------------------------------------------
# branch_events_for
# -----------------------------------------------------------------------


class TestBranchEventsFor:
    async def test_empty(self, initialized_db):
        result = await db.branch_events_for("owner/repo", "main", 10)
        assert result == []

    async def test_returns_events_ordered(self, initialized_db):
        async with db.session() as sess:
            sess.add(
                BranchEvent(
                    repo="owner/repo",
                    branch_name="main",
                    git_hash="aaa1234567",
                    updated_ts=1000,
                )
            )
            sess.add(
                BranchEvent(
                    repo="owner/repo",
                    branch_name="main",
                    git_hash="bbb1234567",
                    updated_ts=2000,
                )
            )

        events = await db.branch_events_for("owner/repo", "main", 10)
        assert len(events) == 2
        assert events[0]["git_hash"] == "aaa1234567"
        assert events[1]["git_hash"] == "bbb1234567"

    async def test_limit_applied(self, initialized_db):
        async with db.session() as sess:
            for i in range(5):
                sess.add(
                    BranchEvent(
                        repo="owner/repo",
                        branch_name="main",
                        git_hash=f"hash{i:010d}",
                        updated_ts=1000 + i,
                    )
                )

        events = await db.branch_events_for("owner/repo", "main", 3)
        assert len(events) == 3


# -----------------------------------------------------------------------
# reports_trend_for_repo_hash
# -----------------------------------------------------------------------


class TestReportsTrendForRepoHash:
    async def test_empty(self, initialized_db):
        result = await db.reports_trend_for_repo_hash("owner/repo", "abc1234567", 10)
        assert result == []

    async def test_returns_matching_records(self, initialized_db):
        async with db.session() as sess:
            sess.add(
                Report(
                    repo="owner/repo",
                    branch_name="main",
                    git_hash="abc1234567",
                    received_ts=1000,
                    overall_percent=85.5,
                    report_dir="/tmp/r",
                )
            )

        result = await db.reports_trend_for_repo_hash("owner/repo", "abc1234567", 10)
        assert len(result) == 1
        assert result[0]["overall_percent"] == 85.5


# -----------------------------------------------------------------------
# report_percent_for_hashes
# -----------------------------------------------------------------------


class TestReportPercentForHashes:
    async def test_empty_pairs(self, initialized_db):
        result = await db.report_percent_for_hashes("owner/repo", [])
        assert result == []

    async def test_resolves_percent(self, initialized_db):
        async with db.session() as sess:
            sess.add(
                Report(
                    repo="owner/repo",
                    branch_name="main",
                    git_hash="abc1234567",
                    received_ts=1000,
                    overall_percent=85.5,
                    report_dir="/tmp/r",
                )
            )

        result = await db.report_percent_for_hashes(
            "owner/repo", [("abc1234567", 1000)]
        )
        assert len(result) == 1
        assert result[0]["overall_percent"] == 85.5
        assert result[0]["git_hash"] == "abc1234567"

    async def test_missing_hash_returns_zero(self, initialized_db):
        result = await db.report_percent_for_hashes(
            "owner/repo", [("nonexistent1", 1000)]
        )
        assert len(result) == 1
        assert result[0]["overall_percent"] == 0.0


# -----------------------------------------------------------------------
# session context manager
# -----------------------------------------------------------------------


class TestSession:
    async def test_commits_on_success(self, initialized_db):
        async with db.session() as sess:
            sess.add(Repo(repo="test/repo", first_seen_ts=100, last_seen_ts=100))

        # Read back in a separate session
        async with db.session() as sess:
            result = await sess.execute(select(Repo).where(Repo.repo == "test/repo"))
            row = result.scalars().first()
            assert row is not None

    async def test_rolls_back_on_error(self, initialized_db):
        with pytest.raises(ValueError):
            async with db.session() as sess:
                sess.add(
                    Repo(repo="rollback/repo", first_seen_ts=100, last_seen_ts=100)
                )
                raise ValueError("oops")

        # Data should NOT be committed
        async with db.session() as sess:
            result = await sess.execute(
                select(Repo).where(Repo.repo == "rollback/repo")
            )
            row = result.scalars().first()
            assert row is None
