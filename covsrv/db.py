"""Async SQLAlchemy database layer."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from sqlalchemy import select, text
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from covsrv.models import BranchEvent, BranchHead, Repo, Report

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Engine & session factory
# ------------------------------------------------------------------

_engine = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def configure(db_path: Path) -> None:
    """Set the database path and create the async engine."""
    global _engine, _session_factory
    url = f"sqlite+aiosqlite:///{db_path}"
    _engine = create_async_engine(url, echo=False)
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)


def _get_session_factory() -> async_sessionmaker[AsyncSession]:
    if _session_factory is None:
        raise RuntimeError("Database not configured – call db.configure() first")
    return _session_factory


@asynccontextmanager
async def session() -> AsyncIterator[AsyncSession]:
    """Async context manager yielding a ready-to-use SQLAlchemy session."""
    factory = _get_session_factory()
    async with factory() as sess:
        yield sess
        await sess.commit()


# ------------------------------------------------------------------
# Alembic helpers
# ------------------------------------------------------------------

_ALEMBIC_DIR = str(Path(__file__).resolve().parent.parent / "alembic")


def _run_alembic_upgrade(connection: Any) -> None:
    """Synchronous helper executed inside ``run_sync``."""
    from sqlalchemy import inspect as sa_inspect

    from alembic import command
    from alembic.config import Config
    from alembic.migration import MigrationContext

    cfg = Config()
    cfg.set_main_option("script_location", _ALEMBIC_DIR)
    cfg.attributes["connection"] = connection

    # Detect pre-existing databases (e.g. migrated from Atlas / create_all)
    # that already have application tables but no alembic_version row yet.
    ctx = MigrationContext.configure(connection)
    if ctx.get_current_revision() is None:
        existing = set(sa_inspect(connection).get_table_names())
        if "reports" in existing:
            command.stamp(cfg, "head")
            return

    command.upgrade(cfg, "head")


async def init_db() -> None:
    """Apply pending Alembic migrations to bring the database up to date."""
    if _engine is None:
        raise RuntimeError("Database not configured – call db.configure() first")
    async with _engine.begin() as conn:
        await conn.execute(text("PRAGMA journal_mode=WAL"))
        await conn.run_sync(_run_alembic_upgrade)


async def dispose() -> None:
    """Dispose of the engine and reset module state."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None


# ------------------------------------------------------------------
# Reusable write helpers
# ------------------------------------------------------------------


async def upsert_repo_seen(sess: AsyncSession, repo: str, ts: int) -> None:
    stmt = sqlite_insert(Repo).values(repo=repo, first_seen_ts=ts, last_seen_ts=ts)
    stmt = stmt.on_conflict_do_update(
        index_elements=[Repo.repo],
        set_={"last_seen_ts": stmt.excluded.last_seen_ts},
    )
    await sess.execute(stmt)


async def upsert_branch_head(
    sess: AsyncSession,
    repo: str,
    branch_name: str,
    git_hash: str,
    ts: int,
) -> None:
    stmt = sqlite_insert(BranchHead).values(
        repo=repo, branch_name=branch_name, current_hash=git_hash, updated_ts=ts
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[BranchHead.repo, BranchHead.branch_name],
        set_={
            "current_hash": stmt.excluded.current_hash,
            "updated_ts": stmt.excluded.updated_ts,
        },
    )
    await sess.execute(stmt)


# ------------------------------------------------------------------
# Reusable query helpers
# ------------------------------------------------------------------


async def latest_report_for_repo_hash(
    repo: str, git_hash: str
) -> dict[str, Any] | None:
    async with session() as sess:
        stmt = (
            select(Report)
            .where(Report.repo == repo, Report.git_hash == git_hash)
            .limit(1)
        )
        result = await sess.execute(stmt)
        row = result.scalars().first()
        if row is None:
            return None
        return {
            "id": row.id,
            "repo": row.repo,
            "branch_name": row.branch_name,
            "git_hash": row.git_hash,
            "received_ts": row.received_ts,
            "overall_percent": row.overall_percent,
            "report_dir": row.report_dir,
            "provider_url": row.provider_url,
        }


async def latest_branch_head_hash(repo: str, branch_name: str) -> str | None:
    async with session() as sess:
        stmt = (
            select(BranchHead.current_hash)
            .where(BranchHead.repo == repo, BranchHead.branch_name == branch_name)
            .limit(1)
        )
        result = await sess.execute(stmt)
        row = result.first()
        return None if row is None else str(row[0])


async def branch_events_for(
    repo: str, branch_name: str, limit: int
) -> list[dict[str, Any]]:
    async with session() as sess:
        stmt = (
            select(BranchEvent.id, BranchEvent.git_hash, BranchEvent.updated_ts)
            .where(
                BranchEvent.repo == repo,
                BranchEvent.branch_name == branch_name,
            )
            .order_by(BranchEvent.updated_ts.asc(), BranchEvent.id.asc())
            .limit(limit)
        )
        result = await sess.execute(stmt)
        return [dict(r._mapping) for r in result.all()]


async def reports_trend_for_repo_hash(
    repo: str, git_hash: str, limit: int
) -> list[dict[str, Any]]:
    async with session() as sess:
        stmt = (
            select(Report.git_hash, Report.received_ts, Report.overall_percent)
            .where(Report.repo == repo, Report.git_hash == git_hash)
            .order_by(Report.received_ts.asc(), Report.id.asc())
            .limit(limit)
        )
        result = await sess.execute(stmt)
        return [dict(r._mapping) for r in result.all()]


async def provider_url_for_repo(repo: str) -> str | None:
    """Return the ``provider_url`` from the most recent report for *repo*."""
    async with session() as sess:
        stmt = (
            select(Report.provider_url)
            .where(Report.repo == repo)
            .order_by(Report.received_ts.desc())
            .limit(1)
        )
        result = await sess.execute(stmt)
        row = result.first()
        return None if row is None else str(row[0])


async def report_percent_for_hashes(
    repo: str, hash_ts_pairs: list[tuple[str, int]]
) -> list[dict[str, Any]]:
    """Resolve overall_percent for a list of (git_hash, updated_ts) pairs."""
    points: list[dict[str, Any]] = []
    async with session() as sess:
        for git_hash, updated_ts in hash_ts_pairs:
            stmt = (
                select(Report.overall_percent)
                .where(Report.repo == repo, Report.git_hash == git_hash)
                .limit(1)
            )
            result = await sess.execute(stmt)
            row = result.first()
            points.append(
                {
                    "git_hash": git_hash,
                    "received_ts": updated_ts,
                    "overall_percent": float(row[0]) if row is not None else 0.0,
                }
            )
    return points
