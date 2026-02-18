"""Async SQLite database layer (aiosqlite)."""

from __future__ import annotations

import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

import aiosqlite

# ------------------------------------------------------------------
# Schema
# ------------------------------------------------------------------

INIT_DB = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,            -- "owner/name"
    branch_name TEXT NOT NULL,     -- branch at time of ingest
    git_hash TEXT NOT NULL,        -- commit sha (required)
    received_ts INTEGER NOT NULL,
    overall_percent REAL NOT NULL,
    report_dir TEXT NOT NULL
);

-- one "original" report per (repo, sha)
CREATE UNIQUE INDEX IF NOT EXISTS uq_reports_repo_hash
    ON reports(repo, git_hash);

CREATE INDEX IF NOT EXISTS idx_reports_repo_branch_ts
    ON reports(repo, branch_name, received_ts);

CREATE INDEX IF NOT EXISTS idx_reports_repo_hash_ts
    ON reports(repo, git_hash, received_ts);

CREATE TABLE IF NOT EXISTS branch_heads (
    repo TEXT NOT NULL,
    branch_name TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    updated_ts INTEGER NOT NULL,
    PRIMARY KEY (repo, branch_name)
);

CREATE INDEX IF NOT EXISTS idx_branch_heads_repo_hash
    ON branch_heads(repo, current_hash);

CREATE TABLE IF NOT EXISTS branch_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    branch_name TEXT NOT NULL,
    git_hash TEXT NOT NULL,
    updated_ts INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_branch_events_repo_branch_ts
    ON branch_events(repo, branch_name, updated_ts);

CREATE INDEX IF NOT EXISTS idx_branch_events_repo_hash_ts
    ON branch_events(repo, git_hash, updated_ts);

CREATE TABLE IF NOT EXISTS repos (
    repo TEXT PRIMARY KEY,
    first_seen_ts INTEGER NOT NULL,
    last_seen_ts INTEGER NOT NULL
);
"""

UPSERT_REPO_SEEN = """
INSERT INTO repos(repo, first_seen_ts, last_seen_ts)
VALUES(?,?,?)
ON CONFLICT(repo) DO UPDATE SET last_seen_ts=excluded.last_seen_ts;
"""

# ------------------------------------------------------------------
# Database handle
# ------------------------------------------------------------------

_DB_PATH: Path | None = None


def configure(db_path: Path) -> None:
    """Set the database path.  Must be called before any DB access."""
    global _DB_PATH
    _DB_PATH = db_path


def _get_path() -> Path:
    if _DB_PATH is None:
        raise RuntimeError("Database not configured – call sql.configure() first")
    return _DB_PATH


async def _connect() -> aiosqlite.Connection:
    conn = await aiosqlite.connect(_get_path())
    conn.row_factory = sqlite3.Row
    await conn.execute("PRAGMA journal_mode=WAL;")
    return conn


@asynccontextmanager
async def connection() -> AsyncIterator[aiosqlite.Connection]:
    """Async context manager yielding a ready-to-use connection."""
    conn = await _connect()
    try:
        yield conn
        await conn.commit()
    finally:
        await conn.close()


async def init_db() -> None:
    """Create tables / indexes if they don't exist."""
    async with connection() as conn:
        await conn.executescript(INIT_DB)


# ------------------------------------------------------------------
# Reusable query helpers
# ------------------------------------------------------------------


async def upsert_repo_seen(conn: aiosqlite.Connection, repo: str, ts: int) -> None:
    await conn.execute(UPSERT_REPO_SEEN, (repo, ts, ts))


async def latest_report_for_repo_hash(
    repo: str, git_hash: str
) -> dict[str, Any] | None:
    async with connection() as conn:
        cur = await conn.execute(
            "SELECT * FROM reports WHERE repo = ? AND git_hash = ? LIMIT 1;",
            (repo, git_hash),
        )
        row = await cur.fetchone()
        return dict(row) if row else None


async def latest_branch_head_hash(repo: str, branch_name: str) -> str | None:
    async with connection() as conn:
        cur = await conn.execute(
            "SELECT current_hash FROM branch_heads "
            "WHERE repo = ? AND branch_name = ? LIMIT 1;",
            (repo, branch_name),
        )
        row = await cur.fetchone()
        return None if row is None else str(row["current_hash"])


async def branch_events_for(
    repo: str, branch_name: str, limit: int
) -> list[dict[str, Any]]:
    async with connection() as conn:
        cur = await conn.execute(
            """
            SELECT id, git_hash, updated_ts
            FROM branch_events
            WHERE repo = ? AND branch_name = ?
            ORDER BY updated_ts ASC, id ASC
            LIMIT ?;
            """,
            (repo, branch_name, limit),
        )
        return [dict(r) for r in await cur.fetchall()]


async def reports_trend_for_repo_hash(
    repo: str, git_hash: str, limit: int
) -> list[dict[str, Any]]:
    async with connection() as conn:
        cur = await conn.execute(
            """
            SELECT git_hash, received_ts, overall_percent
            FROM reports
            WHERE repo = ? AND git_hash = ?
            ORDER BY received_ts ASC, id ASC
            LIMIT ?;
            """,
            (repo, git_hash, limit),
        )
        return [dict(r) for r in await cur.fetchall()]


async def report_percent_for_hashes(
    repo: str, hash_ts_pairs: list[tuple[str, int]]
) -> list[dict[str, Any]]:
    """Resolve overall_percent for a list of (git_hash, updated_ts) pairs."""
    points: list[dict[str, Any]] = []
    async with connection() as conn:
        for git_hash, updated_ts in hash_ts_pairs:
            cur = await conn.execute(
                """
                SELECT overall_percent
                FROM reports
                WHERE repo = ? AND git_hash = ?
                LIMIT 1;
                """,
                (repo, git_hash),
            )
            r = await cur.fetchone()
            points.append(
                {
                    "git_hash": git_hash,
                    "received_ts": updated_ts,
                    "overall_percent": float(r["overall_percent"])
                    if r is not None
                    else 0.0,
                }
            )
    return points
