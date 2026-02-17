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
