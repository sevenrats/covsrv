[![Coverage](https://coverage.crandall.codes/badge/sevenrats/covsrv/b/main)](https://coverage.crandall.codes/sevenrats/covsrv/b/main)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support-yellow?logo=buymeacoffee)](https://buymeacoffee.com/sevenrats)

# covsrv

A self-hosted code-coverage server and dashboard built with
[FastAPI](https://fastapi.tiangolo.com/). Upload a `.tar.gz` of coverage
artifacts from CI, then browse HTML reports, track per-branch trends, and
embed SVG badges — without sending data to a third party.

## Features

- **Single-endpoint report ingestion** — `POST /reports` accepts a `.tar.gz`
  containing an HTML coverage report, `coverage.xml` (Cobertura format), and
  optionally `coverage.json` and `coverage.lcov`. See
  [`.github/workflows/post-pr.yml`](.github/workflows/post-pr.yml) for a
  working example.
- **SVG coverage badges** — shields.io-style badges for any branch or commit.
- **Dashboards** — per-branch and per-commit HTML views with coverage trend
  charts and uncovered-line breakdowns.
- **Raw report hosting** — serves the uploaded HTML report directly, framed
  inside a navigation shell.
- **Downloadable artifacts** — download `coverage.xml`, `coverage.json`, or
  `coverage.lcov` for any commit or branch head (if those files were included
  in the uploaded tarball).
- **OAuth access control** — optional GitHub and Gitea/Forgejo OAuth so
  private-repo coverage is only visible to collaborators.
- **TOML configuration** — a single `config.toml` file defines providers,
  hierarchical report keys, and auth settings. Environment variables are
  supported as a legacy fallback when no config file is present.
- **SQLite + Alembic** — Alembic migrations run automatically on startup
  via `db.init_db()`.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Report Ingestion](#report-ingestion)
- [Badges](#badges)
- [Dashboards & API](#dashboards--api)
- [Authentication & OAuth](#authentication--oauth)
- [Data & Backups](#data--backups)
- [Development](#development)

---

## Quick Start

### Docker Compose

The repository includes a [`compose.yml`](compose.yml):

```yaml
volumes:
  covsrv_conf: {}
  covsrv_data: {}

services:
  covsrv:
    image: ghcr.io/sevenrats/covsrv:latest
    ports:
      - "8000:8000"
    environment:
      COVSRV_CONF: /conf
      COVSRV_DATA: /data
    volumes:
      - covsrv_conf:/conf
      - covsrv_data:/data
    restart: unless-stopped
```

```bash
docker compose up -d
```

On first start, copy [`config.example.toml`](config.example.toml) into the
`covsrv_conf` volume as `config.toml` and edit it (see
[Configuration](#configuration)).

The server listens on port **8000**. The root path (`/`) redirects to the
FastAPI interactive docs at `/docs`.

### Run locally

```bash
# Requires Python ≥ 3.13 and uv
uv sync
cp config.example.toml config.toml   # edit as needed
uvicorn main:app --reload
```

---

## Configuration

covsrv is configured through a TOML file. The path is resolved from the
`COVSRV_CONF` environment variable, which may point to a file or a directory
(in which case `config.toml` is expected inside it). When no `COVSRV_CONF` is
set, covsrv looks for `config.toml` under `$COVSRV_DATA` (default: the
working directory).

See [`config.example.toml`](config.example.toml) for a fully commented
example. The key sections are:

### `[global]`

| Key | Default | Description |
|-----|---------|-------------|
| `report_key` | — | Master report key; authorises posting for any repo on any provider |
| `public_url` | `http://localhost:8000` | Externally-reachable base URL (used for OAuth callbacks) |
| `session_secret` | `change-me-in-production` | Secret for signing session cookies |
| `auth_enabled` | `false` | Set to `true` to require OAuth for private repos |
| `auth_cache_ttl` | `60` | Seconds to cache authorization decisions |

### `[providers.<name>]`

Each provider block defines a code-forge backend. You can define multiple
providers (e.g. GitHub and a self-hosted Gitea), each with a unique name.

| Key | Required | Description |
|-----|----------|-------------|
| `type` | Yes | `"github"` or `"gitea"` |
| `url` | Yes | Forge base URL (e.g. `https://github.com`) |
| `report_key` | — | Provider-level report key |
| `client_id` | — | OAuth client ID (needed only when `auth_enabled = true`) |
| `client_secret` | — | OAuth client secret |

Report keys are hierarchical. A key at a broader scope authorises everything
within that scope:

```
global  →  provider  →  owner  →  repo
```

Owner-level and repo-level keys are defined as nested tables:

```toml
[providers.my-gitea.owners.sevenrats]
report_key = "owner-level-key"

[providers.my-gitea.repos."sevenrats/covsrv"]
report_key = "repo-level-key"
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `COVSRV_DATA` | `.` | Base directory. `covsrv_data/` inside it holds the SQLite DB and uploaded reports. |
| `COVSRV_CONF` | — | Path to `config.toml` or a directory containing it |

When **no** config file is present, covsrv falls back to environment variables
for auth settings (`COVSRV_AUTH_ENABLED`, `COVSRV_SESSION_SECRET`,
`COVSRV_PUBLIC_URL`, `COVSRV_AUTH_CACHE_TTL`, `COVSRV_GITHUB_CLIENT_ID`,
`COVSRV_GITHUB_CLIENT_SECRET`, `COVSRV_GITEA_URL`, `COVSRV_GITEA_CLIENT_ID`,
`COVSRV_GITEA_CLIENT_SECRET`) and a single argon2-hashed token for report
ingestion. This mode exists for backward compatibility; the TOML config file
is the preferred approach.

---

## Report Ingestion

### `POST /reports`

Upload a `.tar.gz` archive containing your coverage artifacts. The tarball
must include `coverage.xml` (Cobertura format) at the top level. It typically
also contains the HTML report (`index.html` and supporting files) and may
include `coverage.json` and `coverage.lcov`.

For a complete working example — generating all artifacts, packaging the
tarball, and posting it — see
[`.github/workflows/post-pr.yml`](.github/workflows/post-pr.yml).

#### Form fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `owner` | Yes | — | Repository owner / org |
| `repo` | Yes | — | Repository name |
| `branch` | Yes | — | Branch name |
| `sha` | Yes | — | Commit SHA (≥ 7 characters) |
| `provider` | Yes (with config file) | `""` | Provider name as defined in `config.toml` |
| `provider_url` | — | `https://github.com` | Forge base URL (legacy; ignored when a config file is loaded) |
| `tarball` | Yes | — | `.tar.gz` file upload |

#### Authentication

Every request must include a report key via one of:

```
Authorization: Bearer <REPORT_KEY>
```

```
X-Access-Token: <REPORT_KEY>
```

The key is verified against the hierarchical keys in `config.toml`
(repo → owner → provider → global). Without a config file, the legacy
argon2-hashed token is used instead.

#### Response

```json
{
  "status": "ok",
  "owner": "myorg",
  "repo": "myrepo",
  "branch": "main",
  "sha": "abc1234...",
  "received_ts": 1739980800,
  "overall_percent": 87.3,
  "hash_dashboard_url": "/myorg/myrepo/h/abc1234...",
  "hash_chart_url": "/myorg/myrepo/h/abc1234.../chart",
  "branch_dashboard_url": "/myorg/myrepo/b/main",
  "hash_raw_url": "/raw/myorg/myrepo/h/abc1234.../"
}
```

Reports are immutable per commit SHA. A second upload for the same
`(repo, sha)` pair returns `409 Conflict`.

---

## Badges

SVG coverage badges are always publicly accessible, even when auth is enabled.

### Branch badge (tracks the branch head)

```
/badge/{owner}/{repo}/b/{branch}
```

Cached with `Cache-Control: max-age=60`.

### Commit badge (immutable)

```
/badge/{owner}/{repo}/h/{sha}
```

Cached with `Cache-Control: max-age=31536000, immutable`.

### Query parameters

| Param | Default | Description |
|-------|---------|-------------|
| `label` | `coverage` | Left-hand text on the badge |
| `decimals` | `1` | Decimal places shown (0–3) |

### Colour thresholds

| Coverage | Colour |
|----------|--------|
| ≥ 90% | green |
| 75–89% | yellow |
| 50–74% | orange |
| < 50% | red |
| unknown | grey |

### Markdown example

```markdown
[![Coverage](https://coverage.example.com/badge/myorg/myrepo/b/main)](https://coverage.example.com/myorg/myrepo/b/main)
```

---

## Dashboards & API

### Web dashboards

| URL pattern | Description |
|-------------|-------------|
| `/{owner}/{repo}/` | Redirects to the `main` branch dashboard |
| `/{owner}/{repo}/b/{branch}` | Branch dashboard — trend chart, uncovered lines |
| `/{owner}/{repo}/h/{sha}` | Commit view — framed raw HTML report |
| `/{owner}/{repo}/h/{sha}/chart` | Commit chart dashboard |
| `/raw/{owner}/{repo}/h/{sha}/` | Raw HTML report (served as-is from disk) |

### JSON API

| Endpoint | Description |
|----------|-------------|
| `GET /api/{owner}/{repo}/b/{branch}/trend` | Coverage trend for the branch (up to `?limit=200` points) |
| `GET /api/{owner}/{repo}/b/{branch}/latest/worst-files` | Files with lowest coverage on branch head |
| `GET /api/{owner}/{repo}/b/{branch}/latest/uncovered-lines` | Files with most uncovered lines on branch head |
| `GET /api/{owner}/{repo}/h/{sha}/trend` | Coverage trend anchored at a specific commit |
| `GET /api/{owner}/{repo}/h/{sha}/latest/worst-files` | Worst-covered files for a commit |
| `GET /api/{owner}/{repo}/h/{sha}/latest/uncovered-lines` | Most uncovered lines for a commit |

### Downloads

These return the raw artifact files from the uploaded tarball, if present.

| URL pattern | Description |
|-------------|-------------|
| `/download/xml/{owner}/{repo}/h/{sha}` | `coverage.xml` |
| `/download/json/{owner}/{repo}/h/{sha}` | `coverage.json` |
| `/download/lcov/{owner}/{repo}/h/{sha}` | `coverage.lcov` |
| `/download/{token}/{owner}/{repo}/b/{branch}` | Same, resolved to the branch head |

---

## Authentication & OAuth

Auth is disabled by default. Enable it by setting `auth_enabled = true` in
`config.toml` and configuring OAuth credentials for at least one provider.

### How it works

1. Dashboards for **public** repos are accessible without login (verified via
   an anonymous API call to the forge).
2. Dashboards for **private** repos redirect browser requests to the
   provider's OAuth login. API/JSON requests receive `401 Unauthorized`.
3. After login, covsrv checks repo access via the provider's API. The result
   is cached for `auth_cache_ttl` seconds.
4. Users without access receive `403 Forbidden`.

### OAuth callback URLs

When creating an OAuth application on your forge, set the callback URL to:

```
{public_url}/auth/{provider_name}/callback
```

For example, if `public_url = "https://coverage.example.com"` and the provider
is named `github` in your config:

```
https://coverage.example.com/auth/github/callback
```

GitHub OAuth Apps request scopes `read:org` and `repo`. Gitea/Forgejo apps
request `openid`, `profile`, and `email`.

### Auth routes

| Route | Description |
|-------|-------------|
| `/auth/{provider}/login?next=/path` | Initiate OAuth login |
| `/auth/{provider}/callback` | OAuth callback (handled automatically) |
| `/auth/{provider}/logout` | Log out of a single provider |
| `/auth/logout` | Log out of all providers |

---

## Data & Backups

All persistent state lives under `$COVSRV_DATA/covsrv_data/`:

| Path | Contents |
|------|----------|
| `covsrv_data/covsrv.sqlite3` | SQLite database (WAL mode) |
| `covsrv_data/reports/` | Uploaded coverage tarballs (extracted) |

Alembic migrations are applied automatically on startup. No manual migration
steps are needed for upgrades.

To back up, snapshot the `covsrv_data/` directory (or the Docker volume).

---

## Development

### Prerequisites

- Python ≥ 3.13
- [uv](https://docs.astral.sh/uv/)

### Setup

```bash
git clone https://github.com/sevenrats/covsrv.git
cd covsrv
uv sync
```

### Running tests

```bash
uv run pytest
```

### Running locally

```bash
uvicorn main:app --reload
```

### Project structure

```
main.py                  # FastAPI application, routes, report ingestion
config.example.toml      # Annotated example configuration
compose.yml              # Docker Compose file
Dockerfile               # Container build
covsrv/
├── config.py            # TOML configuration manager
├── models.py            # SQLAlchemy ORM models
├── db.py                # Async database layer + Alembic runner
├── auth/                # OAuth & authorization
│   ├── config.py        #   Auth configuration (env-var fallback)
│   ├── provider.py      #   Abstract OAuthProvider base class
│   ├── github.py        #   GitHub provider implementation
│   ├── gitea.py         #   Gitea/Forgejo provider implementation
│   ├── dependencies.py  #   FastAPI Depends() for route protection
│   ├── session.py       #   Session read/write helpers
│   ├── cache.py         #   Short-lived authz decision cache
│   └── routes.py        #   /auth/* login/callback/logout routes
├── badges/              # SVG badge generation
│   └── badges.py        #   Colour logic, SVG rendering, caching
└── templates/           # Jinja2 HTML templates
    ├── dashboard.html   #   Coverage dashboard (charts, tables)
    └── framed_raw.html  #   Navigation frame for raw HTML reports
alembic/                 # Database migrations
tests/                   # Test suite
```