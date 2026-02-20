[![Coverage](https://coverage.crandall.codes/badge/sevenrats/covsrv/b/main)](https://coverage.crandall.codes/sevenrats/covsrv/b/main)

# covsrv

A lightweight, self-hosted **code-coverage server** and dashboard. Ingest
[Cobertura XML](https://cobertura.github.io/cobertura/) reports from any CI
pipeline, browse interactive HTML coverage reports, track trends per branch,
and embed live SVG badges in your READMEs — all without sending your data to a
third-party service.

## Features

- **Single-endpoint report ingestion** — push a `.tar.gz` containing your HTML
  report and `coverage.xml` from any CI system.
- **SVG coverage badges** — shields.io-style badges for any branch or commit,
  perfect for README files.
- **Interactive dashboards** — per-branch and per-commit HTML views with
  coverage trend charts, worst-file lists, and uncovered-line breakdowns.
- **Raw report hosting** — serves the original HTML report (e.g. `coverage html`)
  directly, framed inside a lightweight navigation shell.
- **Downloadable artifacts** — download `coverage.xml`, `coverage.json`, or
  `coverage.lcov` for any commit or branch head.
- **OAuth access control** — optional GitHub and Gitea/Forgejo OAuth so private
  repo coverage is only visible to collaborators.
- **SQLite + Alembic** — zero-dependency database with automatic migrations.
- **Docker-first deployment** — single container, single volume, ready to run.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Badge Usage](#badge-usage)
- [Report Ingestion](#report-ingestion)
- [Dashboards & API](#dashboards--api)
- [Authentication & OAuth](#authentication--oauth)
- [Configuration Reference](#configuration-reference)
- [Deployment](#deployment)
- [Development](#development)
- [Roadmap](#roadmap)
- [License](#license)

---

## Quick Start

### Docker Compose (recommended)

```yaml
# compose.yml
services:
  covsrv:
    image: ghcr.io/sevenrats/covsrv:latest
    ports:
      - "8000:8000"
    environment:
      COVSRV_DATA: /data
    volumes:
      - covsrv_data:/data
    restart: unless-stopped

volumes:
  covsrv_data:
```

```bash
docker compose up -d
```

The server is now available at **http://localhost:8000**. The interactive API
docs live at `/docs`.

### Run locally (development)

```bash
# Requires Python ≥ 3.13 and uv
uv sync
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Badge Usage

Embed a live coverage badge in your README or wiki. The SVG is generated
server-side using shields.io-style colours:

| Coverage | Colour |
|----------|--------|
| ≥ 90 %   | ![green](https://img.shields.io/badge/coverage-90%25-brightgreen) |
| 75 – 89 % | ![yellow](https://img.shields.io/badge/coverage-80%25-yellow) |
| 50 – 74 % | ![orange](https://img.shields.io/badge/coverage-60%25-orange) |
| < 50 %   | ![red](https://img.shields.io/badge/coverage-30%25-red) |

### Branch badge (tracks the branch head — updates on every push)

```
https://YOUR_HOST/badge/{owner}/{repo}/b/{branch}
```

**Markdown example:**

```markdown
[![Coverage](https://coverage.example.com/badge/myorg/myrepo/b/main)](https://coverage.example.com/myorg/myrepo/b/main)
```

### Commit badge (immutable — permanently cached)

```
https://YOUR_HOST/badge/{owner}/{repo}/h/{sha}
```

### Query parameters

| Param | Default | Description |
|-------|---------|-------------|
| `label` | `coverage` | Left-hand text on the badge |
| `decimals` | `1` | Decimal places shown (0–3) |

**Example with custom label:**

```
https://coverage.example.com/badge/myorg/myrepo/b/main?label=cov&decimals=2
```

> **Tip:** Branch badges use `Cache-Control: max-age=60` so CDNs and browsers
> pick up changes quickly. Commit badges are cached immutably
> (`max-age=31536000, immutable`).

---

## Report Ingestion

### `POST /reports`

Upload a `.tar.gz` archive containing your HTML coverage report **with a
`coverage.xml` (Cobertura format) at the top level** of the HTML directory.

#### Form fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `owner` | ✅ | — | Repository owner / org (e.g. `myorg`) |
| `repo` | ✅ | — | Repository name (e.g. `myrepo`) |
| `branch` | ✅ | — | Branch name (e.g. `main`) |
| `sha` | ✅ | — | Full or abbreviated commit SHA (≥ 7 chars) |
| `provider_url` | — | `https://github.com` | Git forge base URL |
| `tarball` | ✅ | — | `.tar.gz` file upload |

#### Authentication

Every ingest request must include a bearer token:

```
Authorization: Bearer <TOKEN>
```

or alternatively:

```
X-Access-Token: <TOKEN>
```

#### curl example

```bash
# 1. Generate HTML + coverage.xml
pytest --cov --cov-report=html --cov-report=xml

# 2. Package into a tarball
tar czf coverage.tar.gz -C htmlcov .

# 3. Upload
curl -X POST https://coverage.example.com/reports \
  -H "Authorization: Bearer $COVSRV_TOKEN" \
  -F owner=myorg \
  -F repo=myrepo \
  -F branch=main \
  -F sha=$(git rev-parse HEAD) \
  -F tarball=@coverage.tar.gz
```

#### GitHub Actions example

```yaml
- name: Upload coverage to covsrv
  run: |
    tar czf coverage.tar.gz -C htmlcov .
    curl -X POST ${{ secrets.COVSRV_URL }}/reports \
      -H "Authorization: Bearer ${{ secrets.COVSRV_TOKEN }}" \
      -F owner=${{ github.repository_owner }} \
      -F repo=${{ github.event.repository.name }} \
      -F branch=${{ github.ref_name }} \
      -F sha=${{ github.sha }} \
      -F tarball=@coverage.tar.gz
```

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

> Reports are **immutable per commit SHA** — a second upload for the same
> `(repo, sha)` pair returns `409 Conflict`.

---

## Dashboards & API

### Web dashboards

| URL pattern | Description |
|-------------|-------------|
| `/{owner}/{repo}/` | Redirects to the `main` branch dashboard |
| `/{owner}/{repo}/b/{branch}` | Branch dashboard — trend chart, worst files, uncovered lines |
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

| URL pattern | Description |
|-------------|-------------|
| `/download/xml/{owner}/{repo}/h/{sha}` | Download `coverage.xml` for a commit |
| `/download/json/{owner}/{repo}/h/{sha}` | Download `coverage.json` for a commit |
| `/download/lcov/{owner}/{repo}/h/{sha}` | Download `coverage.lcov` for a commit |
| `/download/{token}/{owner}/{repo}/b/{branch}` | Same, but resolved to the branch head |

---

## Authentication & OAuth

**Auth is disabled by default.** All dashboards, badges, and APIs are publicly
accessible. To protect private-repo coverage data, enable OAuth.

### How it works

1. Set `COVSRV_AUTH_ENABLED=true` and configure at least one OAuth provider.
2. When a user visits a dashboard for a **public** repo, access is granted
   without login (verified via an anonymous API call to the forge).
3. When a user visits a dashboard for a **private** repo:
   - **Browser** → redirected to the provider's OAuth login.
   - **API / JSON** → receives `401 Unauthorized`.
4. After login, covsrv checks whether the user can view the repo via the
   provider's API. The result is cached for `COVSRV_AUTH_CACHE_TTL` seconds.
5. If the user cannot access the repo, they receive `404 Not Found` (to avoid
   leaking the repo's existence).

### Supported providers

#### GitHub

```env
COVSRV_AUTH_ENABLED=true
COVSRV_SESSION_SECRET=<random-secret>
COVSRV_PUBLIC_URL=https://coverage.example.com

COVSRV_GITHUB_CLIENT_ID=<your-github-oauth-app-client-id>
COVSRV_GITHUB_CLIENT_SECRET=<your-github-oauth-app-client-secret>
```

Create a GitHub OAuth App at
**Settings → Developer settings → OAuth Apps** with the callback URL:

```
https://coverage.example.com/auth/github/callback
```

Requested scopes: `read:org`, `repo` (allows checking private repo access).

#### Gitea / Forgejo

```env
COVSRV_AUTH_ENABLED=true
COVSRV_SESSION_SECRET=<random-secret>
COVSRV_PUBLIC_URL=https://coverage.example.com

COVSRV_GITEA_URL=https://gitea.example.com
COVSRV_GITEA_CLIENT_ID=<your-gitea-oauth-app-client-id>
COVSRV_GITEA_CLIENT_SECRET=<your-gitea-oauth-app-client-secret>
```

Create an OAuth2 application in your Gitea/Forgejo instance at
**Site Administration → Applications** (or user-level settings) with the
callback URL:

```
https://coverage.example.com/auth/gitea/callback
```

### Multi-provider

Both GitHub and Gitea can be enabled simultaneously. covsrv maps each
repository to the correct provider based on the `provider_url` stored at
ingest time.

### Auth routes

| Route | Description |
|-------|-------------|
| `/auth/{provider}/login?next=/path` | Initiate OAuth login |
| `/auth/{provider}/callback` | OAuth callback (handled automatically) |
| `/auth/{provider}/logout` | Log out of a single provider |
| `/auth/logout` | Log out of all providers |

> **Note:** Badge endpoints (`/badge/...`) are **always public** and do not
> require authentication, regardless of auth settings.

---

## Configuration Reference

All configuration is via environment variables.

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `COVSRV_DATA` | `.` (current dir) | Base directory for data storage. Inside this directory, `covsrv_data/` holds the SQLite DB and uploaded reports. |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `COVSRV_AUTH_ENABLED` | `false` | Set to `true`, `1`, or `yes` to enable OAuth |
| `COVSRV_SESSION_SECRET` | `change-me-in-production` | Secret key for signing session cookies. **Must be changed in production.** |
| `COVSRV_AUTH_CACHE_TTL` | `60` | Seconds to cache authorization decisions |
| `COVSRV_PUBLIC_URL` | `http://localhost:8000` | Externally-reachable base URL (used for OAuth callback URLs) |

### GitHub provider

| Variable | Required | Description |
|----------|----------|-------------|
| `COVSRV_GITHUB_CLIENT_ID` | Yes | GitHub OAuth App client ID |
| `COVSRV_GITHUB_CLIENT_SECRET` | Yes | GitHub OAuth App client secret |

### Gitea / Forgejo provider

| Variable | Required | Description |
|----------|----------|-------------|
| `COVSRV_GITEA_URL` | Yes | Base URL of your Gitea instance (e.g. `https://gitea.example.com`) |
| `COVSRV_GITEA_CLIENT_ID` | Yes | Gitea OAuth2 App client ID |
| `COVSRV_GITEA_CLIENT_SECRET` | Yes | Gitea OAuth2 App client secret |

---

## Deployment

### Docker Compose (production)

```yaml
services:
  covsrv:
    image: ghcr.io/sevenrats/covsrv:latest
    ports:
      - "8000:8000"
    environment:
      COVSRV_DATA: /data
      COVSRV_AUTH_ENABLED: "true"
      COVSRV_SESSION_SECRET: "${COVSRV_SESSION_SECRET}"
      COVSRV_PUBLIC_URL: "https://coverage.example.com"
      COVSRV_GITHUB_CLIENT_ID: "${COVSRV_GITHUB_CLIENT_ID}"
      COVSRV_GITHUB_CLIENT_SECRET: "${COVSRV_GITHUB_CLIENT_SECRET}"
    volumes:
      - covsrv_data:/data
    restart: unless-stopped

volumes:
  covsrv_data:
```

### Behind a reverse proxy

covsrv is designed to sit behind a reverse proxy (Nginx, Caddy, Traefik, etc.)
that handles TLS. Make sure to:

1. Set `COVSRV_PUBLIC_URL` to the **external** URL users and OAuth callbacks
   will use (e.g. `https://coverage.example.com`).
2. Forward the `Host` header so session cookies work correctly.
3. Proxy to port `8000` on the container.

**Caddy example:**

```
coverage.example.com {
    reverse_proxy covsrv:8000
}
```

**Nginx example:**

```nginx
server {
    listen 443 ssl;
    server_name coverage.example.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Data & backups

All persistent state lives under `$COVSRV_DATA/covsrv_data/`:

| Path | Contents |
|------|----------|
| `covsrv_data/covsrv.sqlite3` | SQLite database (WAL mode) |
| `covsrv_data/reports/` | Uploaded HTML reports and coverage artifacts |

To back up, snapshot the entire `covsrv_data/` directory (or the Docker volume).

### Database migrations

Migrations are managed by **Alembic** and are applied automatically on startup.
No manual migration steps are needed for normal upgrades.

---

## Development

### Prerequisites

- Python ≥ 3.13
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Setup

```bash
git clone https://github.com/sevenrats/covsrv.git
cd covsrv
uv sync
```

### Running tests

```bash
pytest
```

### Running locally

```bash
uvicorn main:app --reload
```

### Project structure

```
main.py                  # FastAPI application, routes, report ingestion
covsrv/
├── models.py            # SQLAlchemy ORM models
├── db.py                # Async database layer
├── auth/                # OAuth & authorization
│   ├── config.py        #   Environment-based auth configuration
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

---

## Roadmap

- [ ] **API key creation & registration** — self-service key management to
      replace the single shared ingest token.
- [ ] **Scheduled cleanup task** — automatic purging of old reports and orphaned
      data.
- [ ] **Additional OAuth providers** — GitLab, Bitbucket, and generic
      OIDC support.
- [ ] **Multi-format badge output** — JSON endpoint for shields.io dynamic
      badges.
- [ ] **PR comment integration** — post coverage diffs as PR comments via
      webhooks.
- [ ] **Report diffing** — compare coverage between two commits or branches.

---

## License

See the repository for license details.