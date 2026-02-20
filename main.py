from __future__ import annotations

import asyncio
import os
import shutil
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote as _url_quote

import anyio
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import Environment, PackageLoader, select_autoescape
from sqlalchemy.exc import IntegrityError
from starlette.middleware.sessions import SessionMiddleware

from covsrv import db
from covsrv.auth import (
    AccessDenied,
    AuthenticationRequired,
    auth_router,
    load_auth_config,
    require_view_permission,
    setup_auth,
)
from covsrv.badges import badge_color, coverage_message, render_badge_svg, svg_response
from covsrv.config import ConfigManager
from covsrv.models import DEFAULT_PROVIDER_URL, BranchEvent, Report

_jinja_env = Environment(
    loader=PackageLoader("covsrv", "templates"),
    autoescape=select_autoescape(["html"]),
)

# ----------------------------
# Configuration
# ----------------------------

BASE_DIR = Path(os.environ.get("COVSRV_DATA", ".")).resolve()

DATA_DIR = BASE_DIR / "covsrv_data"
REPORTS_DIR = DATA_DIR / "reports"  # stored per repo/hash (immutable for a sha)
DB_PATH = DATA_DIR / "covsrv.sqlite3"

TOKEN_HASH = "$argon2id$v=19$m=65536,t=3,p=4$nxSTXtitRlXKAuwz1PxVWQ$G+XQZgF+DURfAptK/v3zFjjO9vzexX1bQ/jxPAcAYBY"
ph = PasswordHasher()

# Module-level ConfigManager (populated during lifespan)
config_manager: ConfigManager | None = None


def _resolve_config_path() -> Path:
    """Return the resolved TOML config file path.

    ``COVSRV_CONF`` may point to either a file or a directory.  When it
    is a directory we look for ``config.toml`` inside it.
    """
    raw = os.environ.get("COVSRV_CONF", "")
    if raw:
        p = Path(raw)
        if p.is_dir():
            return p / "config.toml"
        return p
    return BASE_DIR / "config.toml"


DEFAULT_WORST_FILES = 12
DEFAULT_PIE_FILES = 12
TREND_LIMIT = 200

# ----------------------------
# DTOs (no Pydantic)
# ----------------------------


def normalize_repo_full(repo_full: str) -> str:
    r = repo_full.strip().strip("/")
    if not r or "/" not in r:
        raise HTTPException(status_code=422, detail="repo must look like 'owner/name'")
    owner, name = r.split("/", 1)
    if not owner.strip() or not name.strip():
        raise HTTPException(status_code=422, detail="repo must look like 'owner/name'")
    return f"{owner.strip()}/{name.strip()}"


def normalize_owner_repo(owner: str, repo: str) -> tuple[str, str, str]:
    if not isinstance(owner, str) or not owner.strip():
        raise HTTPException(status_code=422, detail="owner must be a non-empty string")
    if not isinstance(repo, str) or not repo.strip():
        raise HTTPException(status_code=422, detail="repo must be a non-empty string")
    owner_s = owner.strip().strip("/")
    repo_s = repo.strip().strip("/")
    full = normalize_repo_full(f"{owner_s}/{repo_s}")
    return owner_s, repo_s, full


def normalize_sha(sha: str) -> str:
    if not isinstance(sha, str) or not sha.strip():
        raise HTTPException(status_code=422, detail="sha must be a non-empty string")
    s = sha.strip()
    # keep it permissive but sane; you can tighten if you only want hex/40
    if len(s) < 7:
        raise HTTPException(status_code=422, detail="sha looks too short")
    return s


@dataclass(frozen=True, slots=True)
class ReportIngestDTO:
    owner: str
    repo: str
    repo_full: str
    branch: str
    sha: str
    provider_name: str
    provider_url: str  # derived from config

    @classmethod
    def from_form(
        cls,
        owner: str,
        repo: str,
        branch: str,
        sha: str,
        provider_name: str,
        provider_url: str = DEFAULT_PROVIDER_URL,
    ) -> "ReportIngestDTO":
        owner_s, repo_s, repo_full = normalize_owner_repo(owner, repo)

        if not isinstance(branch, str) or not branch.strip():
            raise HTTPException(
                status_code=422, detail="branch must be a non-empty string"
            )
        branch_s = branch.strip()

        sha_s = normalize_sha(sha)

        pname = provider_name.strip() if isinstance(provider_name, str) else ""

        purl = (
            provider_url.strip().rstrip("/")
            if isinstance(provider_url, str) and provider_url.strip()
            else DEFAULT_PROVIDER_URL
        )

        return cls(
            owner=owner_s,
            repo=repo_s,
            repo_full=repo_full,
            branch=branch_s,
            sha=sha_s,
            provider_name=pname,
            provider_url=purl,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ----------------------------
# Auth helpers
# ----------------------------


def extract_token(authorization: str | None, x_access_token: str | None) -> str:
    if x_access_token:
        return x_access_token.strip()
    if authorization:
        parts = authorization.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
    raise HTTPException(status_code=401, detail="Missing token")


def verify_token(token: str) -> None:
    try:
        if not ph.verify(TOKEN_HASH, token):
            raise HTTPException(status_code=401, detail="Invalid token")
    except VerifyMismatchError:
        raise HTTPException(status_code=401, detail="Invalid token")


def verify_report_access(token: str, provider_name: str, owner: str, repo: str) -> None:
    """Verify *token* is authorised to post a report.

    Uses the ``ConfigManager`` (hierarchical keys) when a config file is
    loaded.  Falls back to the legacy argon2 ``TOKEN_HASH`` otherwise.
    """
    if config_manager is not None:
        if config_manager.verify_report_key(token, provider_name, owner, repo):
            return
        raise HTTPException(status_code=401, detail="Invalid report key")

    # Legacy fallback: single global token hash
    verify_token(token)


# ----------------------------
# Storage helpers
# ----------------------------


async def init_dirs() -> None:
    await anyio.Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
    await anyio.Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)


def repo_to_fs(repo_full: str) -> str:
    return repo_full.replace("/", "__")


def repo_from_owner_name(owner: str, name: str) -> str:
    return normalize_repo_full(f"{owner}/{name}")


def safe_join_under(base: Path, rel: str) -> Path:
    rel_path = Path(rel)
    if ".." in rel_path.parts:
        raise HTTPException(status_code=400, detail="invalid path")
    full = (base / rel_path).resolve()
    base_resolved = base.resolve()
    if full == base_resolved:
        return full
    if not str(full).startswith(str(base_resolved) + os.sep):
        raise HTTPException(status_code=400, detail="invalid path")
    return full


def safe_extract_tar(tar_path: Path, dest_dir: Path) -> None:
    """Extract tar safely (prevent path traversal)."""
    dest = dest_dir.resolve()
    with tarfile.open(tar_path, "r:*") as tf:
        for member in tf.getmembers():
            member_path = (dest / member.name).resolve()
            if (
                not str(member_path).startswith(str(dest) + os.sep)
                and member_path != dest
            ):
                raise HTTPException(status_code=400, detail="tar contains unsafe paths")
        tf.extractall(dest, filter="data")


# ----------------------------
# Lifespan (async startup)
# ----------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    global config_manager

    await init_dirs()
    db.configure(DB_PATH)
    await db.init_db()

    # Load declarative config if available
    config_path = _resolve_config_path()
    if config_path.is_file():
        config_manager = ConfigManager.from_file(config_path)
    else:
        config_manager = None

    await setup_auth(config_manager)
    yield


# ----------------------------
# Cobertura XML parsing (coverage.xml)
# ----------------------------


@dataclass(frozen=True, slots=True)
class XmlFileStat:
    filename: str
    percent_covered: float
    uncovered_lines: int


def parse_coverage_xml(xml_path: Path) -> tuple[float, list[XmlFileStat]]:
    """Reads overall percent + per-file stats from Cobertura coverage.xml."""
    try:
        root = ET.fromstring(xml_path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        raise HTTPException(
            status_code=400, detail=f"Failed to parse coverage.xml: {e}"
        )

    overall = 0.0
    lr = root.attrib.get("line-rate")
    if lr is not None:
        try:
            overall = float(lr) * 100.0
        except Exception:
            overall = 0.0

    stats: dict[str, dict[str, Any]] = {}
    for cls in root.findall(".//class"):
        fn = cls.attrib.get("filename")
        if not fn:
            continue

        plc = 0.0
        clr = cls.attrib.get("line-rate")
        if clr is not None:
            try:
                plc = float(clr) * 100.0
            except Exception:
                plc = 0.0

        uncovered = 0
        for ln in cls.findall(".//line"):
            hits = ln.attrib.get("hits")
            if hits is not None and hits.strip() == "0":
                uncovered += 1

        cur = stats.get(fn)
        if cur is None:
            stats[fn] = {"percent": plc, "uncovered": uncovered}
        else:
            cur["percent"] = min(cur["percent"], plc)
            cur["uncovered"] += uncovered

    files = [
        XmlFileStat(
            filename=k, percent_covered=v["percent"], uncovered_lines=v["uncovered"]
        )
        for k, v in stats.items()
    ]
    return overall, files


# ----------------------------
# App setup
# ----------------------------

app = FastAPI(
    title="Coverage Server + Dashboard (single report ingest)",
    version="7.0",
    lifespan=lifespan,
)

# Session middleware (required for OAuth flows)
# Read session settings from the TOML config (if available) so the middleware
# uses the correct secret and https flag.  Env-var config is the fallback.
_config_path = _resolve_config_path()
if _config_path.is_file():
    _boot_cfg = ConfigManager.from_file(_config_path)
    _session_secret = _boot_cfg.global_config.session_secret
    _https_only = _boot_cfg.global_config.public_url.startswith("https://")
else:
    _boot_auth = load_auth_config()
    _session_secret = _boot_auth.session_secret
    _https_only = _boot_auth.public_app_url.startswith("https://")

app.add_middleware(
    SessionMiddleware,  # type: ignore[arg-type]  # Starlette typing limitation
    secret_key=_session_secret,
    same_site="lax",
    https_only=_https_only,
    max_age=14 * 24 * 60 * 60,  # 14 days
)


# Prevent browsers from caching auth-protected responses.  Without this,
# the browser may serve a stale cached page after logout, making it look
# like the session was never invalidated.
@app.middleware("http")
async def _no_cache_protected_responses(
    request: Request,
    call_next,  # noqa: ANN001
) -> Response:
    from covsrv.auth import auth_state

    response = await call_next(request)
    # Only add the header when auth is enabled and no explicit
    # Cache-Control was already set (e.g. badge routes set their own).
    cfg = auth_state.config
    if cfg is not None and cfg.enabled and "Cache-Control" not in response.headers:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    return response


# Auth routes (/auth/{provider}/login, /auth/{provider}/callback, etc.)
app.include_router(auth_router)


@app.exception_handler(AuthenticationRequired)
async def _auth_required_redirect(
    request: Request, exc: AuthenticationRequired
) -> RedirectResponse:
    login_url = f"/auth/{exc.provider}/login?next={_url_quote(exc.next_url, safe='')}"
    return RedirectResponse(url=login_url, status_code=307)


@app.exception_handler(AccessDenied)
async def _access_denied_page(
    request: Request,
    exc: AccessDenied,  # noqa: ARG001
) -> HTMLResponse:
    template = _jinja_env.get_template("access_denied.html")
    html = template.render(owner=exc.owner, name=exc.name)
    return HTMLResponse(content=html, status_code=403)


# Convenience alias used as a route-level dependency on protected endpoints.
_authn = [Depends(require_view_permission)]

# ----------------------------
# NEW: Single reports ingest endpoint
# ----------------------------


@app.post("/reports")
async def ingest_report(
    owner: str = Form(...),
    repo: str = Form(...),
    branch: str = Form(...),
    sha: str = Form(...),
    provider: str = Form(default=""),
    provider_url: str = Form(default=""),
    tarball: UploadFile = File(
        ...
    ),  # expects .tar.gz with HTML + coverage.xml at top of html dir
    authorization: str | None = Header(default=None),
    x_access_token: str | None = Header(default=None, convert_underscores=False),
) -> dict[str, Any]:
    token = extract_token(authorization, x_access_token)

    # Resolve provider name → URL from config, or accept raw URL for legacy
    pname = provider.strip() if provider else ""
    purl = provider_url.strip().rstrip("/") if provider_url else ""

    if config_manager is not None:
        # Config-driven mode: provider name is required
        if not pname:
            raise HTTPException(
                status_code=422,
                detail="'provider' field is required when a config file is loaded",
            )
        entry = config_manager.get_provider(pname)
        if entry is None:
            raise HTTPException(
                status_code=422,
                detail=f"Unknown provider: {pname!r}",
            )
        purl = entry.url
    else:
        # Legacy mode: fall back to provider_url if no name given
        if not pname:
            pname = ""
        if not purl:
            purl = DEFAULT_PROVIDER_URL

    verify_report_access(token, pname, owner.strip(), repo.strip())

    dto = ReportIngestDTO.from_form(owner, repo, branch, sha, pname, purl)
    received_ts = int(time.time())

    repo_fs = repo_to_fs(dto.repo_full)

    # Immutable location: reports/<repo>/h/<sha>/
    report_dir = REPORTS_DIR / repo_fs / "h" / dto.sha
    if await anyio.Path(report_dir).exists():
        # preserve "original" report for that commit hash
        raise HTTPException(
            status_code=409, detail="Report for this (repo, sha) already exists"
        )

    await anyio.Path(report_dir).mkdir(parents=True, exist_ok=True)
    html_dir = report_dir / "html"
    await anyio.Path(html_dir).mkdir(parents=True, exist_ok=True)

    # save upload to temp file then extract safely
    with tempfile.TemporaryDirectory(prefix="covsrv_upload_") as tmp:
        tmp_path = Path(tmp)
        tar_path = tmp_path / "artifact.tar.gz"

        try:
            async with await anyio.open_file(tar_path, "wb") as f:
                while True:
                    chunk = await tarball.read(1024 * 1024)
                    if not chunk:
                        break
                    await f.write(chunk)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to read upload: {e}")

        await asyncio.to_thread(safe_extract_tar, tar_path, html_dir)

    # required: coverage.xml must be inside extracted html dir
    xml_path = html_dir / "coverage.xml"
    if not await anyio.Path(xml_path).exists():
        # cleanup the partially created report_dir
        shutil.rmtree(report_dir, ignore_errors=True)
        raise HTTPException(
            status_code=400,
            detail="Tarball must contain coverage.xml at the top of the HTML directory",
        )

    overall_percent, _ = await asyncio.to_thread(parse_coverage_xml, xml_path)

    # DB: insert report + update branch head + add branch event
    async with db.session() as sess:
        report = Report(
            repo=dto.repo_full,
            branch_name=dto.branch,
            git_hash=dto.sha,
            received_ts=received_ts,
            overall_percent=overall_percent,
            report_dir=str(report_dir),
            provider_url=dto.provider_url,
            provider_name=dto.provider_name,
        )
        sess.add(report)
        try:
            await sess.flush()
        except IntegrityError:
            # unique (repo, sha) collision (race)
            shutil.rmtree(report_dir, ignore_errors=True)
            raise HTTPException(
                status_code=409, detail="Report for this (repo, sha) already exists"
            )

        sess.add(
            BranchEvent(
                repo=dto.repo_full,
                branch_name=dto.branch,
                git_hash=dto.sha,
                updated_ts=received_ts,
            )
        )
        await db.upsert_branch_head(
            sess, dto.repo_full, dto.branch, dto.sha, received_ts
        )
        await db.upsert_repo_seen(sess, dto.repo_full, received_ts)

    return {
        "status": "ok",
        "owner": dto.owner,
        "repo": dto.repo,
        "branch": dto.branch,
        "sha": dto.sha,
        "received_ts": received_ts,
        "overall_percent": overall_percent,
        "hash_dashboard_url": f"/{dto.owner}/{dto.repo}/h/{dto.sha}",
        "hash_chart_url": f"/{dto.owner}/{dto.repo}/h/{dto.sha}/chart",
        "branch_dashboard_url": f"/{dto.owner}/{dto.repo}/b/{dto.branch}",
        "hash_raw_url": f"/raw/{dto.owner}/{dto.repo}/h/{dto.sha}/",
    }


# ----------------------------
# Dashboards (HTML)
# ----------------------------


def _resolve_provider_url(row: dict[str, Any] | None) -> str:
    """Resolve provider URL from a report row, preferring config lookup."""
    if row is None:
        return DEFAULT_PROVIDER_URL
    # If we have a provider_name and config, look up the URL from config
    pname = row.get("provider_name", "")
    if pname and config_manager is not None:
        entry = config_manager.get_provider(pname)
        if entry:
            return entry.url
    # Fallback to stored provider_url
    purl = row.get("provider_url", "")
    return purl if purl else DEFAULT_PROVIDER_URL


def dashboard_html_for(
    kind: str,
    repo_full: str,
    ref: str,
    provider_url: str = DEFAULT_PROVIDER_URL,
) -> str:
    owner, name = repo_full.split("/", 1)
    base = provider_url.rstrip("/") if provider_url else DEFAULT_PROVIDER_URL
    github_url = f"{base}/{owner}/{name}"

    if kind == "h":
        raw_url = f"/{owner}/{name}/h/"
        trend_url = f"/api/{owner}/{name}/h/{ref}/trend"
        uncovered_url = f"/api/{owner}/{name}/h/{ref}/latest/uncovered-lines"
        download_suffix = f"/{owner}/{name}/h/{ref}"
        raw_framed_url = f"/{owner}/{name}/h/{ref}"
    else:
        raw_url = f"/{owner}/{name}/h/"
        trend_url = f"/api/{owner}/{name}/b/{ref}/trend"
        uncovered_url = f"/api/{owner}/{name}/b/{ref}/latest/uncovered-lines"
        download_suffix = f"/{owner}/{name}/b/{ref}"
        raw_framed_url = ""

    template = _jinja_env.get_template("dashboard.html")
    return template.render(
        raw_url=raw_url,
        trend_url=trend_url,
        uncovered_url=uncovered_url,
        download_suffix=download_suffix,
        trend_limit=TREND_LIMIT,
        pie_limit=DEFAULT_PIE_FILES,
        github_url=github_url,
        raw_framed_url=raw_framed_url,
    )


@app.get("/", response_class=HTMLResponse)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/badge/{owner}/{name}/h/{git_hash}")
async def badge_hash_svg(
    owner: str,
    name: str,
    git_hash: str,
    label: str = "coverage",
    decimals: int = 1,
) -> Response:
    repo_full = repo_from_owner_name(owner, name)
    row = await db.latest_report_for_repo_hash(repo_full, git_hash)

    percent = None if row is None else float(row["overall_percent"])
    msg = coverage_message(percent, decimals=max(0, min(int(decimals), 3)))
    color = badge_color(percent)

    svg = render_badge_svg(label=label, message=msg, color=color)

    # hash badges are immutable: can cache hard
    cache = "public, max-age=31536000, immutable"
    seed = f"h|{repo_full}|{git_hash}|{label}|{decimals}|{msg}|{color}"
    return svg_response(svg, cache_control=cache, etag_seed=seed)


@app.get("/badge/{owner}/{name}/b/{branch:path}")
async def badge_branch_svg(
    owner: str,
    name: str,
    branch: str,
    label: str = "coverage",
    decimals: int = 1,
) -> Response:
    repo_full = repo_from_owner_name(owner, name)
    head_hash = await db.latest_branch_head_hash(repo_full, branch)

    percent: float | None = None
    if head_hash is not None:
        row = await db.latest_report_for_repo_hash(repo_full, head_hash)
        if row is not None:
            percent = float(row["overall_percent"])

    msg = coverage_message(percent, decimals=max(0, min(int(decimals), 3)))
    color = badge_color(percent)
    svg = render_badge_svg(label=label, message=msg, color=color)

    # branch badges move: cache briefly
    cache = "public, max-age=60"
    seed = f"b|{repo_full}|{branch}|{head_hash}|{label}|{decimals}|{msg}|{color}"
    return svg_response(svg, cache_control=cache, etag_seed=seed)


@app.get("/{owner}/{name}/", response_class=HTMLResponse, dependencies=_authn)
async def repo_home(owner: str, name: str) -> RedirectResponse:
    return RedirectResponse(url=f"/{owner}/{name}/b/main")


@app.get(
    "/{owner}/{name}/b/{branch:path}", response_class=HTMLResponse, dependencies=_authn
)
async def repo_branch_dashboard(
    request: Request, owner: str, name: str, branch: str
) -> str:
    repo_full = repo_from_owner_name(owner, name)
    head_hash = await db.latest_branch_head_hash(repo_full, branch)
    row = None
    if head_hash:
        row = await db.latest_report_for_repo_hash(repo_full, head_hash)
    provider_url = _resolve_provider_url(row)
    return dashboard_html_for(
        "b",
        repo_full,
        branch,
        provider_url=provider_url,
    )


# ----------------------------
# Raw HTML reports at /raw/... (served as-is from disk)
# ----------------------------


def report_html_root_for_hash(repo_full: str, git_hash: str) -> Path:
    repo_fs = repo_to_fs(repo_full)
    return REPORTS_DIR / repo_fs / "h" / git_hash / "html"


@app.get("/raw/{owner}/{name}/h/{git_hash}", dependencies=_authn)
async def raw_hash_redirect(owner: str, name: str, git_hash: str) -> RedirectResponse:
    return RedirectResponse(url=f"/raw/{owner}/{name}/h/{git_hash}/", status_code=307)


@app.get("/raw/{owner}/{name}/h/{git_hash}/", dependencies=_authn)
async def raw_hash_index(owner: str, name: str, git_hash: str) -> FileResponse:
    repo_full = repo_from_owner_name(owner, name)
    root = report_html_root_for_hash(repo_full, git_hash)
    index = root / "index.html"
    if not await anyio.Path(index).exists():
        raise HTTPException(status_code=404, detail="No raw report for this hash")
    return FileResponse(path=str(index))


@app.get("/raw/{owner}/{name}/h/{git_hash}/{path:path}", dependencies=_authn)
async def raw_hash_file(
    owner: str, name: str, git_hash: str, path: str
) -> FileResponse:
    repo_full = repo_from_owner_name(owner, name)
    root = report_html_root_for_hash(repo_full, git_hash)

    p = safe_join_under(root, path)
    ap = anyio.Path(p)
    if not await ap.exists() or not await ap.is_file():
        raise HTTPException(status_code=404, detail="Not found")

    return FileResponse(path=str(p))


# ----------------------------
# Framed raw view (nav bar + iframe)
# ----------------------------


def framed_html_for(
    repo_full: str,
    git_hash: str,
    provider_url: str = DEFAULT_PROVIDER_URL,
) -> str:
    owner, name = repo_full.split("/", 1)
    base = provider_url.rstrip("/") if provider_url else DEFAULT_PROVIDER_URL
    github_url = f"{base}/{owner}/{name}"
    chart_url = f"/{owner}/{name}/h/{git_hash}/chart"
    raw_src = f"/raw/{owner}/{name}/h/{git_hash}/"

    template = _jinja_env.get_template("framed_raw.html")
    return template.render(
        github_url=github_url,
        chart_url=chart_url,
        raw_src=raw_src,
    )


@app.get(
    "/{owner}/{name}/h/{git_hash}", response_class=HTMLResponse, dependencies=_authn
)
async def repo_hash_framed(
    request: Request, owner: str, name: str, git_hash: str
) -> str:
    repo_full = repo_from_owner_name(owner, name)
    row = await db.latest_report_for_repo_hash(repo_full, git_hash)
    provider_url = _resolve_provider_url(row)
    return framed_html_for(
        repo_full,
        git_hash,
        provider_url=provider_url,
    )


@app.get(
    "/{owner}/{name}/h/{git_hash}/chart",
    response_class=HTMLResponse,
    dependencies=_authn,
)
async def repo_hash_chart(
    request: Request, owner: str, name: str, git_hash: str
) -> str:
    repo_full = repo_from_owner_name(owner, name)
    row = await db.latest_report_for_repo_hash(repo_full, git_hash)
    provider_url = _resolve_provider_url(row)
    return dashboard_html_for(
        "h",
        repo_full,
        git_hash,
        provider_url=provider_url,
    )


# ----------------------------
# Downloads (token-based)
# ----------------------------


async def report_html_root_for_branch(repo_full: str, branch: str) -> Path:
    head_hash = await db.latest_branch_head_hash(repo_full, branch)
    if head_hash is None:
        raise HTTPException(
            status_code=404, detail="No branch head for this branch yet"
        )
    return report_html_root_for_hash(repo_full, head_hash)


def tar_gz_dir(src_dir: Path, out_path: Path) -> None:
    with tarfile.open(out_path, "w:gz") as tf:
        for p in src_dir.rglob("*"):
            if p.is_file():
                tf.add(p, arcname=str(p.relative_to(src_dir)))


async def resolve_download_token(root: Path, token: str) -> tuple[str, Path]:
    """
    Maps token -> actual file or directory.
    Returns (kind, path) where kind is "file" or "archive".
    """

    token = token.lower().strip()

    TOKENS: dict[str, str] = {
        "json": "coverage.json",
        "lcov": "coverage.lcov",
        "xml": "coverage.xml",
    }

    fname = TOKENS.get(token)
    if fname is None:
        raise HTTPException(status_code=404, detail="Unknown download token")

    p = root / fname
    if not await anyio.Path(p).exists():
        raise HTTPException(status_code=404, detail=f"{fname} not found")
    return "file", p


@app.get("/download/{token}/{owner}/{name}/h/{git_hash}", dependencies=_authn)
async def hash_download_token(owner: str, name: str, git_hash: str, token: str):
    repo_full = repo_from_owner_name(owner, name)
    root = report_html_root_for_hash(repo_full, git_hash)

    if not await anyio.Path(root).exists():
        raise HTTPException(status_code=404, detail="No report for this hash")

    kind, target = await resolve_download_token(root, token)

    if kind == "file":
        return FileResponse(path=str(target), filename=target.name)

    # archive (html)
    with tempfile.NamedTemporaryFile(
        prefix="covsrv_", suffix=".tar.gz", delete=False
    ) as tmp:
        tmp_path = Path(tmp.name)

    await asyncio.to_thread(tar_gz_dir, target, tmp_path)

    filename = f"{repo_to_fs(repo_full)}-h-{git_hash}-html.tar.gz"

    return FileResponse(
        path=str(tmp_path),
        media_type="application/gzip",
        filename=filename,
    )


@app.get("/download/{token}/{owner}/{name}/b/{branch:path}", dependencies=_authn)
async def branch_download_token(owner: str, name: str, branch: str, token: str):
    repo_full = repo_from_owner_name(owner, name)
    root = await report_html_root_for_branch(repo_full, branch)

    if not await anyio.Path(root).exists():
        raise HTTPException(status_code=404, detail="No report for this branch head")

    kind, target = await resolve_download_token(root, token)

    if kind == "file":
        return FileResponse(path=str(target), filename=target.name)

    with tempfile.NamedTemporaryFile(
        prefix="covsrv_", suffix=".tar.gz", delete=False
    ) as tmp:
        tmp_path = Path(tmp.name)

    await asyncio.to_thread(tar_gz_dir, target, tmp_path)

    safe_branch = branch.replace("/", "_")
    filename = f"{repo_to_fs(repo_full)}-b-{safe_branch}-html.tar.gz"

    return FileResponse(
        path=str(tmp_path),
        media_type="application/gzip",
        filename=filename,
    )


# ----------------------------
# APIs (hash)
# ----------------------------


@app.get("/api/{owner}/{name}/h/{git_hash}/trend", dependencies=_authn)
async def api_repo_hash_trend(
    owner: str, name: str, git_hash: str, limit: int = TREND_LIMIT
) -> JSONResponse:
    repo_full = repo_from_owner_name(owner, name)
    limit = max(1, min(int(limit), 2000))
    points = await db.reports_trend_for_repo_hash(repo_full, git_hash, limit)
    return JSONResponse(
        {"repo": repo_full, "kind": "hash", "ref": git_hash, "points": points}
    )


async def latest_stats_from_xml(report_dir: Path) -> tuple[float, list[XmlFileStat]]:
    xml_path = report_dir / "html" / "coverage.xml"
    if not await anyio.Path(xml_path).exists():
        return 0.0, []
    return await asyncio.to_thread(parse_coverage_xml, xml_path)


@app.get("/api/{owner}/{name}/h/{git_hash}/latest/worst-files", dependencies=_authn)
async def api_repo_hash_latest_worst_files(
    owner: str, name: str, git_hash: str, limit: int = DEFAULT_WORST_FILES
) -> JSONResponse:
    repo_full = repo_from_owner_name(owner, name)
    limit = max(1, min(int(limit), 200))

    row = await db.latest_report_for_repo_hash(repo_full, git_hash)
    if row is None:
        return JSONResponse({"latest": None, "files": []})

    _, files = await latest_stats_from_xml(Path(row["report_dir"]))
    files_sorted = sorted(files, key=lambda x: x.percent_covered)[:limit]

    return JSONResponse(
        {
            "latest": {
                "repo": repo_full,
                "git_hash": row["git_hash"],
                "received_ts": int(row["received_ts"]),
                "overall_percent": float(row["overall_percent"]),
            },
            "files": [
                {"filename": f.filename, "percent_covered": float(f.percent_covered)}
                for f in files_sorted
            ],
        }
    )


@app.get("/api/{owner}/{name}/h/{git_hash}/latest/uncovered-lines", dependencies=_authn)
async def api_repo_hash_latest_uncovered_lines(
    owner: str, name: str, git_hash: str, limit: int = DEFAULT_PIE_FILES
) -> JSONResponse:
    repo_full = repo_from_owner_name(owner, name)
    limit = max(1, min(int(limit), 200))

    row = await db.latest_report_for_repo_hash(repo_full, git_hash)
    if row is None:
        return JSONResponse({"latest": None, "files": []})

    _, files = await latest_stats_from_xml(Path(row["report_dir"]))
    files_sorted = sorted(files, key=lambda x: x.uncovered_lines, reverse=True)[:limit]

    return JSONResponse(
        {
            "latest": {
                "repo": repo_full,
                "git_hash": row["git_hash"],
                "received_ts": int(row["received_ts"]),
                "overall_percent": float(row["overall_percent"]),
            },
            "files": [
                {"filename": f.filename, "uncovered_lines": int(f.uncovered_lines)}
                for f in files_sorted
            ],
        }
    )


# ----------------------------
# APIs (branch)
# ----------------------------


@app.get("/api/{owner}/{name}/b/{branch:path}/trend", dependencies=_authn)
async def api_repo_branch_trend(
    owner: str, name: str, branch: str, limit: int = TREND_LIMIT
) -> JSONResponse:
    repo_full = repo_from_owner_name(owner, name)
    limit = max(1, min(int(limit), 2000))

    evs = await db.branch_events_for(repo_full, branch, limit)
    hash_ts_pairs = [(e["git_hash"], int(e["updated_ts"])) for e in evs]
    points = await db.report_percent_for_hashes(repo_full, hash_ts_pairs)

    return JSONResponse(
        {"repo": repo_full, "kind": "branch", "ref": branch, "points": points}
    )


@app.get("/api/{owner}/{name}/b/{branch:path}/latest/worst-files", dependencies=_authn)
async def api_repo_branch_latest_worst_files(
    owner: str, name: str, branch: str, limit: int = DEFAULT_WORST_FILES
) -> JSONResponse:
    repo_full = repo_from_owner_name(owner, name)
    limit = max(1, min(int(limit), 200))

    head_hash = await db.latest_branch_head_hash(repo_full, branch)
    if head_hash is None:
        return JSONResponse({"latest": None, "files": []})

    row = await db.latest_report_for_repo_hash(repo_full, head_hash)
    if row is None:
        return JSONResponse({"latest": None, "files": []})

    _, files = await latest_stats_from_xml(Path(row["report_dir"]))
    files_sorted = sorted(files, key=lambda x: x.percent_covered)[:limit]

    return JSONResponse(
        {
            "latest": {
                "repo": repo_full,
                "git_hash": row["git_hash"],
                "received_ts": int(row["received_ts"]),
                "overall_percent": float(row["overall_percent"]),
            },
            "files": [
                {"filename": f.filename, "percent_covered": float(f.percent_covered)}
                for f in files_sorted
            ],
        }
    )


@app.get(
    "/api/{owner}/{name}/b/{branch:path}/latest/uncovered-lines", dependencies=_authn
)
async def api_repo_branch_latest_uncovered_lines(
    owner: str, name: str, branch: str, limit: int = DEFAULT_PIE_FILES
) -> JSONResponse:
    repo_full = repo_from_owner_name(owner, name)
    limit = max(1, min(int(limit), 200))

    head_hash = await db.latest_branch_head_hash(repo_full, branch)
    if head_hash is None:
        return JSONResponse({"latest": None, "files": []})

    row = await db.latest_report_for_repo_hash(repo_full, head_hash)
    if row is None:
        return JSONResponse({"latest": None, "files": []})

    _, files = await latest_stats_from_xml(Path(row["report_dir"]))
    files_sorted = sorted(files, key=lambda x: x.uncovered_lines, reverse=True)[:limit]

    return JSONResponse(
        {
            "latest": {
                "repo": repo_full,
                "git_hash": row["git_hash"],
                "received_ts": int(row["received_ts"]),
                "overall_percent": float(row["overall_percent"]),
            },
            "files": [
                {"filename": f.filename, "uncovered_lines": int(f.uncovered_lines)}
                for f in files_sorted
            ],
        }
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
