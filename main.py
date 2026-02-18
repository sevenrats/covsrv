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

import anyio
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import FastAPI, File, Form, Header, HTTPException, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.exc import IntegrityError

from covsrv import db
from covsrv.badges import badge_color, coverage_message, render_badge_svg, svg_response
from covsrv.html import CHART_VIEW
from covsrv.models import BranchEvent, Report

# ----------------------------
# Configuration
# ----------------------------

BASE_DIR = Path(os.environ.get("COVSRV_DIR", ".")).resolve()

DATA_DIR = BASE_DIR / "covsrv_data"
REPORTS_DIR = DATA_DIR / "reports"  # stored per repo/hash (immutable for a sha)
DB_PATH = DATA_DIR / "covsrv.sqlite3"

TOKEN_HASH = "$argon2id$v=19$m=65536,t=3,p=4$nxSTXtitRlXKAuwz1PxVWQ$G+XQZgF+DURfAptK/v3zFjjO9vzexX1bQ/jxPAcAYBY"
ph = PasswordHasher()

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

    @classmethod
    def from_form(
        cls, owner: str, repo: str, branch: str, sha: str
    ) -> "ReportIngestDTO":
        owner_s, repo_s, repo_full = normalize_owner_repo(owner, repo)

        if not isinstance(branch, str) or not branch.strip():
            raise HTTPException(
                status_code=422, detail="branch must be a non-empty string"
            )
        branch_s = branch.strip()

        sha_s = normalize_sha(sha)

        return cls(
            owner=owner_s, repo=repo_s, repo_full=repo_full, branch=branch_s, sha=sha_s
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
    await init_dirs()
    db.configure(DB_PATH)
    await db.init_db()
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

# ----------------------------
# NEW: Single reports ingest endpoint
# ----------------------------


@app.post("/reports")
async def ingest_report(
    owner: str = Form(...),
    repo: str = Form(...),
    branch: str = Form(...),
    sha: str = Form(...),
    tarball: UploadFile = File(
        ...
    ),  # expects .tar.gz with HTML + coverage.xml at top of html dir
    authorization: str | None = Header(default=None),
    x_access_token: str | None = Header(default=None, convert_underscores=False),
) -> dict[str, Any]:
    token = extract_token(authorization, x_access_token)
    verify_token(token)

    dto = ReportIngestDTO.from_form(owner, repo, branch, sha)
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
        "branch_dashboard_url": f"/{dto.owner}/{dto.repo}/b/{dto.branch}",
        "hash_raw_url": f"/{dto.owner}/{dto.repo}/h/{dto.sha}/raw/",
        "branch_raw_url": f"/{dto.owner}/{dto.repo}/b/{dto.branch}/raw/",
    }


# ----------------------------
# Dashboards (HTML)
# ----------------------------


def dashboard_template() -> str:
    return (
        CHART_VIEW.replace("__TREND_LIMIT__", str(TREND_LIMIT))
        .replace("__WORST_LIMIT__", str(DEFAULT_WORST_FILES))
        .replace("__PIE_LIMIT__", str(DEFAULT_PIE_FILES))
    )


def dashboard_html_for(kind: str, repo_full: str, ref: str) -> str:
    owner, name = repo_full.split("/", 1)

    if kind == "h":
        raw_url = f"/{owner}/{name}/h/"  # html templates will append the hash to this
        trend_url = f"/api/{owner}/{name}/h/{ref}/trend"
        worst_url = f"/api/{owner}/{name}/h/{ref}/latest/worst-files"
        unc_url = f"/api/{owner}/{name}/h/{ref}/latest/uncovered-lines"
        download_suffix = f"/{owner}/{name}/h/{ref}"
    else:
        raw_url = f"/{owner}/{name}/h/"
        trend_url = f"/api/{owner}/{name}/b/{ref}/trend"
        worst_url = f"/api/{owner}/{name}/b/{ref}/latest/worst-files"
        unc_url = f"/api/{owner}/{name}/b/{ref}/latest/uncovered-lines"
        download_suffix = f"/{owner}/{name}/b/{ref}"

    base = dashboard_template()

    return (
        base.replace("__RAW_URL__", raw_url)
        .replace("__TREND_URL__", trend_url)
        .replace("__WORST_URL__", worst_url)
        .replace("__UNCOVERED_URL__", unc_url)
        .replace("__DOWNLOAD_SUFFIX__", download_suffix)
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


@app.get("/{owner}/{name}/", response_class=HTMLResponse)
async def repo_home(owner: str, name: str) -> RedirectResponse:
    return RedirectResponse(url=f"/{owner}/{name}/b/main")


@app.get("/{owner}/{name}/b/{branch:path}", response_class=HTMLResponse)
async def repo_branch_dashboard(owner: str, name: str, branch: str) -> str:
    repo_full = repo_from_owner_name(owner, name)
    return dashboard_html_for("b", repo_full, branch)


# @app.get("/{owner}/{name}/h/{git_hash}", response_class=HTMLResponse)
# def repo_hash_dashboard(owner: str, name: str, git_hash: str) -> str:
#    repo_full = repo_from_owner_name(owner, name)
#    return dashboard_html_for("h", repo_full, git_hash)


# ----------------------------
# Raw HTML serving (FIXED)
# ----------------------------


# ----------------------------
# Hash views serve raw HTML (no /raw/), WITH trailing slash
# ----------------------------


def report_html_root_for_hash(repo_full: str, git_hash: str) -> Path:
    repo_fs = repo_to_fs(repo_full)
    return REPORTS_DIR / repo_fs / "h" / git_hash / "html"


# Redirect /h/<sha> -> /h/<sha>/ so relative asset URLs work
@app.get("/{owner}/{name}/h/{git_hash}")
async def hash_raw_redirect(owner: str, name: str, git_hash: str) -> RedirectResponse:
    return RedirectResponse(url=f"/{owner}/{name}/h/{git_hash}/", status_code=307)


# Serve the report index at /h/<sha>/
@app.get("/{owner}/{name}/h/{git_hash}/")
async def hash_raw_index(owner: str, name: str, git_hash: str) -> FileResponse:
    repo_full = repo_from_owner_name(owner, name)
    root = report_html_root_for_hash(repo_full, git_hash)
    index = root / "index.html"
    if not await anyio.Path(index).exists():
        raise HTTPException(status_code=404, detail="No raw report for this hash")
    return FileResponse(path=str(index))


# Serve any asset under /h/<sha>/<path>
@app.get("/{owner}/{name}/h/{git_hash}/{path:path}")
async def hash_raw_file(
    owner: str, name: str, git_hash: str, path: str
) -> FileResponse:
    repo_full = repo_from_owner_name(owner, name)
    root = report_html_root_for_hash(repo_full, git_hash)

    p = safe_join_under(root, path)
    ap = anyio.Path(p)
    if not await ap.exists() or not await ap.is_file():
        raise HTTPException(status_code=404, detail="Not found")

    return FileResponse(path=str(p))


"""@app.get("/{owner}/{name}/b/{branch:path}/raw/")
def branch_raw_index(owner: str, name: str, branch: str) -> FileResponse:
    repo_full = repo_from_owner_name(owner, name)
    head_hash = latest_branch_head_hash(repo_full, branch)
    if head_hash is None:
        raise HTTPException(
            status_code=404, detail="No branch head for this branch yet"
        )
    return hash_raw_index(owner, name, head_hash)


@app.get("/{owner}/{name}/b/{branch:path}/raw/{path:path}")
def branch_raw_file(owner: str, name: str, branch: str, path: str) -> FileResponse:
    repo_full = repo_from_owner_name(owner, name)
    head_hash = latest_branch_head_hash(repo_full, branch)
    if head_hash is None:
        raise HTTPException(
            status_code=404, detail="No branch head for this branch yet"
        )
    return hash_raw_file(owner, name, head_hash, path)"""


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


@app.get("/download/{token}/{owner}/{name}/h/{git_hash}")
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


@app.get("/download/{token}/{owner}/{name}/b/{branch:path}")
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


@app.get("/api/{owner}/{name}/h/{git_hash}/trend")
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


@app.get("/api/{owner}/{name}/h/{git_hash}/latest/worst-files")
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


@app.get("/api/{owner}/{name}/h/{git_hash}/latest/uncovered-lines")
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


@app.get("/api/{owner}/{name}/b/{branch:path}/trend")
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


@app.get("/api/{owner}/{name}/b/{branch:path}/latest/worst-files")
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


@app.get("/api/{owner}/{name}/b/{branch:path}/latest/uncovered-lines")
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
