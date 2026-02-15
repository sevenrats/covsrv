# main.py
from __future__ import annotations

import base64
import os
import shutil
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import coverage
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import FastAPI, Header, HTTPException, Request, Response
from starlette.staticfiles import StaticFiles

# ----------------------------
# Auth config (simple + usable)
# ----------------------------

# For local testing, the token that matches TOKEN_HASH below is:
#   kvcc-coverage-token
#
# Generate a new hash like this (once), then paste it here:
#   from argon2 import PasswordHasher; print(PasswordHasher().hash("your-new-token"))
TOKEN_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$nxSTXtitRlXKAuwz1PxVWQ$G+XQZgF+DURfAptK/v3zFjjO9vzexX1bQ/jxPAcAYBY"
)
ph = PasswordHasher()


def verify_token(token: str) -> None:
    try:
        if not ph.verify(TOKEN_HASH, token):
            raise HTTPException(status_code=401, detail="Invalid token")
    except VerifyMismatchError:
        raise HTTPException(status_code=401, detail="Invalid token")


def extract_token(authorization: str | None, x_access_token: str | None) -> str:
    """
    Supports either:
      - Authorization: Bearer <token>
      - X-Access-Token: <token>
    """
    if x_access_token:
        return x_access_token.strip()

    if authorization:
        parts = authorization.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()

    raise HTTPException(status_code=401, detail="Missing token")


# ----------------------------
# DTO (no pydantic)
# ----------------------------

@dataclass(frozen=True, slots=True)
class CoverageReportDTO:
    """
    Intuitive + implicitly serializable DTO:
      - git_hash: commit identifier
      - coverage_b64: base64-encoded bytes of the `.coverage` file (binary)
    """
    git_hash: str
    coverage_b64: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CoverageReportDTO":
        git_hash = data.get("git_hash")
        coverage_b64 = data.get("coverage_b64")

        if not isinstance(git_hash, str) or not git_hash.strip():
            raise HTTPException(status_code=422, detail="git_hash must be a non-empty string")
        if not isinstance(coverage_b64, str) or not coverage_b64.strip():
            raise HTTPException(status_code=422, detail="coverage_b64 must be a non-empty base64 string")

        return cls(git_hash=git_hash.strip(), coverage_b64=coverage_b64.strip())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ----------------------------
# App + storage
# ----------------------------

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_placeholder_site()
    yield

app = FastAPI(title="Coverage HTML Server", version="1.0", lifespan=lifespan)

BASE_DIR = Path(os.environ.get("COVERAGE_SERVER_DIR", ".")).resolve()
COVERAGE_HTML_DIR = BASE_DIR / "coverage_html"
LATEST_HASH_FILE = COVERAGE_HTML_DIR / "LATEST_GIT_HASH.txt"


def ensure_placeholder_site() -> None:
    COVERAGE_HTML_DIR.mkdir(parents=True, exist_ok=True)
    index = COVERAGE_HTML_DIR / "index.html"
    if not index.exists():
        index.write_text(
            """<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Coverage</title></head>
  <body style="font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;">
    <h1>No coverage report uploaded yet</h1>
    <p>POST a .coverage report to <code>/report</code> to generate HTML.</p>
  </body>
</html>
""",
            encoding="utf-8",
        )





# ----------------------------
# Endpoints
# ----------------------------

@app.post("/report")
async def upload_coverage_report(
    request: Request,
    authorization: str | None = Header(default=None),
    x_access_token: str | None = Header(default=None, convert_underscores=False),
) -> dict[str, Any]:
    """
    Accepts JSON like:
      {
        "git_hash": "abc1234",
        "coverage_b64": "<base64 of .coverage bytes>"
      }

    Auth:
      - Authorization: Bearer <token>
        OR
      - X-Access-Token: <token>
    """
    token = extract_token(authorization, x_access_token)
    verify_token(token)

    # Manual JSON parsing (no pydantic)
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="JSON body must be an object")

    dto = CoverageReportDTO.from_dict(payload)

    # Decode `.coverage` bytes (binary SQLite db)
    try:
        cov_bytes = base64.b64decode(dto.coverage_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=422, detail="coverage_b64 is not valid base64")

    # Generate HTML using coverage.py
    with tempfile.TemporaryDirectory(prefix="covsrv_") as tmp:
        tmp_path = Path(tmp)
        data_file = tmp_path / ".coverage"
        out_dir = tmp_path / "html"

        data_file.write_bytes(cov_bytes)
        out_dir.mkdir(parents=True, exist_ok=True)

        try:
            cov = coverage.Coverage(data_file=str(data_file))
            cov.load()
            cov.html_report(directory=str(out_dir))
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to generate HTML from .coverage. "
                       f"Ensure matching source files exist on server. Error: {e}",
            )

        # Atomic-ish replace of the served directory
        # (build in temp, then swap)
        new_dir = tmp_path / "html_final"
        shutil.copytree(out_dir, new_dir)

        # Save a tiny banner file (optional, but handy)
        (new_dir / "GIT_HASH.txt").write_text(dto.git_hash + "\n", encoding="utf-8")

        # Replace current site
        if COVERAGE_HTML_DIR.exists():
            shutil.rmtree(COVERAGE_HTML_DIR)
        shutil.move(str(new_dir), str(COVERAGE_HTML_DIR))

        # Save latest hash
        LATEST_HASH_FILE.write_text(dto.git_hash + "\n", encoding="utf-8")

    return {"status": "ok", "git_hash": dto.git_hash}


# Serve the coverage HTML at the root.
# Important: mount AFTER defining /report so the static mount doesn't intercept it.
app.mount("/", StaticFiles(directory=str(COVERAGE_HTML_DIR), html=True), name="coverage-root")


# Optional: small health endpoint (won't be reachable because mount at "/" will catch it)
# If you want one, mount coverage at "/coverage" instead and keep "/" for your own routes.

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)