"""Shared fixtures for the covsrv test suite."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from covsrv import sql

# ---------------------------------------------------------------------------
# Sample Cobertura XML
# ---------------------------------------------------------------------------

SAMPLE_COVERAGE_XML = """\
<?xml version="1.0" ?>
<coverage version="7.0" timestamp="1700000000" lines-valid="100"
          lines-covered="85" line-rate="0.85" branches-covered="0"
          branches-valid="0" branch-rate="0" complexity="0">
  <packages>
    <package name="myapp" line-rate="0.85" branch-rate="0" complexity="0">
      <classes>
        <class name="foo.py" filename="foo.py" line-rate="0.90" branch-rate="0" complexity="0">
          <lines>
            <line number="1" hits="1"/>
            <line number="2" hits="1"/>
            <line number="3" hits="0"/>
            <line number="4" hits="1"/>
            <line number="5" hits="1"/>
            <line number="6" hits="1"/>
            <line number="7" hits="1"/>
            <line number="8" hits="1"/>
            <line number="9" hits="1"/>
            <line number="10" hits="0"/>
          </lines>
        </class>
        <class name="bar.py" filename="bar.py" line-rate="0.80" branch-rate="0" complexity="0">
          <lines>
            <line number="1" hits="1"/>
            <line number="2" hits="0"/>
            <line number="3" hits="0"/>
            <line number="4" hits="0"/>
            <line number="5" hits="1"/>
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
"""


def make_tarball_bytes(
    coverage_xml: str = SAMPLE_COVERAGE_XML,
    extra_files: dict[str, str] | None = None,
) -> bytes:
    """Build an in-memory .tar.gz containing coverage.xml (and optionally more files)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        xml_data = coverage_xml.encode()
        info = tarfile.TarInfo(name="coverage.xml")
        info.size = len(xml_data)
        tf.addfile(info, io.BytesIO(xml_data))

        if extra_files:
            for name, content in extra_files.items():
                data = content.encode()
                fi = tarfile.TarInfo(name=name)
                fi.size = len(data)
                tf.addfile(fi, io.BytesIO(data))

    buf.seek(0)
    return buf.read()


# ---------------------------------------------------------------------------
# Temporary data directory & DB
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_data_dir(tmp_path: Path):
    """Provides a fresh temp directory and patches main module globals."""
    import main as app_module

    orig_base = app_module.BASE_DIR
    orig_data = app_module.DATA_DIR
    orig_reports = app_module.REPORTS_DIR
    orig_db = app_module.DB_PATH

    app_module.BASE_DIR = tmp_path
    app_module.DATA_DIR = tmp_path / "covsrv_data"
    app_module.REPORTS_DIR = tmp_path / "covsrv_data" / "reports"
    app_module.DB_PATH = tmp_path / "covsrv_data" / "covsrv.sqlite3"

    app_module.DATA_DIR.mkdir(parents=True, exist_ok=True)
    app_module.REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    yield tmp_path

    app_module.BASE_DIR = orig_base
    app_module.DATA_DIR = orig_data
    app_module.REPORTS_DIR = orig_reports
    app_module.DB_PATH = orig_db


@pytest_asyncio.fixture()
async def db(tmp_data_dir: Path):
    """Configure sql module against a fresh temp DB and initialise tables."""
    db_path = tmp_data_dir / "covsrv_data" / "covsrv.sqlite3"
    sql.configure(db_path)
    await sql.init_db()
    yield db_path


# ---------------------------------------------------------------------------
# Async HTTP test client (uses the real FastAPI app)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def client(db: Path):
    """Async httpx client wired to the FastAPI app (no lifespan)."""
    import main as app_module

    transport = ASGITransport(app=app_module.app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Convenience: a valid auth token that matches the hardcoded hash in main.py
# ---------------------------------------------------------------------------

# The hash in main.py was generated from this token.
# We derive it once; tests that need auth just use this.
VALID_TOKEN = "test-coverage-token"


@pytest.fixture()
def valid_token() -> str:
    """Return a token string that passes verify_token().

    Because we can't reverse argon2 we monkeypatch verify_token in tests that
    need authenticated requests.
    """
    return VALID_TOKEN
