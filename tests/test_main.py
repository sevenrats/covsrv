"""Tests for main.py — normalisation, auth, helpers, XML parsing, and API endpoints."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

# We import from main at function/class level so the module is available
import main as app_module
from covsrv import db
from covsrv.models import BranchEvent, BranchHead, Report
from tests.conftest import SAMPLE_COVERAGE_XML, make_tarball_bytes

# =====================================================================
# Unit tests — pure functions (no DB / no HTTP)
# =====================================================================


# -----------------------------------------------------------------------
# normalize_repo_full
# -----------------------------------------------------------------------


class TestNormalizeRepoFull:
    def test_valid(self):
        assert app_module.normalize_repo_full("owner/repo") == "owner/repo"

    def test_strips_whitespace(self):
        assert app_module.normalize_repo_full("  owner / repo  ") == "owner/repo"

    def test_strips_slashes(self):
        assert app_module.normalize_repo_full("/owner/repo/") == "owner/repo"

    def test_missing_slash_raises(self):
        with pytest.raises(HTTPException) as exc_info:
            app_module.normalize_repo_full("noslash")
        assert exc_info.value.status_code == 422

    def test_empty_raises(self):
        with pytest.raises(HTTPException):
            app_module.normalize_repo_full("")

    def test_empty_owner_raises(self):
        with pytest.raises(HTTPException):
            app_module.normalize_repo_full("/repo")

    def test_empty_name_raises(self):
        with pytest.raises(HTTPException):
            app_module.normalize_repo_full("owner/")


# -----------------------------------------------------------------------
# normalize_owner_repo
# -----------------------------------------------------------------------


class TestNormalizeOwnerRepo:
    def test_valid(self):
        o, r, f = app_module.normalize_owner_repo("alice", "myrepo")
        assert o == "alice"
        assert r == "myrepo"
        assert f == "alice/myrepo"

    def test_empty_owner_raises(self):
        with pytest.raises(HTTPException):
            app_module.normalize_owner_repo("", "repo")

    def test_empty_repo_raises(self):
        with pytest.raises(HTTPException):
            app_module.normalize_owner_repo("owner", "")

    def test_non_string_owner_raises(self):
        with pytest.raises(HTTPException):
            app_module.normalize_owner_repo(None, "repo")  # type: ignore[arg-type]

    def test_non_string_repo_raises(self):
        with pytest.raises(HTTPException):
            app_module.normalize_owner_repo("owner", None)  # type: ignore[arg-type]


# -----------------------------------------------------------------------
# normalize_sha
# -----------------------------------------------------------------------


class TestNormalizeSha:
    def test_valid(self):
        assert app_module.normalize_sha("abcdef1234567") == "abcdef1234567"

    def test_strips_whitespace(self):
        assert app_module.normalize_sha("  abcdef1  ") == "abcdef1"

    def test_too_short_raises(self):
        with pytest.raises(HTTPException) as exc_info:
            app_module.normalize_sha("abc")
        assert exc_info.value.status_code == 422

    def test_empty_raises(self):
        with pytest.raises(HTTPException):
            app_module.normalize_sha("")

    def test_non_string_raises(self):
        with pytest.raises(HTTPException):
            app_module.normalize_sha(None)  # type: ignore[arg-type]


# -----------------------------------------------------------------------
# ReportIngestDTO
# -----------------------------------------------------------------------


class TestReportIngestDTO:
    def test_from_form_valid(self):
        dto = app_module.ReportIngestDTO.from_form(
            owner="alice", repo="proj", branch="main", sha="abc1234567"
        )
        assert dto.owner == "alice"
        assert dto.repo == "proj"
        assert dto.repo_full == "alice/proj"
        assert dto.branch == "main"
        assert dto.sha == "abc1234567"
        assert dto.provider_url == "https://github.com"

    def test_from_form_with_provider_url(self):
        dto = app_module.ReportIngestDTO.from_form(
            owner="alice",
            repo="proj",
            branch="main",
            sha="abc1234567",
            provider_url="https://gitlab.com",
        )
        assert dto.provider_url == "https://gitlab.com"

    def test_from_form_provider_url_strips_trailing_slash(self):
        dto = app_module.ReportIngestDTO.from_form(
            owner="alice",
            repo="proj",
            branch="main",
            sha="abc1234567",
            provider_url="https://gitlab.com/",
        )
        assert dto.provider_url == "https://gitlab.com"

    def test_from_form_empty_provider_url_defaults(self):
        dto = app_module.ReportIngestDTO.from_form(
            owner="alice",
            repo="proj",
            branch="main",
            sha="abc1234567",
            provider_url="",
        )
        assert dto.provider_url == "https://github.com"

    def test_to_dict(self):
        dto = app_module.ReportIngestDTO.from_form(
            owner="alice", repo="proj", branch="main", sha="abc1234567"
        )
        d = dto.to_dict()
        assert d == {
            "owner": "alice",
            "repo": "proj",
            "repo_full": "alice/proj",
            "branch": "main",
            "sha": "abc1234567",
            "provider_url": "https://github.com",
        }

    def test_empty_branch_raises(self):
        with pytest.raises(HTTPException):
            app_module.ReportIngestDTO.from_form(
                owner="alice", repo="proj", branch="", sha="abc1234567"
            )

    def test_short_sha_raises(self):
        with pytest.raises(HTTPException):
            app_module.ReportIngestDTO.from_form(
                owner="alice", repo="proj", branch="main", sha="abc"
            )


# -----------------------------------------------------------------------
# extract_token
# -----------------------------------------------------------------------


class TestExtractToken:
    def test_from_x_access_token(self):
        assert app_module.extract_token(None, "my-token") == "my-token"

    def test_from_bearer(self):
        assert app_module.extract_token("Bearer my-token", None) == "my-token"

    def test_x_access_token_takes_precedence(self):
        assert app_module.extract_token("Bearer other", "my-token") == "my-token"

    def test_missing_both_raises(self):
        with pytest.raises(HTTPException) as exc_info:
            app_module.extract_token(None, None)
        assert exc_info.value.status_code == 401

    def test_bearer_case_insensitive(self):
        assert app_module.extract_token("bearer my-token", None) == "my-token"

    def test_non_bearer_auth_raises(self):
        with pytest.raises(HTTPException):
            app_module.extract_token("Basic abc123", None)


# -----------------------------------------------------------------------
# verify_token
# -----------------------------------------------------------------------


class TestVerifyToken:
    def test_invalid_token_raises(self):
        with pytest.raises(HTTPException) as exc_info:
            app_module.verify_token("wrong-token")
        assert exc_info.value.status_code == 401


# -----------------------------------------------------------------------
# repo_to_fs / repo_from_owner_name
# -----------------------------------------------------------------------


class TestRepoToFs:
    def test_replaces_slash(self):
        assert app_module.repo_to_fs("alice/proj") == "alice__proj"

    def test_no_slash(self):
        assert app_module.repo_to_fs("noslash") == "noslash"


class TestRepoFromOwnerName:
    def test_valid(self):
        assert app_module.repo_from_owner_name("alice", "proj") == "alice/proj"


# -----------------------------------------------------------------------
# safe_join_under
# -----------------------------------------------------------------------


class TestSafeJoinUnder:
    def test_valid_join(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        result = app_module.safe_join_under(base, "file.txt")
        assert str(result).startswith(str(base))

    def test_traversal_blocked(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        with pytest.raises(HTTPException) as exc_info:
            app_module.safe_join_under(base, "../etc/passwd")
        assert exc_info.value.status_code == 400

    def test_dot_dot_in_component(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        with pytest.raises(HTTPException):
            app_module.safe_join_under(base, "foo/../../bar")

    def test_same_as_base(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        result = app_module.safe_join_under(base, ".")
        assert result == base.resolve()


# -----------------------------------------------------------------------
# safe_extract_tar
# -----------------------------------------------------------------------


class TestSafeExtractTar:
    def test_extracts_normal_tar(self, tmp_path):
        tar_path = tmp_path / "test.tar.gz"
        dest = tmp_path / "dest"
        dest.mkdir()

        with tarfile.open(tar_path, "w:gz") as tf:
            data = b"hello"
            info = tarfile.TarInfo(name="hello.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        app_module.safe_extract_tar(tar_path, dest)
        assert (dest / "hello.txt").read_text() == "hello"

    def test_blocks_path_traversal(self, tmp_path):
        tar_path = tmp_path / "evil.tar.gz"
        dest = tmp_path / "dest"
        dest.mkdir()

        with tarfile.open(tar_path, "w:gz") as tf:
            data = b"evil"
            info = tarfile.TarInfo(name="../../../etc/evil.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        with pytest.raises(HTTPException) as exc_info:
            app_module.safe_extract_tar(tar_path, dest)
        assert exc_info.value.status_code == 400


# -----------------------------------------------------------------------
# parse_coverage_xml
# -----------------------------------------------------------------------


class TestParseCoverageXml:
    def test_parses_sample_xml(self, tmp_path):
        xml_path = tmp_path / "coverage.xml"
        xml_path.write_text(SAMPLE_COVERAGE_XML)

        overall, files = app_module.parse_coverage_xml(xml_path)
        assert overall == pytest.approx(85.0, abs=0.01)
        assert len(files) == 2

        fnames = {f.filename for f in files}
        assert "foo.py" in fnames
        assert "bar.py" in fnames

    def test_per_file_uncovered_lines(self, tmp_path):
        xml_path = tmp_path / "coverage.xml"
        xml_path.write_text(SAMPLE_COVERAGE_XML)

        _, files = app_module.parse_coverage_xml(xml_path)
        by_name = {f.filename: f for f in files}

        # foo.py has 2 lines with hits=0 (lines 3, 10)
        assert by_name["foo.py"].uncovered_lines == 2
        # bar.py has 3 lines with hits=0 (lines 2, 3, 4)
        assert by_name["bar.py"].uncovered_lines == 3

    def test_invalid_xml_raises(self, tmp_path):
        xml_path = tmp_path / "coverage.xml"
        xml_path.write_text("not xml at all <<<>>>")

        with pytest.raises(HTTPException) as exc_info:
            app_module.parse_coverage_xml(xml_path)
        assert exc_info.value.status_code == 400

    def test_missing_line_rate_defaults_to_zero(self, tmp_path):
        xml_path = tmp_path / "coverage.xml"
        xml_path.write_text(
            '<?xml version="1.0" ?>'
            "<coverage><packages><package><classes>"
            '<class filename="x.py"><lines></lines></class>'
            "</classes></package></packages></coverage>"
        )
        overall, files = app_module.parse_coverage_xml(xml_path)
        assert overall == 0.0

    def test_empty_coverage(self, tmp_path):
        xml_path = tmp_path / "coverage.xml"
        xml_path.write_text(
            '<?xml version="1.0" ?>'
            '<coverage line-rate="0.0"><packages></packages></coverage>'
        )
        overall, files = app_module.parse_coverage_xml(xml_path)
        assert overall == 0.0
        assert files == []


# -----------------------------------------------------------------------
# dashboard helpers
# -----------------------------------------------------------------------


class TestDashboardHtmlFor:
    def test_hash_kind(self):
        html = app_module.dashboard_html_for("h", "alice/proj", "abc123")
        assert "/api/alice/proj/h/abc123/trend" in html
        assert "/api/alice/proj/h/abc123/latest/uncovered-lines" in html
        assert "/download/" in html  # download links present
        # Verify no raw Jinja2 placeholders remain
        assert "{{" not in html
        assert "}}" not in html

    def test_branch_kind(self):
        html = app_module.dashboard_html_for("b", "alice/proj", "main")
        assert "/api/alice/proj/b/main/trend" in html
        assert "/api/alice/proj/b/main/latest/uncovered-lines" in html

    def test_contains_trend_limit(self):
        html = app_module.dashboard_html_for("h", "alice/proj", "abc123")
        assert str(app_module.TREND_LIMIT) in html

    def test_hash_contains_nav_urls(self):
        html = app_module.dashboard_html_for("h", "alice/proj", "abc123")
        assert "github.com/alice/proj" in html
        assert "/alice/proj/h/abc123" in html  # raw_framed_url

    def test_branch_hides_spreadsheet(self):
        html = app_module.dashboard_html_for("b", "alice/proj", "main")
        assert 'style="display:none"' in html  # spreadsheet btn hidden

    def test_custom_provider_url(self):
        html = app_module.dashboard_html_for(
            "h", "alice/proj", "abc123", provider_url="https://gitlab.com"
        )
        assert "gitlab.com/alice/proj" in html
        assert "github.com" not in html

    def test_default_provider_url(self):
        html = app_module.dashboard_html_for("h", "alice/proj", "abc123")
        assert "github.com/alice/proj" in html


class TestFramedHtmlFor:
    def test_renders_with_iframe(self):
        html = app_module.framed_html_for("alice/proj", "abc123")
        assert "iframe" in html
        assert "/raw/alice/proj/h/abc123/" in html
        assert "github.com/alice/proj" in html
        assert "/alice/proj/h/abc123/chart" in html
        assert "{{" not in html
        assert "}}" not in html

    def test_custom_provider_url(self):
        html = app_module.framed_html_for(
            "alice/proj", "abc123", provider_url="https://gitlab.com"
        )
        assert "gitlab.com/alice/proj" in html
        assert "github.com" not in html


# =====================================================================
# Integration tests — HTTP endpoints (need DB + client)
# =====================================================================


# -----------------------------------------------------------------------
# Helper: ingest a report directly into DB + filesystem
# -----------------------------------------------------------------------


async def seed_report(
    tmp_data_dir: Path,
    repo_full: str = "alice/proj",
    branch: str = "main",
    sha: str = "abc1234567890abcdef1234567890abcdef123456",
    overall_percent: float = 85.0,
    received_ts: int = 1700000000,
    coverage_xml: str = SAMPLE_COVERAGE_XML,
    provider_url: str = "https://github.com",
):
    """Seed a report record + write the HTML directory with coverage.xml."""
    repo_fs = app_module.repo_to_fs(repo_full)
    report_dir = tmp_data_dir / "covsrv_data" / "reports" / repo_fs / "h" / sha
    html_dir = report_dir / "html"
    html_dir.mkdir(parents=True, exist_ok=True)

    (html_dir / "coverage.xml").write_text(coverage_xml)
    (html_dir / "coverage.json").write_text('{"meta": {}}')
    (html_dir / "coverage.lcov").write_text("TN:\nSF:foo.py\nend_of_record\n")
    (html_dir / "index.html").write_text("<html><body>report</body></html>")
    (html_dir / "style.css").write_text("body{}")

    from sqlalchemy.dialects.sqlite import insert as sqlite_insert

    async with db.session() as sess:
        sess.add(
            Report(
                repo=repo_full,
                branch_name=branch,
                git_hash=sha,
                received_ts=received_ts,
                overall_percent=overall_percent,
                report_dir=str(report_dir),
                provider_url=provider_url,
            )
        )
        stmt = sqlite_insert(BranchHead).values(
            repo=repo_full,
            branch_name=branch,
            current_hash=sha,
            updated_ts=received_ts,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[BranchHead.repo, BranchHead.branch_name],
            set_={
                "current_hash": stmt.excluded.current_hash,
                "updated_ts": stmt.excluded.updated_ts,
            },
        )
        await sess.execute(stmt)
        sess.add(
            BranchEvent(
                repo=repo_full,
                branch_name=branch,
                git_hash=sha,
                updated_ts=received_ts,
            )
        )
        await db.upsert_repo_seen(sess, repo_full, received_ts)

    return report_dir


# -----------------------------------------------------------------------
# Root
# -----------------------------------------------------------------------


class TestRootEndpoint:
    async def test_redirects_to_docs(self, client: AsyncClient):
        resp = await client.get("/", follow_redirects=False)
        assert resp.status_code in (301, 302, 307, 308)
        assert "/docs" in resp.headers["location"]


# -----------------------------------------------------------------------
# Repo home
# -----------------------------------------------------------------------


class TestRepoHome:
    async def test_redirects_to_branch_main(self, client: AsyncClient):
        resp = await client.get("/alice/proj/", follow_redirects=False)
        assert resp.status_code in (301, 302, 307, 308)
        assert "/alice/proj/b/main" in resp.headers["location"]


# -----------------------------------------------------------------------
# Branch dashboard
# -----------------------------------------------------------------------


class TestBranchDashboard:
    async def test_returns_html(self, client: AsyncClient, tmp_data_dir):
        resp = await client.get("/alice/proj/b/main")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Coverage" in resp.text

    async def test_uses_provider_url_from_report(
        self, client: AsyncClient, tmp_data_dir
    ):
        await seed_report(tmp_data_dir, provider_url="https://gitlab.com")
        resp = await client.get("/alice/proj/b/main")
        assert resp.status_code == 200
        assert "gitlab.com/alice/proj" in resp.text


# -----------------------------------------------------------------------
# Hash raw views
# -----------------------------------------------------------------------


SHA = "abc1234567890abcdef1234567890abcdef123456"


class TestHashFramedView:
    async def test_returns_framed_html(self, client: AsyncClient, tmp_data_dir):
        resp = await client.get(f"/alice/proj/h/{SHA}")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "iframe" in resp.text
        assert f"/raw/alice/proj/h/{SHA}/" in resp.text

    async def test_contains_nav_buttons(self, client: AsyncClient, tmp_data_dir):
        resp = await client.get(f"/alice/proj/h/{SHA}")
        assert "github.com/alice/proj" in resp.text
        assert f"/alice/proj/h/{SHA}/chart" in resp.text

    async def test_uses_provider_url_from_report(
        self, client: AsyncClient, tmp_data_dir
    ):
        await seed_report(tmp_data_dir, provider_url="https://gitlab.com")
        resp = await client.get(f"/alice/proj/h/{SHA}")
        assert "gitlab.com/alice/proj" in resp.text


class TestHashChart:
    async def test_returns_chart_html(self, client: AsyncClient, tmp_data_dir):
        resp = await client.get(f"/alice/proj/h/{SHA}/chart")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Coverage" in resp.text
        assert f"/api/alice/proj/h/{SHA}/trend" in resp.text

    async def test_uses_provider_url_from_report(
        self, client: AsyncClient, tmp_data_dir
    ):
        await seed_report(tmp_data_dir, provider_url="https://gitlab.com")
        resp = await client.get(f"/alice/proj/h/{SHA}/chart")
        assert "gitlab.com/alice/proj" in resp.text


class TestRawHashRedirect:
    async def test_redirect_appends_slash(self, client: AsyncClient, tmp_data_dir):
        resp = await client.get(f"/raw/alice/proj/h/{SHA}", follow_redirects=False)
        assert resp.status_code == 307
        assert resp.headers["location"].endswith("/")


class TestRawHashIndex:
    async def test_serves_index(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get(f"/raw/alice/proj/h/{SHA}/")
        assert resp.status_code == 200
        assert "report" in resp.text

    async def test_404_when_missing(self, client: AsyncClient, tmp_data_dir):
        resp = await client.get("/raw/alice/proj/h/nonexistent1234567/")
        assert resp.status_code == 404


class TestRawHashFile:
    async def test_serves_asset(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get(f"/raw/alice/proj/h/{SHA}/style.css")
        assert resp.status_code == 200

    async def test_404_for_missing_file(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get(f"/raw/alice/proj/h/{SHA}/nonexistent.js")
        assert resp.status_code == 404


# -----------------------------------------------------------------------
# Badge endpoints
# -----------------------------------------------------------------------


class TestBadgeHash:
    async def test_returns_svg(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get(f"/badge/alice/proj/h/{SHA}")
        assert resp.status_code == 200
        assert "svg" in resp.headers["content-type"]
        assert "<svg" in resp.text

    async def test_unknown_hash_returns_unknown(
        self, client: AsyncClient, tmp_data_dir
    ):
        resp = await client.get("/badge/alice/proj/h/0000000deadbeef")
        assert resp.status_code == 200
        assert "unknown" in resp.text

    async def test_immutable_cache_control(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get(f"/badge/alice/proj/h/{SHA}")
        assert "immutable" in resp.headers.get("cache-control", "")


class TestBadgeBranch:
    async def test_returns_svg(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get("/badge/alice/proj/b/main")
        assert resp.status_code == 200
        assert "svg" in resp.headers["content-type"]

    async def test_unknown_branch_returns_unknown(
        self, client: AsyncClient, tmp_data_dir
    ):
        resp = await client.get("/badge/alice/proj/b/nonexistent")
        assert resp.status_code == 200
        assert "unknown" in resp.text

    async def test_short_cache_control(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get("/badge/alice/proj/b/main")
        cc = resp.headers.get("cache-control", "")
        assert "max-age=60" in cc


# -----------------------------------------------------------------------
# API — hash trend
# -----------------------------------------------------------------------


class TestApiHashTrend:
    async def test_empty(self, client: AsyncClient, tmp_data_dir):
        resp = await client.get(f"/api/alice/proj/h/{SHA}/trend")
        assert resp.status_code == 200
        data = resp.json()
        assert data["points"] == []

    async def test_with_data(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get(f"/api/alice/proj/h/{SHA}/trend")
        data = resp.json()
        assert len(data["points"]) == 1
        assert data["points"][0]["overall_percent"] == 85.0

    async def test_limit_param(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get(f"/api/alice/proj/h/{SHA}/trend?limit=1")
        data = resp.json()
        assert len(data["points"]) <= 1


# -----------------------------------------------------------------------
# API — hash worst-files
# -----------------------------------------------------------------------


class TestApiHashWorstFiles:
    async def test_no_report(self, client: AsyncClient, tmp_data_dir):
        resp = await client.get(f"/api/alice/proj/h/{SHA}/latest/worst-files")
        data = resp.json()
        assert data["latest"] is None
        assert data["files"] == []

    async def test_with_report(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get(f"/api/alice/proj/h/{SHA}/latest/worst-files")
        data = resp.json()
        assert data["latest"] is not None
        assert data["latest"]["overall_percent"] == 85.0
        assert len(data["files"]) == 2


# -----------------------------------------------------------------------
# API — hash uncovered-lines
# -----------------------------------------------------------------------


class TestApiHashUncoveredLines:
    async def test_no_report(self, client: AsyncClient, tmp_data_dir):
        resp = await client.get(f"/api/alice/proj/h/{SHA}/latest/uncovered-lines")
        data = resp.json()
        assert data["latest"] is None

    async def test_with_report(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get(f"/api/alice/proj/h/{SHA}/latest/uncovered-lines")
        data = resp.json()
        assert data["latest"]["overall_percent"] == 85.0
        assert len(data["files"]) == 2
        # Sorted by uncovered_lines desc → bar.py (3) first
        assert (
            data["files"][0]["uncovered_lines"] >= data["files"][1]["uncovered_lines"]
        )


# -----------------------------------------------------------------------
# API — branch trend
# -----------------------------------------------------------------------


class TestApiBranchTrend:
    async def test_empty(self, client: AsyncClient, tmp_data_dir):
        resp = await client.get("/api/alice/proj/b/main/trend")
        data = resp.json()
        assert data["points"] == []

    async def test_with_data(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get("/api/alice/proj/b/main/trend")
        data = resp.json()
        assert len(data["points"]) == 1


# -----------------------------------------------------------------------
# API — branch worst-files
# -----------------------------------------------------------------------


class TestApiBranchWorstFiles:
    async def test_no_head(self, client: AsyncClient, tmp_data_dir):
        resp = await client.get("/api/alice/proj/b/main/latest/worst-files")
        data = resp.json()
        assert data["latest"] is None

    async def test_with_report(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get("/api/alice/proj/b/main/latest/worst-files")
        data = resp.json()
        assert data["latest"] is not None
        assert len(data["files"]) == 2


# -----------------------------------------------------------------------
# API — branch uncovered-lines
# -----------------------------------------------------------------------


class TestApiBranchUncoveredLines:
    async def test_no_head(self, client: AsyncClient, tmp_data_dir):
        resp = await client.get("/api/alice/proj/b/main/latest/uncovered-lines")
        data = resp.json()
        assert data["latest"] is None

    async def test_with_report(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get("/api/alice/proj/b/main/latest/uncovered-lines")
        data = resp.json()
        assert data["latest"] is not None
        assert len(data["files"]) == 2


# -----------------------------------------------------------------------
# Downloads
# -----------------------------------------------------------------------


class TestDownloads:
    async def test_hash_download_json(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get(f"/download/json/alice/proj/h/{SHA}")
        assert resp.status_code == 200

    async def test_hash_download_xml(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get(f"/download/xml/alice/proj/h/{SHA}")
        assert resp.status_code == 200

    async def test_hash_download_lcov(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get(f"/download/lcov/alice/proj/h/{SHA}")
        assert resp.status_code == 200

    async def test_hash_download_unknown_token(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get(f"/download/nope/alice/proj/h/{SHA}")
        assert resp.status_code == 404

    async def test_hash_download_missing_report(
        self, client: AsyncClient, tmp_data_dir
    ):
        resp = await client.get("/download/json/alice/proj/h/nonexistent1234567")
        assert resp.status_code == 404

    async def test_branch_download_json(self, client: AsyncClient, tmp_data_dir):
        await seed_report(tmp_data_dir)
        resp = await client.get("/download/json/alice/proj/b/main")
        assert resp.status_code == 200

    async def test_branch_download_no_head(self, client: AsyncClient, tmp_data_dir):
        resp = await client.get("/download/json/alice/proj/b/nonexistent")
        assert resp.status_code == 404


# -----------------------------------------------------------------------
# POST /reports — ingest (with auth bypass)
# -----------------------------------------------------------------------


class TestIngestReport:
    @pytest_asyncio.fixture()
    async def auth_client(self, initialized_db, tmp_data_dir):
        """Client with extract_token and verify_token monkeypatched to bypass auth."""
        with (
            patch.object(app_module, "extract_token", return_value="dummy-token"),
            patch.object(app_module, "verify_token", return_value=None),
        ):
            transport = ASGITransport(app=app_module.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                yield ac

    async def test_successful_ingest(self, auth_client: AsyncClient, tmp_data_dir):
        tarball = make_tarball_bytes()
        resp = await auth_client.post(
            "/reports",
            data={
                "owner": "alice",
                "repo": "proj",
                "branch": "main",
                "sha": "feed1234567890abcdef1234567890abcdef12345",
            },
            files={"tarball": ("report.tar.gz", tarball, "application/gzip")},
            headers={"x-access-token": "dummy"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["overall_percent"] == pytest.approx(85.0, abs=0.01)
        assert "hash_dashboard_url" in data

    async def test_duplicate_ingest_returns_409(
        self, auth_client: AsyncClient, tmp_data_dir
    ):
        tarball = make_tarball_bytes()
        sha = "dupe1234567890abcdef1234567890abcdef12345"
        resp1 = await auth_client.post(
            "/reports",
            data={"owner": "alice", "repo": "proj", "branch": "main", "sha": sha},
            files={"tarball": ("report.tar.gz", tarball, "application/gzip")},
            headers={"x-access-token": "dummy"},
        )
        assert resp1.status_code == 200

        tarball2 = make_tarball_bytes()
        resp2 = await auth_client.post(
            "/reports",
            data={"owner": "alice", "repo": "proj", "branch": "main", "sha": sha},
            files={"tarball": ("report.tar.gz", tarball2, "application/gzip")},
            headers={"x-access-token": "dummy"},
        )
        assert resp2.status_code == 409

    async def test_missing_coverage_xml_returns_400(
        self, auth_client: AsyncClient, tmp_data_dir
    ):
        # Build a tarball without coverage.xml
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = b"not coverage"
            info = tarfile.TarInfo(name="readme.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        buf.seek(0)

        resp = await auth_client.post(
            "/reports",
            data={
                "owner": "alice",
                "repo": "proj",
                "branch": "main",
                "sha": "noxml234567890abcdef1234567890abcdef12345",
            },
            files={"tarball": ("report.tar.gz", buf.read(), "application/gzip")},
            headers={"x-access-token": "dummy"},
        )
        assert resp.status_code == 400

    async def test_ingest_with_custom_provider_url(
        self, auth_client: AsyncClient, tmp_data_dir
    ):
        tarball = make_tarball_bytes()
        resp = await auth_client.post(
            "/reports",
            data={
                "owner": "alice",
                "repo": "proj",
                "branch": "main",
                "sha": "prov1234567890abcdef1234567890abcdef12345",
                "provider_url": "https://gitlab.com",
            },
            files={"tarball": ("report.tar.gz", tarball, "application/gzip")},
            headers={"x-access-token": "dummy"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

        # Verify the stored report uses the custom provider_url
        row = await db.latest_report_for_repo_hash(
            "alice/proj", "prov1234567890abcdef1234567890abcdef12345"
        )
        assert row is not None
        assert row["provider_url"] == "https://gitlab.com"

    async def test_ingest_without_provider_url_defaults(
        self, auth_client: AsyncClient, tmp_data_dir
    ):
        tarball = make_tarball_bytes()
        resp = await auth_client.post(
            "/reports",
            data={
                "owner": "alice",
                "repo": "proj",
                "branch": "dev",
                "sha": "dflt1234567890abcdef1234567890abcdef12345",
            },
            files={"tarball": ("report.tar.gz", tarball, "application/gzip")},
            headers={"x-access-token": "dummy"},
        )
        assert resp.status_code == 200

        row = await db.latest_report_for_repo_hash(
            "alice/proj", "dflt1234567890abcdef1234567890abcdef12345"
        )
        assert row is not None
        assert row["provider_url"] == "https://github.com"

    async def test_no_auth_returns_401(self, client: AsyncClient, tmp_data_dir):
        """Without monkeypatching, missing token → 401."""
        tarball = make_tarball_bytes()
        resp = await client.post(
            "/reports",
            data={
                "owner": "alice",
                "repo": "proj",
                "branch": "main",
                "sha": "nope1234567890abcdef1234567890abcdef12345",
            },
            files={"tarball": ("report.tar.gz", tarball, "application/gzip")},
        )
        assert resp.status_code == 401
