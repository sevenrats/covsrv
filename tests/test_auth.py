"""Tests for the covsrv.auth package.

Covers: cache, session helpers, config loading, provider abstraction,
auth routes, and the ``require_view_permission`` dependency.
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from covsrv import db
from covsrv.auth.cache import AuthzCache
from covsrv.auth.config import AuthConfig, ProviderConfig, load_auth_config
from covsrv.auth.provider import (
    OAuthProvider,
    ProviderUser,
    RepoAccess,
    ResourceDescriptor,
    TokenResponse,
)
from covsrv.auth.session import (
    clear_all_sessions,
    clear_provider_session,
    get_provider_session,
    set_provider_session,
)

# =====================================================================
# AuthzCache
# =====================================================================


class TestAuthzCache:
    def test_get_miss(self):
        cache = AuthzCache(ttl=60)
        assert cache.get("github", "u1", "owner", "repo") is None

    def test_set_and_get(self):
        cache = AuthzCache(ttl=60)
        cache.set("github", "u1", "owner", "repo", True)
        assert cache.get("github", "u1", "owner", "repo") is True

    def test_denied_cached(self):
        cache = AuthzCache(ttl=60)
        cache.set("github", "u1", "owner", "repo", False)
        assert cache.get("github", "u1", "owner", "repo") is False

    def test_expired_entry_returns_none(self):
        cache = AuthzCache(ttl=0)  # instant expiry
        cache.set("github", "u1", "owner", "repo", True)
        # monotonic clock won't give us exactly 0, so sleep a tiny bit
        time.sleep(0.01)
        assert cache.get("github", "u1", "owner", "repo") is None

    def test_clear(self):
        cache = AuthzCache(ttl=60)
        cache.set("github", "u1", "owner", "repo", True)
        cache.clear()
        assert cache.get("github", "u1", "owner", "repo") is None

    def test_different_keys_independent(self):
        cache = AuthzCache(ttl=60)
        cache.set("github", "u1", "owner", "repoA", True)
        cache.set("github", "u1", "owner", "repoB", False)
        assert cache.get("github", "u1", "owner", "repoA") is True
        assert cache.get("github", "u1", "owner", "repoB") is False

    def test_eviction_on_max_size(self):
        cache = AuthzCache(ttl=60, max_size=2)
        cache.set("github", "u1", "o", "r1", True)
        cache.set("github", "u1", "o", "r2", True)
        # Manually expire the first two entries so eviction can reclaim them
        with cache._lock:
            for k in list(cache._cache):
                val, _ = cache._cache[k]
                cache._cache[k] = (val, time.monotonic() - 120)
        # Third insert triggers eviction of expired entries
        cache.set("github", "u1", "o", "r3", True)
        assert cache.get("github", "u1", "o", "r3") is True


# =====================================================================
# Session helpers
# =====================================================================


class _FakeRequest:
    """Minimal stand-in for ``starlette.requests.Request`` with a dict session."""

    def __init__(self):
        self.session: dict = {}


class TestSessionHelpers:
    def test_get_provider_session_empty(self):
        req = _FakeRequest()
        assert get_provider_session(req, "github") is None

    def test_set_and_get_provider_session(self):
        req = _FakeRequest()
        set_provider_session(
            req, "github", access_token="tok", user_id="1", username="octocat"
        )
        data = get_provider_session(req, "github")
        assert data is not None
        assert data["access_token"] == "tok"
        assert data["user_id"] == "1"
        assert data["username"] == "octocat"

    def test_clear_provider_session(self):
        req = _FakeRequest()
        set_provider_session(
            req, "github", access_token="tok", user_id="1", username="octocat"
        )
        clear_provider_session(req, "github")
        assert get_provider_session(req, "github") is None

    def test_clear_all_sessions(self):
        req = _FakeRequest()
        set_provider_session(
            req, "github", access_token="tok1", user_id="1", username="a"
        )
        set_provider_session(
            req, "gitea", access_token="tok2", user_id="2", username="b"
        )
        clear_all_sessions(req)
        assert get_provider_session(req, "github") is None
        assert get_provider_session(req, "gitea") is None

    def test_multiple_providers_independent(self):
        req = _FakeRequest()
        set_provider_session(
            req, "github", access_token="gh", user_id="1", username="a"
        )
        set_provider_session(req, "gitea", access_token="gt", user_id="2", username="b")
        gh = get_provider_session(req, "github")
        gt = get_provider_session(req, "gitea")
        assert gh is not None
        assert gt is not None
        assert gh["access_token"] == "gh"
        assert gt["access_token"] == "gt"


# =====================================================================
# Config loading
# =====================================================================


class TestLoadAuthConfig:
    def test_defaults_disabled(self):
        """Without env vars, auth is disabled and no providers are registered."""
        with patch.dict("os.environ", {}, clear=True):
            cfg = load_auth_config()
        assert cfg.enabled is False
        assert len(cfg.providers) == 0

    def test_github_provider_from_env(self):
        env = {
            "COVSRV_AUTH_ENABLED": "true",
            "COVSRV_GITHUB_CLIENT_ID": "gh-id",
            "COVSRV_GITHUB_CLIENT_SECRET": "gh-secret",
            "COVSRV_SESSION_SECRET": "s3cret",
        }
        with patch.dict("os.environ", env, clear=True):
            cfg = load_auth_config()
        assert cfg.enabled is True
        assert "github" in cfg.providers
        assert cfg.providers["github"].client_id == "gh-id"
        assert cfg.session_secret == "s3cret"

    def test_gitea_provider_from_env(self):
        env = {
            "COVSRV_AUTH_ENABLED": "true",
            "COVSRV_GITEA_URL": "https://gitea.example.com",
            "COVSRV_GITEA_CLIENT_ID": "gt-id",
            "COVSRV_GITEA_CLIENT_SECRET": "gt-secret",
        }
        with patch.dict("os.environ", env, clear=True):
            cfg = load_auth_config()
        assert "gitea" in cfg.providers
        assert cfg.providers["gitea"].base_url == "https://gitea.example.com"

    def test_url_to_provider_mapping(self):
        env = {
            "COVSRV_AUTH_ENABLED": "true",
            "COVSRV_GITHUB_CLIENT_ID": "id",
            "COVSRV_GITHUB_CLIENT_SECRET": "sec",
            "COVSRV_GITEA_URL": "https://gitea.local",
            "COVSRV_GITEA_CLIENT_ID": "id2",
            "COVSRV_GITEA_CLIENT_SECRET": "sec2",
        }
        with patch.dict("os.environ", env, clear=True):
            cfg = load_auth_config()
        assert cfg.url_to_provider["https://github.com"] == "github"
        assert cfg.url_to_provider["https://gitea.local"] == "gitea"

    def test_cache_ttl_from_env(self):
        env = {"COVSRV_AUTH_CACHE_TTL": "120"}
        with patch.dict("os.environ", env, clear=True):
            cfg = load_auth_config()
        assert cfg.cache_ttl == 120


# =====================================================================
# Provider abstraction
# =====================================================================


class TestResourceDescriptor:
    def test_defaults(self):
        rd = ResourceDescriptor(provider="github", owner="o", repo="r")
        assert rd.resource_type == "repo"
        assert rd.path is None
        assert rd.ref is None


class TestOAuthProviderCanView:
    """Test that the default ``can_view`` delegates to ``can_view_repo``."""

    async def test_delegates_to_can_view_repo(self):
        class StubProvider(OAuthProvider):
            name = "stub"

            async def get_authorize_url(self, state, redirect_uri):
                return ""

            async def exchange_code(self, code, redirect_uri):
                return TokenResponse(access_token="x")

            async def get_user(self, access_token):
                return ProviderUser(id="1", username="u", provider="stub")

            async def can_view_repo(self, access_token, owner, repo):
                return RepoAccess.ALLOWED if owner == "allowed" else RepoAccess.DENIED

        p = StubProvider()
        rd_yes = ResourceDescriptor(provider="stub", owner="allowed", repo="r")
        rd_no = ResourceDescriptor(provider="stub", owner="denied", repo="r")
        assert await p.can_view("tok", rd_yes) is RepoAccess.ALLOWED
        assert await p.can_view("tok", rd_no) is RepoAccess.DENIED


# =====================================================================
# Auth routes — integration tests
# =====================================================================


class _FakeProvider(OAuthProvider):
    """In-memory fake for testing auth routes without hitting any real API."""

    @property
    def name(self):
        return "fakeprov"

    async def get_authorize_url(self, state: str, redirect_uri: str) -> str:
        return f"https://fake.example.com/authorize?state={state}&redirect_uri={redirect_uri}"

    async def exchange_code(self, code: str, redirect_uri: str) -> TokenResponse:
        if code == "bad-code":
            raise ValueError("invalid code")
        return TokenResponse(access_token="fake-access-token")

    async def get_user(self, access_token: str) -> ProviderUser:
        return ProviderUser(id="42", username="fakeuser", provider="fakeprov")

    async def can_view_repo(
        self, access_token: str, owner: str, repo: str
    ) -> RepoAccess:
        if repo == "expired-repo":
            return RepoAccess.TOKEN_EXPIRED
        if repo == "private-repo":
            return RepoAccess.DENIED
        return RepoAccess.ALLOWED

    async def is_repo_public(self, owner: str, repo: str) -> bool:
        return repo == "public-repo"


def _make_fake_auth_state(enabled: bool = True):
    """Patch ``covsrv.auth.auth_state`` with a fake provider."""
    from covsrv.auth import _AuthState

    state = _AuthState()
    fake_provider = _FakeProvider()

    state.config = AuthConfig(
        enabled=enabled,
        session_secret="test-secret",
        providers={
            "fakeprov": ProviderConfig(
                name="fakeprov",
                client_id="cid",
                client_secret="csec",
                base_url="https://fake.example.com",
                api_base_url="https://fake.example.com/api",
                authorize_url="https://fake.example.com/login/oauth/authorize",
                token_url="https://fake.example.com/login/oauth/access_token",
                userinfo_url="https://fake.example.com/api/user",
            )
        },
        url_to_provider={"https://fake.example.com": "fakeprov"},
        cache_ttl=60,
        public_app_url="http://test",
    )
    state.providers = {"fakeprov": fake_provider}
    state.cache = AuthzCache(ttl=60)

    # Wire up the repo→provider lookup using the DB
    async def _lookup(repo_full: str) -> str | None:
        from covsrv import db as _db

        provider_url = await _db.provider_url_for_repo(repo_full)
        if provider_url is None:
            return None
        purl = provider_url.rstrip("/")
        assert state.config is not None
        for url, pname in state.config.url_to_provider.items():
            if purl == url.rstrip("/") or purl.startswith(url.rstrip("/") + "/"):
                return pname
        return None

    state.repo_provider_lookup = _lookup

    # Also wire up the raw provider_url lookup (for anonymous public checks)
    async def _url_lookup(repo_full: str) -> str | None:
        from covsrv import db as _db

        return await _db.provider_url_for_repo(repo_full)

    state.repo_provider_url_lookup = _url_lookup
    return state


@pytest_asyncio.fixture()
async def auth_client(initialized_db, tmp_data_dir):
    """Client with auth enabled using a fake provider."""
    import covsrv.auth as auth_mod
    import main as app_module

    fake_state = _make_fake_auth_state(enabled=True)
    original_state = auth_mod.auth_state

    # Replace the module-level auth_state
    auth_mod.auth_state = fake_state

    try:
        transport = ASGITransport(app=app_module.app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
    finally:
        auth_mod.auth_state = original_state


class TestAuthLoginRoute:
    async def test_login_redirects_to_provider(self, auth_client: AsyncClient):
        resp = await auth_client.get(
            "/auth/fakeprov/login?next=/some/page",
            follow_redirects=False,
        )
        assert resp.status_code == 307
        loc = resp.headers["location"]
        assert "fake.example.com/authorize" in loc
        assert "state=" in loc

    async def test_login_unknown_provider_404(self, auth_client: AsyncClient):
        resp = await auth_client.get(
            "/auth/nosuch/login",
            follow_redirects=False,
        )
        assert resp.status_code == 404


class TestAuthCallbackRoute:
    async def test_callback_invalid_state_403(self, auth_client: AsyncClient):
        resp = await auth_client.get(
            "/auth/fakeprov/callback?code=abc&state=wrong",
            follow_redirects=False,
        )
        assert resp.status_code == 403

    async def test_callback_missing_code_400(self, auth_client: AsyncClient):
        # First do a login to set the state in the session
        login_resp = await auth_client.get(
            "/auth/fakeprov/login",
            follow_redirects=False,
        )
        cookies = login_resp.cookies
        # Extract state from redirect URL
        loc = login_resp.headers["location"]
        import re

        state_match = re.search(r"state=([^&]+)", loc)
        assert state_match is not None
        state = state_match.group(1)

        resp = await auth_client.get(
            f"/auth/fakeprov/callback?state={state}",
            follow_redirects=False,
            cookies=cookies,
        )
        assert resp.status_code == 400

    async def test_callback_error_param_403(self, auth_client: AsyncClient):
        resp = await auth_client.get(
            "/auth/fakeprov/callback?error=access_denied",
            follow_redirects=False,
        )
        assert resp.status_code == 403

    async def test_full_login_flow(self, auth_client: AsyncClient):
        """Login → callback → session established."""
        # 1. Start login
        login_resp = await auth_client.get(
            "/auth/fakeprov/login?next=/alice/proj/b/main",
            follow_redirects=False,
        )
        assert login_resp.status_code == 307
        cookies = login_resp.cookies

        # Extract state
        loc = login_resp.headers["location"]
        import re

        state_match = re.search(r"state=([^&]+)", loc)
        assert state_match is not None
        state = state_match.group(1)

        # 2. Simulate callback
        cb_resp = await auth_client.get(
            f"/auth/fakeprov/callback?code=good-code&state={state}",
            follow_redirects=False,
            cookies=cookies,
        )
        assert cb_resp.status_code == 307
        assert "/alice/proj/b/main" in cb_resp.headers["location"]


class TestAuthLogoutRoute:
    async def test_logout_redirects(self, auth_client: AsyncClient):
        resp = await auth_client.get(
            "/auth/fakeprov/logout?next=/",
            follow_redirects=False,
        )
        assert resp.status_code == 307

    async def test_logout_all(self, auth_client: AsyncClient):
        resp = await auth_client.get(
            "/auth/logout?next=/",
            follow_redirects=False,
        )
        assert resp.status_code == 307


# =====================================================================
# require_view_permission dependency
# =====================================================================


class TestRequireViewPermission:
    """Test the dependency with auth enabled (using the fake provider)."""

    async def test_unauthenticated_browser_redirects_to_login(
        self, auth_client: AsyncClient
    ):
        """A browser request without a session triggers a redirect to login."""
        # Seed a report so the provider lookup maps this repo to fakeprov
        import main as app_module
        from tests.test_main import seed_report

        tmp_data_dir = Path(app_module.BASE_DIR)
        await seed_report(
            tmp_data_dir,
            repo_full="alice/proj",
            provider_url="https://fake.example.com",
        )

        resp = await auth_client.get(
            "/alice/proj/b/main",
            follow_redirects=False,
        )
        # Should redirect to auth login
        assert resp.status_code == 307
        loc = resp.headers["location"]
        assert "/auth/fakeprov/login" in loc
        # The next param should be the *path*, not a full URL
        assert (
            "next=%2Falice%2Fproj%2Fb%2Fmain" in loc or "next=/alice/proj/b/main" in loc
        )

    async def test_unauthenticated_api_returns_401(self, auth_client: AsyncClient):
        """An API/JSON request without a session gets a 401."""
        # Seed a report so the provider lookup maps this repo to fakeprov
        import main as app_module
        from tests.test_main import seed_report

        tmp_data_dir = Path(app_module.BASE_DIR)
        await seed_report(
            tmp_data_dir,
            repo_full="alice/proj",
            provider_url="https://fake.example.com",
        )

        resp = await auth_client.get(
            "/api/alice/proj/b/main/trend",
            follow_redirects=False,
            headers={"Accept": "application/json"},
        )
        assert resp.status_code == 401

    async def test_authenticated_allowed_repo_succeeds(self, auth_client: AsyncClient):
        """After login, accessing an allowed repo works."""

        # Seed a report so dashboard can render
        import main as app_module
        from tests.test_main import seed_report

        tmp_data_dir = Path(app_module.BASE_DIR)
        await seed_report(
            tmp_data_dir,
            repo_full="alice/proj",
            provider_url="https://fake.example.com",
        )

        # Do a full login flow
        login_resp = await auth_client.get(
            "/auth/fakeprov/login",
            follow_redirects=False,
        )
        cookies = login_resp.cookies
        import re

        loc = login_resp.headers["location"]
        m = re.search(r"state=([^&]+)", loc)
        assert m is not None
        state = m.group(1)

        cb_resp = await auth_client.get(
            f"/auth/fakeprov/callback?code=good-code&state={state}",
            follow_redirects=False,
            cookies=cookies,
        )
        # Merge cookies
        session_cookies = cb_resp.cookies

        # Now access a protected page
        resp = await auth_client.get(
            "/alice/proj/b/main",
            cookies=session_cookies,
        )
        assert resp.status_code == 200

    async def test_authenticated_denied_repo_returns_403(
        self, auth_client: AsyncClient
    ):
        """Accessing a repo the provider denies returns a 403 access-denied page."""
        # Seed so the provider lookup maps this repo to fakeprov
        import main as app_module
        from tests.test_main import seed_report

        tmp_data_dir = Path(app_module.BASE_DIR)
        await seed_report(
            tmp_data_dir,
            repo_full="alice/private-repo",
            provider_url="https://fake.example.com",
        )

        # Login first
        login_resp = await auth_client.get(
            "/auth/fakeprov/login",
            follow_redirects=False,
        )
        cookies = login_resp.cookies
        import re

        loc = login_resp.headers["location"]
        m = re.search(r"state=([^&]+)", loc)
        assert m is not None
        state = m.group(1)

        cb_resp = await auth_client.get(
            f"/auth/fakeprov/callback?code=good-code&state={state}",
            follow_redirects=False,
            cookies=cookies,
        )
        session_cookies = cb_resp.cookies

        # "private-repo" is denied by _FakeProvider.can_view_repo
        resp = await auth_client.get(
            "/alice/private-repo/b/main",
            cookies=session_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 403
        assert "Access Denied" in resp.text
        assert "alice/private-repo" in resp.text

    async def test_authenticated_denied_api_returns_404(self, auth_client: AsyncClient):
        """API/JSON request for a denied repo still gets a 404 (no leak)."""
        import main as app_module
        from tests.test_main import seed_report

        tmp_data_dir = Path(app_module.BASE_DIR)
        await seed_report(
            tmp_data_dir,
            repo_full="alice/private-repo",
            provider_url="https://fake.example.com",
        )

        # Login first
        login_resp = await auth_client.get(
            "/auth/fakeprov/login",
            follow_redirects=False,
        )
        cookies = login_resp.cookies
        import re

        loc = login_resp.headers["location"]
        m = re.search(r"state=([^&]+)", loc)
        assert m is not None
        state = m.group(1)

        cb_resp = await auth_client.get(
            f"/auth/fakeprov/callback?code=good-code&state={state}",
            follow_redirects=False,
            cookies=cookies,
        )
        session_cookies = cb_resp.cookies

        # API request for denied repo → 404
        resp = await auth_client.get(
            "/api/alice/private-repo/b/main/trend",
            cookies=session_cookies,
            follow_redirects=False,
            headers={"Accept": "application/json"},
        )
        assert resp.status_code == 404

    async def test_expired_token_redirects_to_login(self, auth_client: AsyncClient):
        """When the provider reports token expired, user is sent back to OAuth."""
        import main as app_module
        from tests.test_main import seed_report

        tmp_data_dir = Path(app_module.BASE_DIR)
        # "expired-repo" triggers TOKEN_EXPIRED in _FakeProvider
        await seed_report(
            tmp_data_dir,
            repo_full="alice/expired-repo",
            provider_url="https://fake.example.com",
        )

        # Login first
        login_resp = await auth_client.get(
            "/auth/fakeprov/login",
            follow_redirects=False,
        )
        cookies = login_resp.cookies
        import re

        loc = login_resp.headers["location"]
        m = re.search(r"state=([^&]+)", loc)
        assert m is not None
        state = m.group(1)

        cb_resp = await auth_client.get(
            f"/auth/fakeprov/callback?code=good-code&state={state}",
            follow_redirects=False,
            cookies=cookies,
        )
        session_cookies = cb_resp.cookies

        # Access repo whose token is "expired" → should redirect to login
        resp = await auth_client.get(
            "/alice/expired-repo/b/main",
            cookies=session_cookies,
            follow_redirects=False,
        )
        assert resp.status_code == 307
        loc = resp.headers["location"]
        assert "/auth/fakeprov/login" in loc


class TestAuthDisabledPassthrough:
    """When auth is disabled, all routes behave normally (no login needed)."""

    async def test_dashboard_accessible_without_login(self, client):
        resp = await client.get("/alice/proj/b/main")
        assert resp.status_code == 200

    async def test_api_accessible_without_login(self, client):
        resp = await client.get("/api/alice/proj/b/main/trend")
        assert resp.status_code == 200


class TestPublicRepoBypass:
    """Public repos should be accessible without login even when auth is enabled."""

    async def test_public_repo_no_login_needed(self, auth_client: AsyncClient):
        """A public repo (is_repo_public=True) should be accessible without login."""
        import main as app_module
        from tests.test_main import seed_report

        tmp_data_dir = Path(app_module.BASE_DIR)
        # "public-repo" is marked public by _FakeProvider.is_repo_public
        await seed_report(
            tmp_data_dir,
            repo_full="alice/public-repo",
            provider_url="https://fake.example.com",
        )

        resp = await auth_client.get(
            "/alice/public-repo/b/main",
            follow_redirects=False,
        )
        assert resp.status_code == 200


class TestUnconfiguredProviderBypass:
    """Repos whose provider isn't configured: public → allow, private → deny."""

    async def test_unconfigured_provider_public_repo_allowed(
        self, auth_client: AsyncClient
    ):
        """An unconfigured provider with a public repo → anonymous check passes."""
        import main as app_module
        from tests.test_main import seed_report

        tmp_data_dir = Path(app_module.BASE_DIR)
        await seed_report(
            tmp_data_dir,
            repo_full="alice/github-repo",
            provider_url="https://github.com",
        )

        # Mock the anonymous public check to return True (simulates a public repo)
        with patch(
            "covsrv.auth.dependencies._check_public_anonymous",
            new_callable=AsyncMock,
            return_value=True,
        ):
            resp = await auth_client.get(
                "/alice/github-repo/b/main",
                follow_redirects=False,
            )
        assert resp.status_code == 200

    async def test_unconfigured_provider_private_repo_denied(
        self, auth_client: AsyncClient
    ):
        """An unconfigured provider with a private repo → 404."""
        import main as app_module
        from tests.test_main import seed_report

        tmp_data_dir = Path(app_module.BASE_DIR)
        await seed_report(
            tmp_data_dir,
            repo_full="alice/github-private",
            provider_url="https://github.com",
        )

        # Mock the anonymous public check to return False (simulates a private repo)
        with patch(
            "covsrv.auth.dependencies._check_public_anonymous",
            new_callable=AsyncMock,
            return_value=False,
        ):
            resp = await auth_client.get(
                "/alice/github-private/b/main",
                follow_redirects=False,
            )
        assert resp.status_code == 404

    async def test_unknown_repo_denied(self, auth_client: AsyncClient):
        """A repo with no reports in the DB at all → 404."""
        resp = await auth_client.get(
            "/unknown/noreports/b/main",
            follow_redirects=False,
        )
        assert resp.status_code == 404


# =====================================================================
# DB helper: provider_url_for_repo
# =====================================================================


class TestProviderUrlForRepo:
    async def test_returns_none_for_unknown(self, initialized_db):
        result = await db.provider_url_for_repo("unknown/repo")
        assert result is None

    async def test_returns_provider_url(self, initialized_db, tmp_data_dir):
        from tests.test_main import seed_report

        await seed_report(
            tmp_data_dir,
            repo_full="alice/proj",
            provider_url="https://gitea.example.com",
        )
        result = await db.provider_url_for_repo("alice/proj")
        assert result == "https://gitea.example.com"

    async def test_returns_latest(self, initialized_db, tmp_data_dir):
        from tests.test_main import seed_report

        await seed_report(
            tmp_data_dir,
            repo_full="alice/proj",
            sha="aaa1234567890abcdef1234567890abcdef123456",
            received_ts=1000,
            provider_url="https://old.example.com",
        )
        await seed_report(
            tmp_data_dir,
            repo_full="alice/proj",
            sha="bbb1234567890abcdef1234567890abcdef123456",
            received_ts=2000,
            provider_url="https://new.example.com",
        )
        result = await db.provider_url_for_repo("alice/proj")
        assert result == "https://new.example.com"
