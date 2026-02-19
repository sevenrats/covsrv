"""Authentication and authorization for covsrv.

This package provides:

* **Provider-agnostic OAuth / OIDC login** (GitHub, Gitea — more can be
  added by subclassing ``OAuthProvider``).
* **Per-request authorization** that queries the provider API to verify
  the caller may view the corresponding repository.
* **Short-lived caching** of authorization decisions to avoid hammering
  the upstream API on every request.
* **A single ``Depends(require_view_permission)``** dependency that can
  be attached to any route that contains ``{owner}`` and ``{name}`` path
  parameters.

**Auth is disabled by default**.  Set ``COVSRV_AUTH_ENABLED=true`` plus
the relevant ``COVSRV_GITHUB_*`` / ``COVSRV_GITEA_*`` env vars to
enable it.
"""

from __future__ import annotations

from typing import Awaitable, Callable

from covsrv.auth.cache import AuthzCache
from covsrv.auth.config import AuthConfig, ProviderConfig, load_auth_config
from covsrv.auth.dependencies import AuthenticationRequired, require_view_permission
from covsrv.auth.provider import (
    OAuthProvider,
    ProviderUser,
    ResourceDescriptor,
    TokenResponse,
)
from covsrv.auth.routes import router as auth_router

__all__ = [
    "AuthConfig",
    "AuthenticationRequired",
    "AuthzCache",
    "OAuthProvider",
    "ProviderConfig",
    "ProviderUser",
    "ResourceDescriptor",
    "TokenResponse",
    "auth_router",
    "auth_state",
    "load_auth_config",
    "require_view_permission",
    "setup_auth",
]


# ------------------------------------------------------------------
# Module-level state (configured once during app startup)
# ------------------------------------------------------------------


class _AuthState:
    """Singleton holding the runtime auth configuration.

    Attributes are set by ``setup_auth()`` during the FastAPI lifespan.
    Before that, ``config`` is ``None`` and the ``require_view_permission``
    dependency is a no-op.
    """

    def __init__(self) -> None:
        self.config: AuthConfig | None = None
        self.providers: dict[str, OAuthProvider] = {}
        self.cache: AuthzCache = AuthzCache()
        self.repo_provider_lookup: Callable[[str], Awaitable[str | None]] | None = None
        self.repo_provider_url_lookup: Callable[[str], Awaitable[str | None]] | None = (
            None
        )


auth_state = _AuthState()


# ------------------------------------------------------------------
# Startup helper
# ------------------------------------------------------------------


async def setup_auth() -> None:
    """Initialise the auth system from environment variables.

    Called once during the FastAPI lifespan.  Safe to call even when auth
    is disabled — it will simply populate ``auth_state.config`` with
    ``enabled=False``.
    """
    config = load_auth_config()
    auth_state.config = config
    auth_state.cache = AuthzCache(ttl=config.cache_ttl)

    # Build provider instances
    providers: dict[str, OAuthProvider] = {}
    for name, pconfig in config.providers.items():
        if name == "github":
            from covsrv.auth.github import GitHubProvider

            providers[name] = GitHubProvider(pconfig)
        elif name == "gitea":
            from covsrv.auth.gitea import GiteaProvider

            providers[name] = GiteaProvider(pconfig)
    auth_state.providers = providers

    # Wire up the repo → provider lookup (queries the DB)
    auth_state.repo_provider_lookup = _make_repo_provider_lookup(config)
    auth_state.repo_provider_url_lookup = _make_repo_provider_url_lookup()


def _make_repo_provider_lookup(
    config: AuthConfig,
) -> Callable[[str], Awaitable[str | None]]:
    """Return an async callable that maps ``'owner/repo'`` → provider name."""

    async def _lookup(repo_full: str) -> str | None:
        from covsrv import db as _db

        provider_url = await _db.provider_url_for_repo(repo_full)
        if provider_url is None:
            return None

        purl = provider_url.rstrip("/")
        for url, pname in config.url_to_provider.items():
            if purl == url.rstrip("/") or purl.startswith(url.rstrip("/") + "/"):
                return pname
        return None

    return _lookup


def _make_repo_provider_url_lookup() -> Callable[[str], Awaitable[str | None]]:
    """Return an async callable that maps ``'owner/repo'`` → raw provider URL."""

    async def _lookup(repo_full: str) -> str | None:
        from covsrv import db as _db

        return await _db.provider_url_for_repo(repo_full)

    return _lookup
