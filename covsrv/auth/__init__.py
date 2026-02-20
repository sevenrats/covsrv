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

from typing import TYPE_CHECKING, Awaitable, Callable

if TYPE_CHECKING:
    from covsrv.config import ConfigManager

from covsrv.auth.cache import AuthzCache
from covsrv.auth.config import AuthConfig, ProviderConfig, load_auth_config
from covsrv.auth.dependencies import (
    AccessDenied,
    AuthenticationRequired,
    require_view_permission,
)
from covsrv.auth.provider import (
    OAuthProvider,
    ProviderUser,
    RepoAccess,
    ResourceDescriptor,
    TokenResponse,
)
from covsrv.auth.routes import router as auth_router

__all__ = [
    "AccessDenied",
    "AuthConfig",
    "AuthenticationRequired",
    "AuthzCache",
    "OAuthProvider",
    "ProviderConfig",
    "ProviderUser",
    "RepoAccess",
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
        self.config_manager: "ConfigManager | None" = None


auth_state = _AuthState()


# ------------------------------------------------------------------
# Startup helper
# ------------------------------------------------------------------


async def setup_auth(config_manager: "ConfigManager | None" = None) -> None:
    """Initialise the auth system.

    When a ``ConfigManager`` is provided its settings take precedence
    over environment variables.  Called once during the FastAPI lifespan.
    Safe to call even when auth is disabled — it will simply populate
    ``auth_state.config`` with ``enabled=False``.
    """

    if config_manager is not None:
        auth_state.config_manager = config_manager
        config = config_manager.to_auth_config()
    else:
        config = load_auth_config()

    auth_state.config = config
    auth_state.cache = AuthzCache(ttl=config.cache_ttl)

    # Build provider instances
    providers: dict[str, OAuthProvider] = {}
    for name, pconfig in config.providers.items():
        # Determine the provider *type* — when driven by ConfigManager
        # we can look it up; the env-based path uses the well-known names.
        ptype = name  # default: env-based names ("github", "gitea")
        if config_manager is not None:
            entry = config_manager.get_provider(name)
            ptype = entry.type if entry else name

        if ptype == "github":
            from covsrv.auth.github import GitHubProvider

            providers[name] = GitHubProvider(pconfig)
        elif ptype == "gitea":
            from covsrv.auth.gitea import GiteaProvider

            providers[name] = GiteaProvider(pconfig)
    # Also create provider instances for non-OAuth-configured providers.
    # These are used for anonymous public-repo checks — they can't do
    # OAuth login, but they can tell us whether a repo is public.
    if config_manager is not None:
        for name, entry in config_manager.providers.items():
            if name in providers:
                continue  # already built from OAuth config
            pconfig = config_manager.to_auth_provider_config(entry)
            if entry.type == "github":
                from covsrv.auth.github import GitHubProvider

                providers[name] = GitHubProvider(pconfig)
            elif entry.type == "gitea":
                from covsrv.auth.gitea import GiteaProvider

                providers[name] = GiteaProvider(pconfig)

    auth_state.providers = providers

    # Wire up the repo → provider lookup.
    # Prefer provider_name column when available (config-driven);
    # fall back to provider_url mapping (env-driven).
    auth_state.repo_provider_lookup = _make_repo_provider_lookup(config)
    auth_state.repo_provider_url_lookup = _make_repo_provider_url_lookup()


def _make_repo_provider_lookup(
    config: AuthConfig,
) -> Callable[[str], Awaitable[str | None]]:
    """Return an async callable that maps ``'owner/repo'`` → provider name.

    Checks the ``provider_name`` column first (populated by config-driven
    ingest).  Falls back to the ``provider_url`` → name mapping for
    legacy reports.  As a last resort, when there is exactly one OAuth
    provider configured, returns it unconditionally — this covers legacy
    reports whose ``provider_url`` is a stale default.
    """

    # Build a *full* URL→name map from the ConfigManager (if available)
    # that covers all providers, not just OAuth-enabled ones.
    all_url_to_name: dict[str, str] = {}
    if auth_state.config_manager is not None:
        for name, entry in auth_state.config_manager.providers.items():
            all_url_to_name[entry.url.rstrip("/")] = name

    async def _lookup(repo_full: str) -> str | None:
        from covsrv import db as _db

        # Fast path: provider_name stored directly
        pname = await _db.provider_name_for_repo(repo_full)
        if pname and pname in auth_state.providers:
            return pname

        # Fallback: resolve via provider_url
        provider_url = await _db.provider_url_for_repo(repo_full)
        if provider_url is not None:
            purl = provider_url.rstrip("/")
            # Try OAuth-enabled providers first
            for url, name in config.url_to_provider.items():
                if purl == url.rstrip("/") or purl.startswith(url.rstrip("/") + "/"):
                    return name
            # Try all configured providers (including non-OAuth)
            for url, name in all_url_to_name.items():
                if purl == url or purl.startswith(url + "/"):
                    if name in auth_state.providers:
                        return name

        # Last resort: if there is exactly one OAuth provider, use it.
        # This covers legacy reports whose provider_url is a stale default
        # (e.g. "https://github.com" when the repo actually lives on Gitea).
        if len(config.providers) == 1:
            return next(iter(config.providers))
        return None

    return _lookup


def _make_repo_provider_url_lookup() -> Callable[[str], Awaitable[str | None]]:
    """Return an async callable that maps ``'owner/repo'`` → raw provider URL."""

    async def _lookup(repo_full: str) -> str | None:
        from covsrv import db as _db

        return await _db.provider_url_for_repo(repo_full)

    return _lookup
