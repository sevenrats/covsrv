"""FastAPI dependencies for authentication and authorization."""

from __future__ import annotations

import logging

import httpx
from fastapi import HTTPException, Request

from covsrv.auth.provider import ProviderUser, RepoAccess
from covsrv.auth.session import clear_provider_session, get_provider_session

logger = logging.getLogger(__name__)

_GITHUB_API = "https://api.github.com"


# ------------------------------------------------------------------
# Custom exception — caught by an exception handler that redirects
# ------------------------------------------------------------------


class AuthenticationRequired(Exception):
    """Raised when a browser user needs to log in with a provider."""

    def __init__(self, provider: str, next_url: str) -> None:
        self.provider = provider
        self.next_url = next_url


class AccessDenied(Exception):
    """Raised when an authenticated user does not have access to a repo.

    Caught by an exception handler that renders a user-friendly
    "Access Denied" splash page for browser requests.
    """

    def __init__(self, owner: str, name: str) -> None:
        self.owner = owner
        self.name = name


# ------------------------------------------------------------------
# The dependency
# ------------------------------------------------------------------


async def require_view_permission(request: Request) -> ProviderUser | None:
    """FastAPI dependency: ensure the caller may view ``{owner}/{name}``.

    When auth is disabled (the default) this is a no-op that returns
    ``None``.  When auth is enabled:

    * If the repo is **public** on the provider → allow without login.
    * If the repo is **private** and the provider is **not configured**
      → deny (404).  Implementers must configure OAuth or disable auth.
    * Browser requests without a session → redirect to OAuth login.
    * API / JSON requests without a session → **401**.
    * Denied access → **404** (prevents leaking repo existence).
    * Provider errors → **503** (fail-closed).
    """
    from covsrv.auth import auth_state

    if auth_state.config is None or not auth_state.config.enabled:
        return None

    owner: str | None = request.path_params.get("owner")
    name: str | None = request.path_params.get("name")

    if not owner or not name:
        raise HTTPException(status_code=400, detail="Missing owner or repo in path")

    # --- resolve provider ---
    provider_name = await _resolve_provider(owner, name)
    provider = auth_state.providers.get(provider_name) if provider_name else None

    # --- public repo check (cached) ---
    # Use provider name if configured, otherwise fall back to raw URL key
    cache_provider_key = provider_name or "__anon__"
    cached_public = auth_state.cache.get(cache_provider_key, "__public__", owner, name)
    if cached_public is True:
        return None  # public repo, no login needed

    if cached_public is None:
        # Not in cache yet — ask anonymously
        if provider is not None:
            try:
                is_public = await provider.is_repo_public(owner, name)
            except Exception:
                logger.warning(
                    "Public-check failed for %s/%s on %s, proceeding to auth",
                    owner,
                    name,
                    provider_name,
                )
                is_public = False
        else:
            # No configured provider — try an anonymous API check
            is_public = await _check_public_anonymous(owner, name)

        auth_state.cache.set(cache_provider_key, "__public__", owner, name, is_public)
        if is_public:
            return None

    # --- repo appears private ---

    # If the provider isn't configured, we can't do OAuth — deny.
    if provider is None:
        raise HTTPException(status_code=404, detail="Not found")

    # Provider exists but has no OAuth credentials → can check visibility
    # but cannot authenticate users.  Deny access to private repos.
    if (
        auth_state.config is not None
        and provider_name not in auth_state.config.providers
    ):
        _handle_access_denied(request, owner, name)
        raise AssertionError  # pragma: no cover

    # --- require login ---
    session_data = get_provider_session(request, provider_name)  # type: ignore[arg-type]
    if session_data is None:
        _handle_unauthenticated(request, provider_name)  # type: ignore[arg-type]
        raise AssertionError  # pragma: no cover

    access_token: str = session_data["access_token"]
    user_id: str = session_data["user_id"]
    username: str = session_data.get("username", "")

    # --- check authz cache ---
    cached = auth_state.cache.get(provider_name, user_id, owner, name)  # type: ignore[arg-type]
    if cached is True:
        return ProviderUser(id=user_id, username=username, provider=provider_name)  # type: ignore[arg-type]
    if cached is False:
        _handle_access_denied(request, owner, name)
        raise AssertionError  # pragma: no cover

    # --- call provider API ---
    try:
        result = await provider.can_view_repo(access_token, owner, name)
    except Exception:
        logger.exception("Provider API error during authz check for %s/%s", owner, name)
        raise HTTPException(
            status_code=503,
            detail="Authorization check temporarily unavailable",
        )

    if result is RepoAccess.TOKEN_EXPIRED:
        # Token revoked or expired — clear session + user cache, re-authenticate.
        # We must NOT cache a denial here: after re-login the user_id is the
        # same, and a stale ``False`` would block access even with a fresh
        # valid token.  Clearing the user's cache entries ensures a fresh
        # provider check after re-authentication.
        clear_provider_session(request, provider_name)  # type: ignore[arg-type]
        auth_state.cache.clear_user(provider_name, user_id)  # type: ignore[arg-type]
        _handle_unauthenticated(request, provider_name)  # type: ignore[arg-type]
        raise AssertionError  # pragma: no cover

    allowed = result is RepoAccess.ALLOWED
    auth_state.cache.set(provider_name, user_id, owner, name, allowed)  # type: ignore[arg-type]

    if not allowed:
        _handle_access_denied(request, owner, name)
        raise AssertionError  # pragma: no cover

    return ProviderUser(id=user_id, username=username, provider=provider_name)  # type: ignore[arg-type]


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


async def _resolve_provider(owner: str, name: str) -> str | None:
    """Determine which auth provider handles ``owner/name``.

    Returns the provider name if one is configured for this repo's
    ``provider_url``, or ``None`` if the repo is unknown or its
    provider isn't configured.
    """
    from covsrv.auth import auth_state

    if auth_state.repo_provider_lookup is not None:
        result = await auth_state.repo_provider_lookup(f"{owner}/{name}")
        if result is not None:
            return result

    return None


async def _get_raw_provider_url(owner: str, name: str) -> str | None:
    """Return the raw ``provider_url`` from the DB for ``owner/name``."""
    from covsrv.auth import auth_state

    if auth_state.repo_provider_url_lookup is not None:
        return await auth_state.repo_provider_url_lookup(f"{owner}/{name}")
    return None


async def _check_public_anonymous(owner: str, name: str) -> bool:
    """Check if a repo is public via an unauthenticated API call.

    Works for repos whose provider isn't configured in env.  Constructs
    the API URL from the stored ``provider_url``:

    * ``https://github.com`` → ``https://api.github.com/repos/...``
    * Anything else (Gitea / Forgejo / etc.) → ``{base}/api/v1/repos/...``
    """
    raw_url = await _get_raw_provider_url(owner, name)
    if raw_url is None:
        return False  # no report in DB → can't verify, treat as private

    base = raw_url.rstrip("/")
    if base == "https://github.com":
        api_url = f"{_GITHUB_API}/repos/{owner}/{name}"
    else:
        # Gitea / Forgejo / generic
        api_url = f"{base}/api/v1/repos/{owner}/{name}"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(api_url, headers={"Accept": "application/json"})
        if resp.status_code != 200:
            return False
        data = resp.json()
        return data.get("private") is False
    except Exception:
        logger.warning(
            "Anonymous public-check failed for %s/%s at %s",
            owner,
            name,
            api_url,
        )
        return False


def _handle_unauthenticated(request: Request, provider_name: str) -> None:
    """Raise the appropriate error for an unauthenticated caller.

    * API / JSON callers → 401
    * Browser callers    → ``AuthenticationRequired`` (caught by the
      exception handler and turned into a redirect to the login page)

    Uses the request **path** (not the full URL) as the ``next`` target
    to avoid scheme mismatches behind reverse proxies.
    """
    accept = request.headers.get("accept", "")
    path = str(request.url.path)
    qs = str(request.url.query)
    next_url = f"{path}?{qs}" if qs else path

    if "application/json" in accept or path.startswith("/api/"):
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": f'Bearer realm="{provider_name}"'},
        )

    raise AuthenticationRequired(provider_name, next_url)


def _handle_access_denied(request: Request, owner: str, name: str) -> None:
    """Raise the appropriate error for an authenticated but unauthorised caller.

    * API / JSON callers → 404 (don't leak repo existence)
    * Browser callers    → ``AccessDenied`` (caught by the exception
      handler and turned into a user-friendly splash page)
    """
    accept = request.headers.get("accept", "")
    path = str(request.url.path)

    if "application/json" in accept or path.startswith("/api/"):
        raise HTTPException(status_code=404, detail="Not found")

    raise AccessDenied(owner, name)
