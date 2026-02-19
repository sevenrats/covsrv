"""Auth routes: login, callback, and logout."""

from __future__ import annotations

import secrets
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from covsrv.auth.session import clear_all_sessions, clear_provider_session

router = APIRouter(prefix="/auth", tags=["auth"])


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _safe_next_url(raw: str, public_app_url: str) -> str:
    """Sanitise *raw* to prevent open-redirect attacks.

    Only relative URLs or URLs whose origin matches our app are allowed.
    """
    if not raw:
        return "/"
    parsed = urlparse(raw)
    # Relative path → always safe
    if not parsed.scheme and not parsed.netloc:
        return raw
    # Absolute → must match our origin
    app = urlparse(public_app_url)
    if parsed.scheme == app.scheme and parsed.netloc == app.netloc:
        return raw
    return "/"


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------


@router.get("/{provider}/login")
async def auth_login(
    request: Request,
    provider: str,
    next: str = "/",
) -> RedirectResponse:
    from covsrv.auth import auth_state

    if auth_state.config is None or not auth_state.config.enabled:
        raise HTTPException(status_code=404, detail="Auth not enabled")

    prov = auth_state.providers.get(provider)
    if prov is None:
        raise HTTPException(status_code=404, detail=f"Unknown provider: {provider}")

    # CSRF state
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    request.session["oauth_next"] = _safe_next_url(
        next, auth_state.config.public_app_url
    )

    redirect_uri = f"{auth_state.config.public_app_url}/auth/{provider}/callback"
    authorize_url = await prov.get_authorize_url(state=state, redirect_uri=redirect_uri)
    return RedirectResponse(url=authorize_url, status_code=307)


@router.get("/{provider}/callback")
async def auth_callback(
    request: Request,
    provider: str,
    code: str = "",
    state: str = "",
    error: str = "",
) -> RedirectResponse:
    from covsrv.auth import auth_state
    from covsrv.auth.session import set_provider_session

    if auth_state.config is None or not auth_state.config.enabled:
        raise HTTPException(status_code=404, detail="Auth not enabled")

    if error:
        raise HTTPException(status_code=403, detail=f"OAuth error: {error}")

    prov = auth_state.providers.get(provider)
    if prov is None:
        raise HTTPException(status_code=404, detail=f"Unknown provider: {provider}")

    # Validate CSRF state
    expected_state = request.session.pop("oauth_state", None)
    if not state or state != expected_state:
        raise HTTPException(status_code=403, detail="Invalid OAuth state")

    next_url = request.session.pop("oauth_next", "/")

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    redirect_uri = f"{auth_state.config.public_app_url}/auth/{provider}/callback"

    try:
        token_response = await prov.exchange_code(code=code, redirect_uri=redirect_uri)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Token exchange failed: {exc}")

    try:
        user = await prov.get_user(token_response.access_token)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"User info fetch failed: {exc}")

    set_provider_session(
        request,
        provider,
        access_token=token_response.access_token,
        user_id=user.id,
        username=user.username,
    )

    safe_next = _safe_next_url(
        next_url,
        auth_state.config.public_app_url,
    )
    return RedirectResponse(url=safe_next, status_code=307)


@router.get("/{provider}/logout")
async def auth_logout(
    request: Request,
    provider: str,
    next: str = "/",
) -> RedirectResponse:
    from covsrv.auth import auth_state

    clear_provider_session(request, provider)
    safe = _safe_next_url(next, (auth_state.config or _EMPTY_CONFIG).public_app_url)
    return RedirectResponse(url=safe, status_code=307)


@router.get("/logout")
async def auth_logout_all(
    request: Request,
    next: str = "/",
) -> RedirectResponse:
    from covsrv.auth import auth_state

    clear_all_sessions(request)
    safe = _safe_next_url(next, (auth_state.config or _EMPTY_CONFIG).public_app_url)
    return RedirectResponse(url=safe, status_code=307)


# Sentinel used only when config isn't loaded yet (shouldn't happen
# in normal operation but keeps mypy / runtime safe).
class _EmptyConfig:
    public_app_url = "http://localhost:8000"


_EMPTY_CONFIG = _EmptyConfig()
