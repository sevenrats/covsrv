"""Session helpers for reading / writing provider tokens.

Session data lives in ``request.session`` (provided by Starlette's
``SessionMiddleware``).  Layout::

    {
        "providers": {
            "github": {
                "access_token": "...",
                "user_id": "123",
                "username": "octocat",
            },
            "gitea": { ... },
        }
    }
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SessionRequest(Protocol):
    """Any object that exposes a mutable ``.session`` dict."""

    session: dict[str, Any]


def get_provider_session(
    request: SessionRequest, provider: str
) -> dict[str, Any] | None:
    """Return the stored session dict for *provider*, or ``None``."""
    providers = request.session.get("providers", {})
    data = providers.get(provider)
    if not data or not data.get("access_token"):
        return None
    return data


def set_provider_session(
    request: SessionRequest,
    provider: str,
    *,
    access_token: str,
    user_id: str,
    username: str,
    **extra: Any,
) -> None:
    """Store provider credentials in the session."""
    if "providers" not in request.session:
        request.session["providers"] = {}
    request.session["providers"][provider] = {
        "access_token": access_token,
        "user_id": user_id,
        "username": username,
        **extra,
    }


def clear_provider_session(request: SessionRequest, provider: str) -> None:
    """Remove session data for a single provider."""
    providers = request.session.get("providers", {})
    providers.pop(provider, None)


def clear_all_sessions(request: SessionRequest) -> None:
    """Remove all provider sessions."""
    request.session.pop("providers", None)
