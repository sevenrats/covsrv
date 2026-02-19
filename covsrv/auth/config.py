"""Authentication configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProviderConfig:
    """Configuration for a single OAuth/OIDC provider."""

    name: str
    client_id: str
    client_secret: str
    base_url: str  # e.g. "https://github.com"
    api_base_url: str  # e.g. "https://api.github.com"
    authorize_url: str
    token_url: str
    userinfo_url: str
    scopes: list[str] = field(default_factory=list)


# ------------------------------------------------------------------
# Per-provider config builders
# ------------------------------------------------------------------


def _github_config() -> ProviderConfig | None:
    client_id = os.environ.get("COVSRV_GITHUB_CLIENT_ID", "")
    client_secret = os.environ.get("COVSRV_GITHUB_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        return None
    return ProviderConfig(
        name="github",
        client_id=client_id,
        client_secret=client_secret,
        base_url="https://github.com",
        api_base_url="https://api.github.com",
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        userinfo_url="https://api.github.com/user",
        # 'repo' scope gives read access to private repos
        scopes=["read:org", "repo"],
    )


def _gitea_config() -> ProviderConfig | None:
    client_id = os.environ.get("COVSRV_GITEA_CLIENT_ID", "")
    client_secret = os.environ.get("COVSRV_GITEA_CLIENT_SECRET", "")
    base_url = os.environ.get("COVSRV_GITEA_URL", "")
    if not client_id or not client_secret or not base_url:
        return None
    base = base_url.rstrip("/")
    return ProviderConfig(
        name="gitea",
        client_id=client_id,
        client_secret=client_secret,
        base_url=base,
        api_base_url=f"{base}/api/v1",
        authorize_url=f"{base}/login/oauth/authorize",
        token_url=f"{base}/login/oauth/access_token",
        userinfo_url=f"{base}/login/oauth/userinfo",
        scopes=["openid", "profile", "email"],
    )


# ------------------------------------------------------------------
# Top-level config
# ------------------------------------------------------------------


@dataclass(frozen=True)
class AuthConfig:
    """Aggregated auth configuration."""

    enabled: bool
    session_secret: str
    providers: dict[str, ProviderConfig]
    # Maps normalised base_url → provider name
    url_to_provider: dict[str, str]
    cache_ttl: int  # seconds
    public_app_url: str  # used to build OAuth callback URLs


def load_auth_config() -> AuthConfig:
    """Build an ``AuthConfig`` from environment variables.

    Environment variables
    ---------------------
    COVSRV_AUTH_ENABLED      : "true" / "1" / "yes" to enable  (default: disabled)
    COVSRV_SESSION_SECRET    : secret for signing session cookies
    COVSRV_AUTH_CACHE_TTL    : authz cache TTL in seconds  (default: 60)
    COVSRV_PUBLIC_URL        : externally-reachable base URL of this app

    GitHub provider:
        COVSRV_GITHUB_CLIENT_ID
        COVSRV_GITHUB_CLIENT_SECRET

    Gitea provider:
        COVSRV_GITEA_URL           : e.g. "https://gitea.example.com"
        COVSRV_GITEA_CLIENT_ID
        COVSRV_GITEA_CLIENT_SECRET
    """
    enabled = os.environ.get("COVSRV_AUTH_ENABLED", "false").lower() in (
        "1",
        "true",
        "yes",
    )
    session_secret = os.environ.get("COVSRV_SESSION_SECRET", "change-me-in-production")
    cache_ttl = int(os.environ.get("COVSRV_AUTH_CACHE_TTL", "60"))
    public_app_url = os.environ.get(
        "COVSRV_PUBLIC_URL", "http://localhost:8000"
    ).rstrip("/")

    providers: dict[str, ProviderConfig] = {}
    url_to_provider: dict[str, str] = {}

    gh = _github_config()
    if gh:
        providers[gh.name] = gh
        url_to_provider[gh.base_url] = gh.name

    gt = _gitea_config()
    if gt:
        providers[gt.name] = gt
        url_to_provider[gt.base_url] = gt.name

    return AuthConfig(
        enabled=enabled,
        session_secret=session_secret,
        providers=providers,
        url_to_provider=url_to_provider,
        cache_ttl=cache_ttl,
        public_app_url=public_app_url,
    )
