"""Declarative configuration manager for covsrv.

Parses a TOML config file and provides:

* Hierarchical report-key verification (global → provider → owner → repo).
* Provider configuration for OAuth and report ingestion.
* Conversion helpers to build ``AuthConfig`` / ``ProviderConfig`` objects
  consumed by the auth subsystem.

The config file is the **single source of truth** for provider definitions,
report keys, and global settings.  Environment variables are still honoured
as a fallback when no config file is present.
"""

from __future__ import annotations

import hmac
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ------------------------------------------------------------------
# Data classes
# ------------------------------------------------------------------

_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


@dataclass(frozen=True)
class RepoConfig:
    """Configuration for a specific repository within a provider."""

    name: str  # "owner/repo"
    report_key: str | None = None


@dataclass(frozen=True)
class OwnerConfig:
    """Configuration for a repository owner within a provider."""

    name: str
    report_key: str | None = None


@dataclass(frozen=True)
class ProviderEntry:
    """Configuration for a single provider instance.

    ``name`` is the user-chosen unique identifier (e.g. ``"my-gitea"``).
    ``type`` selects the backend implementation (``"github"`` or ``"gitea"``).
    """

    name: str
    type: str  # "github" | "gitea"
    url: str
    report_key: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    owners: dict[str, OwnerConfig] = field(default_factory=dict)
    repos: dict[str, RepoConfig] = field(default_factory=dict)

    @property
    def oauth_configured(self) -> bool:
        """True when client credentials are present (OAuth login possible)."""
        return bool(self.client_id and self.client_secret)


@dataclass(frozen=True)
class GlobalConfig:
    """Top-level / global settings."""

    report_key: str | None = None
    public_url: str = "http://localhost:8000"
    session_secret: str = "change-me-in-production"
    auth_enabled: bool = False
    auth_cache_ttl: int = 60


# ------------------------------------------------------------------
# ConfigManager
# ------------------------------------------------------------------


class ConfigManager:
    """Manages the declarative TOML configuration for covsrv.

    Typical usage::

        cfg = ConfigManager.from_file(Path("config.toml"))
        cfg.verify_report_key(token, "my-gitea", "sevenrats", "covsrv")
    """

    def __init__(
        self,
        global_config: GlobalConfig,
        providers: dict[str, ProviderEntry],
    ) -> None:
        self._global = global_config
        self._providers = providers

    # -------------------------------------------------------------- factories

    @classmethod
    def from_file(cls, path: Path) -> ConfigManager:
        """Load configuration from a TOML file."""
        with open(path, "rb") as f:
            raw = tomllib.load(f)
        return cls._from_dict(raw)

    @classmethod
    def from_str(cls, toml_str: str) -> ConfigManager:
        """Load configuration from a TOML string (handy for tests)."""
        raw = tomllib.loads(toml_str)
        return cls._from_dict(raw)

    @classmethod
    def _from_dict(cls, raw: dict[str, Any]) -> ConfigManager:
        """Build a ``ConfigManager`` from a parsed TOML dictionary."""
        # -- global section --
        g = raw.get("global", {})
        global_config = GlobalConfig(
            report_key=g.get("report_key") or None,
            public_url=str(g.get("public_url", "http://localhost:8000")).rstrip("/"),
            session_secret=str(g.get("session_secret", "change-me-in-production")),
            auth_enabled=bool(g.get("auth_enabled", False)),
            auth_cache_ttl=int(g.get("auth_cache_ttl", 60)),
        )

        # -- providers section --
        providers: dict[str, ProviderEntry] = {}
        for name, pdata in raw.get("providers", {}).items():
            if not isinstance(pdata, dict):
                continue

            # Validate provider name (used in URL paths)
            if not _NAME_RE.match(name):
                raise ValueError(
                    f"Provider name {name!r} is invalid; "
                    "use only letters, digits, hyphens, and underscores"
                )

            ptype = pdata.get("type", "")
            if not ptype:
                raise ValueError(f"Provider {name!r} missing required 'type' field")

            url = pdata.get("url", "")
            if not url:
                raise ValueError(f"Provider {name!r} missing required 'url' field")

            # Parse owners
            owners: dict[str, OwnerConfig] = {}
            for oname, odata in pdata.get("owners", {}).items():
                if isinstance(odata, dict):
                    owners[oname.strip()] = OwnerConfig(
                        name=oname.strip(),
                        report_key=odata.get("report_key") or None,
                    )

            # Parse repos
            repos: dict[str, RepoConfig] = {}
            for rname, rdata in pdata.get("repos", {}).items():
                if isinstance(rdata, dict):
                    normalised = rname.strip().strip("/")
                    repos[normalised] = RepoConfig(
                        name=normalised,
                        report_key=rdata.get("report_key") or None,
                    )

            providers[name] = ProviderEntry(
                name=name,
                type=ptype,
                url=url.rstrip("/"),
                report_key=pdata.get("report_key") or None,
                client_id=pdata.get("client_id") or None,
                client_secret=pdata.get("client_secret") or None,
                owners=owners,
                repos=repos,
            )

        return cls(global_config, providers)

    @classmethod
    def default(cls) -> ConfigManager:
        """Return an empty (no providers, no keys) configuration."""
        return cls(GlobalConfig(), {})

    # -------------------------------------------------------------- accessors

    @property
    def global_config(self) -> GlobalConfig:
        return self._global

    @property
    def providers(self) -> dict[str, ProviderEntry]:
        return dict(self._providers)

    def get_provider(self, name: str) -> ProviderEntry | None:
        return self._providers.get(name)

    def provider_url(self, name: str) -> str | None:
        """Return the base URL for *name*, or ``None`` if unknown."""
        p = self._providers.get(name)
        return p.url if p else None

    # --------------------------------------------------- report-key verification

    def verify_report_key(
        self,
        key: str,
        provider_name: str,
        owner: str,
        repo: str,
    ) -> bool:
        """Check whether *key* authorises posting a report.

        The check is **hierarchical** — the most-specific matching key
        wins, but any level that matches grants access:

        1. **Repo-level** key  (``providers.<name>.repos."owner/repo"``)
        2. **Owner-level** key (``providers.<name>.owners.<owner>``)
        3. **Provider-level** key (``providers.<name>.report_key``)
        4. **Global** key       (``global.report_key``)

        All comparisons are constant-time (``hmac.compare_digest``).
        """
        provider = self._providers.get(provider_name)
        if provider is None:
            return False

        repo_full = f"{owner}/{repo}"

        # 1. Repo-level
        repo_cfg = provider.repos.get(repo_full)
        if repo_cfg and repo_cfg.report_key:
            if hmac.compare_digest(repo_cfg.report_key, key):
                return True

        # 2. Owner-level
        owner_cfg = provider.owners.get(owner)
        if owner_cfg and owner_cfg.report_key:
            if hmac.compare_digest(owner_cfg.report_key, key):
                return True

        # 3. Provider-level
        if provider.report_key:
            if hmac.compare_digest(provider.report_key, key):
                return True

        # 4. Global
        if self._global.report_key:
            if hmac.compare_digest(self._global.report_key, key):
                return True

        return False

    # -------------------------------------------- auth subsystem integration

    def to_auth_provider_config(self, entry: ProviderEntry):
        """Build an ``auth.config.ProviderConfig`` from a provider entry.

        Derives OAuth / API URLs automatically from the provider ``type``
        and ``url``.
        """
        from covsrv.auth.config import ProviderConfig

        base = entry.url.rstrip("/")

        if entry.type == "github":
            # GitHub has a separate API host
            api_base = "https://api.github.com"
            if base != "https://github.com":
                # GitHub Enterprise Server
                api_base = f"{base}/api/v3"
            return ProviderConfig(
                name=entry.name,
                client_id=entry.client_id or "",
                client_secret=entry.client_secret or "",
                base_url=base,
                api_base_url=api_base,
                authorize_url=f"{base}/login/oauth/authorize",
                token_url=f"{base}/login/oauth/access_token",
                userinfo_url=f"{api_base}/user",
                scopes=["read:org", "repo"],
            )

        if entry.type == "gitea":
            return ProviderConfig(
                name=entry.name,
                client_id=entry.client_id or "",
                client_secret=entry.client_secret or "",
                base_url=base,
                api_base_url=f"{base}/api/v1",
                authorize_url=f"{base}/login/oauth/authorize",
                token_url=f"{base}/login/oauth/access_token",
                userinfo_url=f"{base}/login/oauth/userinfo",
                scopes=["openid", "profile", "email"],
            )

        raise ValueError(f"Unknown provider type: {entry.type!r}")

    def to_auth_config(self):
        """Build a complete ``AuthConfig`` from this configuration.

        Only providers with OAuth credentials (``client_id`` +
        ``client_secret``) are included.
        """
        from covsrv.auth.config import AuthConfig, ProviderConfig

        auth_providers: dict[str, ProviderConfig] = {}
        url_to_provider: dict[str, str] = {}

        for name, entry in self._providers.items():
            if not entry.oauth_configured:
                continue
            pc = self.to_auth_provider_config(entry)
            auth_providers[name] = pc
            url_to_provider[pc.base_url] = name

        return AuthConfig(
            enabled=self._global.auth_enabled,
            session_secret=self._global.session_secret,
            providers=auth_providers,
            url_to_provider=url_to_provider,
            cache_ttl=self._global.auth_cache_ttl,
            public_app_url=self._global.public_url,
        )
