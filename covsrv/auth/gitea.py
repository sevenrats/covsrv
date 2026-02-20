"""Gitea OIDC / OAuth2 provider implementation."""

from __future__ import annotations

from urllib.parse import urlencode

import httpx

from covsrv.auth.config import ProviderConfig
from covsrv.auth.provider import OAuthProvider, ProviderUser, RepoAccess, TokenResponse


class GiteaProvider(OAuthProvider):
    """Gitea OIDC provider.

    Uses the Gitea REST API (``/api/v1``) with the user's OAuth access
    token to verify repository visibility.
    """

    def __init__(self, config: ProviderConfig) -> None:
        self._config = config

    @property
    def name(self) -> str:
        return "gitea"

    async def get_authorize_url(self, state: str, redirect_uri: str) -> str:
        params = {
            "client_id": self._config.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(self._config.scopes),
            "state": state,
        }
        return f"{self._config.authorize_url}?{urlencode(params)}"

    async def exchange_code(self, code: str, redirect_uri: str) -> TokenResponse:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                self._config.token_url,
                data={
                    "client_id": self._config.client_id,
                    "client_secret": self._config.client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri,
                },
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()

        if "error" in data:
            desc = data.get("error_description", data["error"])
            raise ValueError(f"Gitea token error: {desc}")

        return TokenResponse(
            access_token=data["access_token"],
            token_type=data.get("token_type", "bearer"),
            refresh_token=data.get("refresh_token"),
            expires_in=data.get("expires_in"),
            scope=data.get("scope"),
            id_token=data.get("id_token"),
        )

    async def get_user(self, access_token: str) -> ProviderUser:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                self._config.userinfo_url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        # Gitea OIDC userinfo returns "sub" + "preferred_username"
        user_id = str(data.get("sub", data.get("id", "")))
        username = data.get(
            "preferred_username", data.get("login", data.get("name", ""))
        )

        return ProviderUser(
            id=user_id,
            username=username,
            provider="gitea",
        )

    async def can_view_repo(
        self, access_token: str, owner: str, repo: str
    ) -> RepoAccess:
        """GET /api/v1/repos/{owner}/{repo} — 200 means visible, 401 means token expired."""
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{self._config.api_base_url}/repos/{owner}/{repo}",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
        if resp.status_code == 200:
            return RepoAccess.ALLOWED
        if resp.status_code == 401:
            return RepoAccess.TOKEN_EXPIRED
        return RepoAccess.DENIED

    async def is_repo_public(self, owner: str, repo: str) -> bool:
        """Anonymous GET — 200 means public."""
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{self._config.api_base_url}/repos/{owner}/{repo}",
                headers={"Accept": "application/json"},
            )
        return resp.status_code == 200
