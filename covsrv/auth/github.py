"""GitHub OAuth2 provider implementation."""

from __future__ import annotations

from urllib.parse import urlencode

import httpx

from covsrv.auth.config import ProviderConfig
from covsrv.auth.provider import OAuthProvider, ProviderUser, RepoAccess, TokenResponse


class GitHubProvider(OAuthProvider):
    """GitHub OAuth2 provider.

    Uses the GitHub REST API with the user's access token to verify
    repository visibility.
    """

    def __init__(self, config: ProviderConfig) -> None:
        self._config = config

    @property
    def name(self) -> str:
        return self._config.name

    async def get_authorize_url(self, state: str, redirect_uri: str) -> str:
        params = {
            "client_id": self._config.client_id,
            "redirect_uri": redirect_uri,
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
                    "redirect_uri": redirect_uri,
                },
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()

        if "error" in data:
            desc = data.get("error_description", data["error"])
            raise ValueError(f"GitHub token error: {desc}")

        return TokenResponse(
            access_token=data["access_token"],
            token_type=data.get("token_type", "bearer"),
            scope=data.get("scope"),
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

        return ProviderUser(
            id=str(data["id"]),
            username=data["login"],
            provider=self.name,
        )

    async def can_view_repo(
        self, access_token: str, owner: str, repo: str
    ) -> RepoAccess:
        """GET /repos/{owner}/{repo} — 200 means visible, 401 means token expired."""
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{self._config.api_base_url}/repos/{owner}/{repo}",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github+json",
                },
            )
        if resp.status_code == 200:
            return RepoAccess.ALLOWED
        if resp.status_code == 401:
            return RepoAccess.TOKEN_EXPIRED
        return RepoAccess.DENIED

    async def is_repo_public(self, owner: str, repo: str) -> bool:
        """Anonymous GET — public only when the API confirms ``private`` is false."""
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{self._config.api_base_url}/repos/{owner}/{repo}",
                headers={"Accept": "application/vnd.github+json"},
            )
        if resp.status_code != 200:
            return False
        try:
            data = resp.json()
        except Exception:
            return False
        return data.get("private") is False
