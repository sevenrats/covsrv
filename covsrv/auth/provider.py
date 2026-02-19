"""Provider abstraction: base class and data models."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProviderUser:
    """Authenticated user identity from a provider."""

    id: str
    username: str
    provider: str


@dataclass(frozen=True, slots=True)
class TokenResponse:
    """Token data returned after OAuth code exchange."""

    access_token: str
    token_type: str = "bearer"
    refresh_token: str | None = None
    expires_in: int | None = None
    scope: str | None = None
    id_token: str | None = None  # OIDC only


@dataclass(frozen=True, slots=True)
class ResourceDescriptor:
    """Describes a provider resource to check access for."""

    provider: str
    owner: str
    repo: str
    resource_type: str = "repo"  # "repo" | "file" | "wiki"
    path: str | None = None
    ref: str | None = None


class OAuthProvider(ABC):
    """Abstract base class for OAuth/OIDC providers.

    Each concrete provider must implement the four abstract methods.
    Adding a new provider (e.g. GitLab) means adding one file that
    subclasses this — no changes to core logic.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short, stable identifier for this provider (e.g. 'github')."""
        ...

    @abstractmethod
    async def get_authorize_url(self, state: str, redirect_uri: str) -> str:
        """Return the URL the user's browser should be redirected to."""
        ...

    @abstractmethod
    async def exchange_code(self, code: str, redirect_uri: str) -> TokenResponse:
        """Exchange an authorization code for tokens."""
        ...

    @abstractmethod
    async def get_user(self, access_token: str) -> ProviderUser:
        """Fetch the authenticated user's identity."""
        ...

    @abstractmethod
    async def can_view_repo(self, access_token: str, owner: str, repo: str) -> bool:
        """Return True iff the token bearer can view ``owner/repo``."""
        ...

    async def is_repo_public(self, owner: str, repo: str) -> bool:
        """Return True if ``owner/repo`` is publicly visible (no auth needed).

        Default implementation returns False (assume private).  Providers
        should override to make an anonymous API call.
        """
        return False

    async def can_view(self, access_token: str, resource: ResourceDescriptor) -> bool:
        """Check if the user can view the given resource.

        Default implementation delegates to the repo-level check.
        Override in subclasses for finer-grained checks.
        """
        return await self.can_view_repo(access_token, resource.owner, resource.repo)
