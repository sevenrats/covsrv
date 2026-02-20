"""TTL cache for authorization decisions.

Keys are ``(provider, user_id, owner, repo)`` tuples.  Values are
``True`` (allowed) or ``False`` (denied) with a monotonic timestamp.
Expired entries are lazily evicted.
"""

from __future__ import annotations

import time
from threading import Lock


class AuthzCache:
    """Thread-safe, bounded TTL cache for authz decisions."""

    def __init__(self, ttl: int = 60, max_size: int = 10_000) -> None:
        self._ttl = ttl
        self._max_size = max_size
        self._cache: dict[str, tuple[bool, float]] = {}
        self._lock = Lock()

    # ------------------------------------------------------------------ key

    @staticmethod
    def _key(provider: str, user_id: str, owner: str, repo: str) -> str:
        return f"{provider}\x00{user_id}\x00{owner}\x00{repo}"

    # ------------------------------------------------------------------ API

    def get(self, provider: str, user_id: str, owner: str, repo: str) -> bool | None:
        """Return cached decision, or ``None`` on miss / expiry."""
        key = self._key(provider, user_id, owner, repo)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            allowed, ts = entry
            if time.monotonic() - ts > self._ttl:
                del self._cache[key]
                return None
            return allowed

    def set(
        self,
        provider: str,
        user_id: str,
        owner: str,
        repo: str,
        allowed: bool,
    ) -> None:
        """Store an authz decision with the current timestamp."""
        key = self._key(provider, user_id, owner, repo)
        with self._lock:
            if len(self._cache) >= self._max_size:
                self._evict_expired()
            self._cache[key] = (allowed, time.monotonic())

    def clear(self) -> None:
        """Drop every cached entry."""
        with self._lock:
            self._cache.clear()

    def clear_user(self, provider: str, user_id: str) -> None:
        """Drop all cached entries for a specific provider + user."""
        prefix = f"{provider}\x00{user_id}\x00"
        with self._lock:
            keys = [k for k in self._cache if k.startswith(prefix)]
            for k in keys:
                del self._cache[k]

    # ------------------------------------------------------------------ internal

    def _evict_expired(self) -> None:
        now = time.monotonic()
        expired = [k for k, (_, ts) in self._cache.items() if now - ts > self._ttl]
        for k in expired:
            del self._cache[k]
