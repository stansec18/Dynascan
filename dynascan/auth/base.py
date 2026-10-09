from __future__ import annotations

from abc import ABC, abstractmethod

from ..http_client import ScanClient


class AuthError(Exception):
    pass


class AuthHandler(ABC):
    """Prepares a ScanClient so that its requests are authenticated."""

    #: short human description used in reports (never includes secrets)
    description: str = "authenticated"

    @abstractmethod
    async def apply(self, client: ScanClient, base_url: str) -> None:
        """Authenticate ``client`` in place (set cookies / headers). Raises AuthError on failure."""

    async def verify(self, client: ScanClient, base_url: str) -> bool:
        """Optional post-login check; return True when the session looks valid."""
        return True
