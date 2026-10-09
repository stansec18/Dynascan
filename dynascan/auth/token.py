from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

from ..http_client import ScanClient
from .base import AuthHandler, AuthError


class BearerAuth(AuthHandler):
    """Static bearer token / JWT supplied by the tester."""

    def __init__(self, token: str, header: str = "Authorization", scheme: str = "Bearer") -> None:
        self.token = token
        self.header = header
        self.scheme = scheme
        self.description = "bearer token"

    async def apply(self, client: ScanClient, base_url: str) -> None:
        value = f"{self.scheme} {self.token}".strip()
        client.set_header(self.header, value)


class ApiKeyAuth(AuthHandler):
    """API key sent in a header (default) or query-string via default params."""

    def __init__(self, key: str, header: str = "X-API-Key") -> None:
        self.key = key
        self.header = header
        self.description = f"API key in {header}"

    async def apply(self, client: ScanClient, base_url: str) -> None:
        client.set_header(self.header, self.key)


class HeadersAuth(AuthHandler):
    """Arbitrary custom headers and/or cookies."""

    def __init__(self, headers: dict[str, str] | None = None,
                 cookies: dict[str, str] | None = None) -> None:
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.description = "custom headers/cookies"

    async def apply(self, client: ScanClient, base_url: str) -> None:
        for k, v in self.headers.items():
            client.set_header(k, v)
        for k, v in self.cookies.items():
            client.cookies.set(k, v)


class TokenLoginAuth(AuthHandler):
    """POST credentials (JSON) to a login endpoint and extract a token from the response.

    ``token_path`` is a dotted path into the JSON response, e.g. ``data.access_token``.
    """

    def __init__(self, login_url: str, username: str, password: str,
                 username_field: str = "username", password_field: str = "password",
                 token_path: str = "token", header: str = "Authorization",
                 scheme: str = "Bearer", extra_fields: dict[str, Any] | None = None) -> None:
        self.login_url = login_url
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.token_path = token_path
        self.header = header
        self.scheme = scheme
        self.extra_fields = extra_fields or {}
        self.description = f"token login as '{username}'"

    async def apply(self, client: ScanClient, base_url: str) -> None:
        body = {**self.extra_fields, self.username_field: self.username,
                self.password_field: self.password}
        resp = await client.post(urljoin(base_url, self.login_url), json=body)
        if resp is None or resp.status_code >= 400:
            raise AuthError(f"token login failed (HTTP {resp.status_code if resp else 'n/a'})")
        try:
            node: Any = resp.json()
        except ValueError as e:  # noqa: PERF203
            raise AuthError("token login response was not JSON") from e
        for part in self.token_path.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                raise AuthError(f"token path '{self.token_path}' not found in login response")
        if not isinstance(node, str) or not node:
            raise AuthError("extracted token is empty")
        client.set_header(self.header, f"{self.scheme} {node}".strip())
