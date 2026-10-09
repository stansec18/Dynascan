"""Async, scope-aware, rate-limited HTTP client used by every component."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .scope import Scope

DEFAULT_UA = "Dynascan/0.1 (+authorised security testing)"


@dataclass
class ClientConfig:
    timeout: float = 15.0
    max_concurrency: int = 8
    requests_per_second: float = 15.0  # global politeness limit
    verify_tls: bool = True
    follow_redirects: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None
    max_requests: int = 5000  # hard cap per scan


class RequestBudgetExceeded(Exception):
    pass


class ScanClient:
    """Wraps httpx.AsyncClient adding scope checks, rate limiting and a request budget.

    A ScanClient owns its own cookie jar and default headers, so an anonymous client
    and an authenticated client can be used side by side to compare responses.
    """

    def __init__(self, scope: Scope, cfg: ClientConfig | None = None, *,
                 transport: httpx.AsyncBaseTransport | None = None, label: str = "anon") -> None:
        self.scope = scope
        self.cfg = cfg or ClientConfig()
        self.label = label
        self.request_count = 0
        self._sem = asyncio.Semaphore(self.cfg.max_concurrency)
        self._lock = asyncio.Lock()
        self._next_slot = 0.0
        headers = {"User-Agent": DEFAULT_UA, **self.cfg.headers}
        self._client = httpx.AsyncClient(
            timeout=self.cfg.timeout,
            verify=self.cfg.verify_tls,
            follow_redirects=self.cfg.follow_redirects,
            headers=headers,
            proxy=self.cfg.proxy,
            transport=transport,
        )

    # -- configuration helpers -------------------------------------------------
    def set_header(self, name: str, value: str) -> None:
        self._client.headers[name] = value

    def remove_header(self, name: str) -> None:
        self._client.headers.pop(name, None)

    @property
    def cookies(self) -> httpx.Cookies:
        return self._client.cookies

    @property
    def headers(self) -> httpx.Headers:
        return self._client.headers

    # -- request ---------------------------------------------------------------
    async def _throttle(self) -> None:
        if self.cfg.requests_per_second <= 0:
            return
        interval = 1.0 / self.cfg.requests_per_second
        async with self._lock:
            now = time.monotonic()
            wait = self._next_slot - now
            self._next_slot = max(now, self._next_slot) + interval
        if wait > 0:
            await asyncio.sleep(wait)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response | None:
        """Send a request. Returns None on network error. Raises OutOfScopeError off-scope."""
        self.scope.check(url)
        if self.request_count >= self.cfg.max_requests:
            raise RequestBudgetExceeded(f"request budget of {self.cfg.max_requests} reached")
        async with self._sem:
            await self._throttle()
            self.request_count += 1
            try:
                return await self._client.request(method, url, **kwargs)
            except (httpx.HTTPError, httpx.InvalidURL):
                return None

    async def get(self, url: str, **kw: Any) -> httpx.Response | None:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw: Any) -> httpx.Response | None:
        return await self.request("POST", url, **kw)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "ScanClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()


def format_request(resp: httpx.Response) -> str:
    """Compact, human-readable request line + selected headers for evidence."""
    req = resp.request
    lines = [f"{req.method} {req.url}"]
    for h in ("Host", "Content-Type", "Authorization", "Cookie"):
        if h.lower() in req.headers:
            v = req.headers[h]
            if h in ("Authorization", "Cookie") and len(v) > 24:
                v = v[:12] + "…[redacted]"
            lines.append(f"{h}: {v}")
    body = req.content[:300].decode("utf-8", "replace") if req.content else ""
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines)


def snippet(resp: httpx.Response, needle: str | None = None, width: int = 160) -> str:
    """Return a short response excerpt, centred on ``needle`` if present."""
    text = resp.text or ""
    if needle and needle in text:
        i = text.index(needle)
        s = max(0, i - width // 2)
        return text[s: s + width + len(needle)]
    return text[:width]
