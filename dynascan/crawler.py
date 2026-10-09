"""Breadth-first HTML crawler that discovers links and forms."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urldefrag, urlsplit, parse_qsl

from bs4 import BeautifulSoup

from .http_client import ScanClient
from .models import Endpoint, Param

_SKIP_EXT = re.compile(
    r"\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|mp4|mp3|webm|pdf|zip|gz|map)$", re.I)
_LOGOUT = re.compile(r"(logout|signout|sign-out|log-out|delete|remove)", re.I)


class Crawler:
    def __init__(self, client: ScanClient, max_pages: int = 150, max_depth: int = 4) -> None:
        self.client = client
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.visited: set[str] = set()
        self.endpoints: dict[str, Endpoint] = {}
        self.pages: dict[str, str] = {}  # url -> html (used by passive checks)

    def _add(self, ep: Endpoint) -> None:
        self.endpoints.setdefault(ep.key, ep)

    async def crawl(self, start_urls: list[str]) -> list[Endpoint]:
        queue: list[tuple[str, int]] = [(u, 0) for u in start_urls]
        while queue and len(self.visited) < self.max_pages:
            batch = []
            while queue and len(batch) < 6:
                url, depth = queue.pop(0)
                url, _ = urldefrag(url)
                if url in self.visited or depth > self.max_depth:
                    continue
                if _SKIP_EXT.search(urlsplit(url).path) or not self.client.scope.allows(url):
                    continue
                if _LOGOUT.search(urlsplit(url).path):
                    continue  # never trigger destructive/logout links
                self.visited.add(url)
                batch.append((url, depth))
            if not batch:
                continue
            results = await asyncio.gather(*(self._fetch(u, d) for u, d in batch))
            for links in results:
                queue.extend(links)
        return list(self.endpoints.values())

    async def _fetch(self, url: str, depth: int) -> list[tuple[str, int]]:
        resp = await self.client.get(url)
        if resp is None:
            return []
        sp = urlsplit(url)
        params = [Param(k, "query", v) for k, v in parse_qsl(sp.query)]
        self._add(Endpoint("GET", url, params, source="crawl"))
        if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
            nxt = urljoin(url, resp.headers["location"])
            return [(nxt, depth + 1)]
        ctype = resp.headers.get("content-type", "")
        if "html" not in ctype:
            return []
        self.pages[url] = resp.text
        soup = BeautifulSoup(resp.text, "html.parser")
        out: list[tuple[str, int]] = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            out.append((urljoin(url, href), depth + 1))
        for tag in soup.find_all(["script", "iframe", "frame"], src=True):
            pass  # static assets are not crawled, but kept for passive analysis
        for form in soup.find_all("form"):
            self._add(self._form_endpoint(url, form))
        return out

    @staticmethod
    def _form_endpoint(page_url: str, form) -> Endpoint:
        action = urljoin(page_url, form.get("action") or page_url)
        method = (form.get("method") or "GET").upper()
        params: list[Param] = []
        for el in form.find_all(["input", "textarea", "select"]):
            name = el.get("name")
            if not name:
                continue
            itype = (el.get("type") or "text").lower()
            if itype in ("submit", "button", "image", "reset", "file"):
                continue
            params.append(Param(name, "form" if method != "GET" else "query", el.get("value", "") or ""))
        ep = Endpoint(method, action, params, body_type="form" if method != "GET" else "",
                      source="crawl")
        ep.description = f"HTML form on {page_url}"
        return ep
