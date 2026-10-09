"""Helpers for building mutated requests from an Endpoint."""
from __future__ import annotations

import random
import string
from typing import Any
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, quote

import httpx

from ..http_client import ScanClient
from ..models import Endpoint, Param


def rand_token(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def build_request(ep: Endpoint, overrides: dict[str, str] | None = None) -> tuple[str, str, dict[str, Any]]:
    """Return (method, url, kwargs) for ``ep`` with ``overrides`` replacing param values by name."""
    overrides = overrides or {}
    sp = urlsplit(ep.url)
    path = sp.path
    query = [(k, v) for k, v in parse_qsl(sp.query, keep_blank_values=True)]
    query_names = {k for k, _ in query}
    form: dict[str, str] = {}
    js: dict[str, Any] = {}
    headers: dict[str, str] = {}
    for p in ep.params:
        val = overrides.get(p.name, p.value)
        if p.location == "query":
            if p.name in query_names:
                query = [(k, val if k == p.name else v) for k, v in query]
            else:
                query.append((p.name, val))
                query_names.add(p.name)
        elif p.location == "form":
            form[p.name] = val
        elif p.location == "json":
            js[p.name] = _coerce(val, p.value)
        elif p.location == "header":
            headers[p.name] = val
        elif p.location == "path" and p.value:
            segs = path.split("/")
            for i in range(len(segs) - 1, -1, -1):
                if segs[i] == p.value:
                    segs[i] = quote(val, safe="")
                    break
            path = "/".join(segs)
    url = urlunsplit((sp.scheme, sp.netloc, path, urlencode(query), ""))
    kwargs: dict[str, Any] = {}
    if headers:
        kwargs["headers"] = headers
    if form or (ep.body_type == "form"):
        kwargs["data"] = form
    if js or (ep.body_type == "json"):
        kwargs["json"] = js
    return ep.method.upper(), url, kwargs


def _coerce(new: str, original: str) -> Any:
    """Keep numeric JSON fields numeric when the override is itself numeric."""
    if original.lstrip("-").isdigit() and new.lstrip("-").isdigit():
        return int(new)
    return new


async def send(client: ScanClient, ep: Endpoint, overrides: dict[str, str] | None = None,
               **extra: Any) -> httpx.Response | None:
    method, url, kwargs = build_request(ep, overrides)
    kwargs.update(extra)
    return await client.request(method, url, **kwargs)


def mutable_params(ep: Endpoint) -> list[Param]:
    return [p for p in ep.params if p.location in ("query", "form", "json", "path")]


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
