"""Scope enforcement. The scanner never sends requests outside the declared scope."""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit


class OutOfScopeError(Exception):
    pass


@dataclass
class Scope:
    """Defines which hosts/paths may be scanned.

    ``allowed_hosts`` supports fnmatch wildcards (``*.example.com``). When empty
    it defaults to the host of the target URL only.
    """
    target: str
    allowed_hosts: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)  # regexes
    authorized: bool = False  # user must confirm they are authorised to test

    def __post_init__(self) -> None:
        host = urlsplit(self.target).hostname or ""
        if not self.allowed_hosts:
            self.allowed_hosts = [host]
        self._excl = [re.compile(p) for p in self.exclude_paths]

    def require_authorization(self) -> None:
        if not self.authorized:
            raise OutOfScopeError(
                "Scan not started: you must confirm you are authorised to test this target "
                "(--i-am-authorized / the checkbox in the GUI)."
            )

    def host_ok(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        return any(fnmatch.fnmatch(host, pat.lower()) for pat in self.allowed_hosts)

    def path_ok(self, url: str) -> bool:
        path = urlsplit(url).path or "/"
        return not any(rx.search(path) for rx in self._excl)

    def allows(self, url: str) -> bool:
        return self.host_ok(url) and self.path_ok(url)

    def check(self, url: str) -> None:
        if not self.allows(url):
            raise OutOfScopeError(f"URL is out of scope: {url}")
