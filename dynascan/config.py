"""Scan configuration (loadable from YAML/JSON)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ScanConfig:
    target: str
    authorized: bool = False                 # explicit confirmation of permission to test
    auth: dict[str, Any] | None = None       # {"type": "form"|"bearer"|"apikey"|"headers"|"token_login", ...}
    openapi: str | None = None               # path or URL to an OpenAPI/Swagger document
    seeds: list[str] = field(default_factory=list)          # extra start URLs
    allowed_hosts: list[str] = field(default_factory=list)  # defaults to target host
    exclude_paths: list[str] = field(default_factory=list)  # regexes never requested
    headers: dict[str, str] = field(default_factory=dict)
    # crawling
    max_pages: int = 150
    max_depth: int = 4
    # behaviour
    active: bool = True                      # False = passive/host checks only (no payloads)
    allow_unsafe_methods: bool = False       # fuzz PUT/PATCH/DELETE too
    only_checks: list[str] = field(default_factory=list)
    skip_checks: list[str] = field(default_factory=list)
    login_attempts: int = 12
    # transport
    requests_per_second: float = 15.0
    concurrency: int = 8
    timeout: float = 15.0
    verify_tls: bool = True
    proxy: str | None = None
    max_requests: int = 5000

    @classmethod
    def from_file(cls, path: str | Path) -> "ScanConfig":
        text = Path(path).read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except ValueError:
            data = yaml.safe_load(text)
        return cls.from_dict(data or {})

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanConfig":
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"unknown config keys: {', '.join(sorted(unknown))}")
        if "target" not in data:
            raise ValueError("config must define 'target'")
        return cls(**data)

    def redacted(self) -> dict[str, Any]:
        """Config safe to embed in reports (secrets removed)."""
        d = {f.name: getattr(self, f.name) for f in fields(self)}
        if d.get("auth"):
            d["auth"] = {k: ("***" if k in ("password", "token", "key", "cookies", "headers") else v)
                         for k, v in d["auth"].items()}
        return d
