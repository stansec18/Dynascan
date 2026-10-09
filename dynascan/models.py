"""Core data models shared by the engine, reports and GUI."""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import Any
from urllib.parse import urlsplit

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Param:
    """An input the scanner can mutate."""
    name: str
    location: str  # query | form | json | path | header | cookie
    value: str = ""


@dataclass
class Endpoint:
    """A discovered request surface (page, form or API operation)."""
    method: str
    url: str
    params: list[Param] = field(default_factory=list)
    body_type: str = ""  # "" | form | json
    source: str = "crawl"  # crawl | openapi | seed
    requires_auth: bool | None = None  # filled when auth scan compares to anon
    description: str = ""

    @property
    def key(self) -> str:
        sp = urlsplit(self.url)
        names = ",".join(sorted(p.name for p in self.params))
        return f"{self.method.upper()} {sp.scheme}://{sp.netloc}{sp.path} [{names}]"

    @property
    def path(self) -> str:
        return urlsplit(self.url).path or "/"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    description: str
    url: str
    method: str = "GET"
    parameter: str = ""
    evidence: str = ""
    request: str = ""
    response_snippet: str = ""
    remediation: str = ""
    cwe: list[str] = field(default_factory=list)
    owasp_web: list[str] = field(default_factory=list)  # e.g. ["A03:2021"]
    owasp_api: list[str] = field(default_factory=list)  # e.g. ["API1:2023"]
    confidence: str = "medium"  # low | medium | high
    authenticated: bool = False
    references: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        raw = "|".join([self.check_id, self.method, self.url.split("?")[0], self.parameter])
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["id"] = self.fingerprint
        return d


@dataclass
class ScanResult:
    target: str
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    mode: str = "unauthenticated"  # unauthenticated | authenticated
    endpoints: list[Endpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    requests_made: int = 0
    notes: list[str] = field(default_factory=list)
    threat_model: dict[str, Any] = field(default_factory=dict)
    auth_summary: str = ""

    def add(self, finding: Finding) -> bool:
        """Add finding, de-duplicating on fingerprint. Returns True if new."""
        if any(f.fingerprint == finding.fingerprint for f in self.findings):
            return False
        self.findings.append(finding)
        return True

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.title))

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "mode": self.mode,
            "started": self.started,
            "finished": self.finished,
            "requests_made": self.requests_made,
            "auth_summary": self.auth_summary,
            "notes": self.notes,
            "counts": self.counts(),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "threat_model": self.threat_model,
        }
