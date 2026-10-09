"""Check framework: every check is a small class registered in the registry."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

import httpx

from ..http_client import ScanClient, format_request, snippet
from ..models import Endpoint, Finding, ScanResult

if TYPE_CHECKING:
    pass


@dataclass
class CheckContext:
    """Everything a check needs. ``client`` is authenticated when the scan is."""
    base_url: str
    client: ScanClient
    anon_client: ScanClient
    result: ScanResult
    authenticated: bool = False
    endpoints: list[Endpoint] = field(default_factory=list)
    pages: dict[str, str] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)
    # filled by the engine: cache of baseline responses keyed by endpoint key
    baselines: dict[str, httpx.Response | None] = field(default_factory=dict)

    def report(self, f: Finding) -> None:
        f.authenticated = self.authenticated
        self.result.add(f)


class Check:
    """Base class. ``kind`` selects when the engine runs the check:

    * ``host``     - once per target (``run_host``)
    * ``passive``  - on every baseline response (``run_response``) - no extra traffic
    * ``active``   - per endpoint, sends modified requests (``run_endpoint``)
    """
    id: ClassVar[str] = "base"
    title: ClassVar[str] = ""
    kind: ClassVar[str] = "passive"
    severity: ClassVar[str] = "low"
    owasp_web: ClassVar[list[str]] = []
    owasp_api: ClassVar[list[str]] = []
    cwe: ClassVar[list[str]] = []
    remediation: ClassVar[str] = ""
    references: ClassVar[list[str]] = []

    async def run_host(self, ctx: CheckContext) -> None:  # pragma: no cover - default no-op
        return None

    async def run_response(self, ctx: CheckContext, ep: Endpoint, resp: httpx.Response) -> None:  # pragma: no cover
        return None

    async def run_endpoint(self, ctx: CheckContext, ep: Endpoint) -> None:  # pragma: no cover
        return None

    # -- helper to build findings with the check's static metadata ---------------
    def finding(self, *, url: str, description: str, method: str = "GET", parameter: str = "",
                evidence: str = "", resp: httpx.Response | None = None, needle: str | None = None,
                severity: str | None = None, confidence: str = "medium", title: str | None = None,
                remediation: str | None = None) -> Finding:
        return Finding(
            check_id=self.id,
            title=title or self.title,
            severity=severity or self.severity,
            description=description,
            url=url,
            method=method,
            parameter=parameter,
            evidence=evidence,
            request=format_request(resp) if resp is not None else "",
            response_snippet=snippet(resp, needle) if resp is not None else "",
            remediation=remediation or self.remediation,
            cwe=list(self.cwe),
            owasp_web=list(self.owasp_web),
            owasp_api=list(self.owasp_api),
            confidence=confidence,
            references=list(self.references),
        )


REGISTRY: list[Check] = []


def register(cls: type[Check]) -> type[Check]:
    REGISTRY.append(cls())
    return cls
