"""STRIDE threat model generated from the discovered attack surface and scan findings."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .models import Endpoint, Finding, ScanResult, SEVERITY_RANK


@dataclass
class Surface:
    """Summary of the application's attack surface derived from discovery."""
    endpoints: list[Endpoint]
    meta: dict[str, Any] = field(default_factory=dict)
    authenticated_scan: bool = False
    auth_description: str = ""

    def __post_init__(self) -> None:
        eps = self.endpoints
        self.params = [(e, p) for e in eps for p in e.params]
        self.api_eps = [e for e in eps if e.source == "openapi" or e.body_type == "json"
                        or re.search(r"/(api|v\d+|graphql|rest)(/|$)", e.path, re.I)]
        self.web_eps = [e for e in eps if e not in self.api_eps]
        self.forms = [e for e in eps if e.method == "POST" and e.source == "crawl"]
        self.login_eps = [e for e in eps if re.search(r"login|signin|auth|token|session", e.path, re.I)
                          and any(re.search("pass", p.name, re.I) for p in e.params)]
        self.id_params = [(e, p) for e, p in self.params if re.search(r"(^|_)id$", p.name, re.I)
                          or p.location == "path"]
        self.file_params = [(e, p) for e, p in self.params
                            if re.search(r"(file|path|page|template|include|dir|doc)", p.name, re.I)]
        self.url_params = [(e, p) for e, p in self.params
                           if re.search(r"(url|uri|link|webhook|callback|dest|redirect|fetch|proxy)", p.name, re.I)]
        self.json_eps = [e for e in eps if e.body_type == "json"]
        self.mutating = [e for e in eps if e.method in ("POST", "PUT", "PATCH", "DELETE")]


@dataclass
class ThreatDef:
    key: str
    stride: str
    component: str
    threat: str
    owasp_web: list[str]
    owasp_api: list[str]
    impact: int  # 1 low .. 3 high
    mitigations: list[str]
    relevant: Callable[[Surface], bool]
    check_prefixes: list[str]
    testable: bool = True  # False -> cannot be validated by DAST, flagged for manual review


def _always(_: Surface) -> bool:
    return True


THREATS: list[ThreatDef] = [
    ThreatDef("S1", "Spoofing", "Authentication",
              "Attacker guesses or stuffs credentials against login/token endpoints to impersonate users.",
              ["A07:2021"], ["API2:2023"], 3,
              ["Rate limiting and lockout", "MFA", "Breached-password screening", "Uniform error messages"],
              lambda s: bool(s.login_eps), ["login-no-ratelimit"]),
    ThreatDef("S2", "Spoofing", "Session / token management",
              "Session cookies or tokens are stolen, forged or replayed because of weak flags or JWT configuration.",
              ["A07:2021", "A02:2021"], ["API2:2023"], 3,
              ["Secure/HttpOnly/SameSite cookies", "Short-lived tokens with validated alg/aud/iss", "Server-side revocation"],
              lambda s: s.authenticated_scan or bool(s.login_eps), ["cookie-flags", "jwt-weak"]),
    ThreatDef("S3", "Spoofing", "Browser trust (CSRF / CORS)",
              "A malicious site makes the victim's browser perform authenticated actions or read authenticated responses.",
              ["A01:2021", "A05:2021"], ["API8:2023"], 2,
              ["Anti-CSRF tokens", "SameSite cookies", "Strict CORS allow-list"],
              lambda s: bool(s.forms) or bool(s.api_eps), ["csrf-missing", "cors-misconfig"]),
    ThreatDef("T1", "Tampering", "Data layer / interpreters",
              "Untrusted input alters SQL queries or template evaluation, allowing data theft or modification.",
              ["A03:2021"], [], 3,
              ["Parameterised queries", "Input validation", "Least-privilege DB accounts", "Sandboxed templating"],
              lambda s: bool(s.params), ["sqli-", "ssti"]),
    ThreatDef("T2", "Tampering", "Object references / API parameters",
              "Attacker alters object identifiers or JSON properties to read or modify objects they do not own.",
              ["A01:2021", "A04:2021"], ["API1:2023", "API3:2023"], 3,
              ["Ownership checks per request", "Explicit request/response schemas", "Reject unknown properties"],
              lambda s: bool(s.id_params) or bool(s.json_eps), ["bola-candidate", "api-excessive-data"]),
    ThreatDef("T3", "Tampering", "File handling",
              "File-name parameters are abused to read or overwrite files outside the intended directory.",
              ["A01:2021", "A03:2021"], ["API1:2023"], 3,
              ["Allow-listed base directory", "Canonicalise and validate paths"],
              lambda s: bool(s.file_params), ["path-traversal"]),
    ThreatDef("R1", "Repudiation", "Logging and monitoring",
              "Malicious actions cannot be attributed or detected because security events are not logged or alerted on.",
              ["A09:2021"], ["API8:2023"], 2,
              ["Log authentication, access-control and input-validation failures centrally", "Alerting and tamper-resistant logs"],
              _always, [], testable=False),
    ThreatDef("I1", "Information disclosure", "Error handling / content exposure",
              "Stack traces, secrets, debug endpoints or excessive API data leak information that enables further attacks.",
              ["A05:2021", "A02:2021"], ["API8:2023", "API3:2023"], 2,
              ["Generic errors", "Disable debug", "Remove sensitive files", "Response filtering"],
              _always, ["info-errors", "secrets-exposed", "exposed-files", "dir-listing", "info-banner"]),
    ThreatDef("I2", "Information disclosure", "Transport security",
              "Traffic is intercepted or downgraded because TLS or HSTS is missing.",
              ["A02:2021"], ["API8:2023"], 3,
              ["TLS 1.2+ everywhere", "HSTS with preload"],
              _always, ["transport-http", "headers-missing:strict"]),
    ThreatDef("I3", "Information disclosure", "API inventory",
              "Exposed API documentation, GraphQL introspection or legacy versions reveal and widen the attack surface.",
              ["A05:2021", "A06:2021"], ["API9:2023"], 2,
              ["Restrict docs in production", "Decommission old versions", "Maintain an API inventory"],
              lambda s: bool(s.api_eps), ["api-docs-exposed", "graphql-introspection", "api-old-version"]),
    ThreatDef("I4", "Information disclosure", "Browser-side content",
              "Script injected into pages steals sessions or data from other users (XSS, clickjacking).",
              ["A03:2021", "A05:2021"], [], 3,
              ["Output encoding", "Strict CSP", "Frame protections"],
              lambda s: bool(s.web_eps), ["xss-reflected", "headers-missing:content-security", "headers-missing:x-frame"]),
    ThreatDef("D1", "Denial of service", "Resource limits",
              "Missing rate limits and quotas allow automated abuse and resource exhaustion.",
              ["A04:2021"], ["API4:2023", "API6:2023"], 2,
              ["Per-client rate limits", "Payload/pagination limits", "Bot protection for business flows"],
              lambda s: bool(s.api_eps) or bool(s.login_eps), ["login-no-ratelimit"]),
    ThreatDef("E1", "Elevation of privilege", "Access control",
              "Users reach resources or functions beyond their privilege (forced browsing, missing function-level checks).",
              ["A01:2021"], ["API1:2023", "API5:2023"], 3,
              ["Deny by default", "Central authorisation layer", "Automated authorisation tests"],
              _always, ["authz-unauth-access", "bola-candidate", "open-redirect"]),
    ThreatDef("E2", "Elevation of privilege", "Outbound requests",
              "The server is coerced into calling internal services or cloud metadata endpoints (SSRF).",
              ["A10:2021"], ["API7:2023"], 3,
              ["URL allow-lists", "Block internal ranges", "Egress filtering and IMDSv2"],
              lambda s: bool(s.url_params), ["ssrf-candidate"]),
    ThreatDef("E3", "Elevation of privilege", "Third-party components",
              "Known vulnerabilities in outdated components are exploited to take over the application.",
              ["A06:2021"], ["API8:2023"], 3,
              ["Software composition analysis", "Patch management", "Hide version banners"],
              _always, ["info-banner"], testable=True),
]

_SEV_LIKELIHOOD = {"critical": 3, "high": 3, "medium": 2, "low": 1, "info": 1}
_RISK_LABEL = [(9, "Critical"), (6, "High"), (4, "Medium"), (0, "Low")]


def _risk_label(score: int) -> str:
    for threshold, label in _RISK_LABEL:
        if score >= threshold:
            return label
    return "Low"


def _match(f: Finding, prefixes: list[str]) -> bool:
    return any(f.check_id.startswith(p) for p in prefixes)


def build_threat_model(result: ScanResult, surface: Surface) -> dict[str, Any]:
    threats: list[dict[str, Any]] = []
    for td in THREATS:
        if not td.relevant(surface):
            continue
        related = [f for f in result.findings if _match(f, td.check_prefixes)]
        # informational-only findings do not make a threat "evidenced"
        real = [f for f in related if f.severity != "info" or f.check_id.startswith("ssrf")]
        if real:
            top = min(real, key=lambda f: SEVERITY_RANK.get(f.severity, 9))
            likelihood = _SEV_LIKELIHOOD.get(top.severity, 1)
            if all(f.confidence == "low" for f in real):
                likelihood = max(1, likelihood - 1)
            status = "Evidenced by scan"
        elif not td.testable:
            likelihood, status = 2, "Manual review required (not testable by DAST)"
        else:
            likelihood, status = 1, "Potential - no issue observed"
        score = likelihood * td.impact
        threats.append({
            "id": td.key,
            "stride": td.stride,
            "component": td.component,
            "threat": td.threat,
            "status": status,
            "likelihood": likelihood,
            "impact": td.impact,
            "risk_score": score,
            "risk": _risk_label(score),
            "owasp_web": td.owasp_web,
            "owasp_api": td.owasp_api,
            "findings": sorted({f.fingerprint for f in related}),
            "mitigations": td.mitigations,
        })
    threats.sort(key=lambda t: (-t["risk_score"], t["id"]))

    entry_points = []
    groups = [
        ("Authentication endpoints", surface.login_eps),
        ("HTML forms (POST)", surface.forms),
        ("API operations", surface.api_eps),
        ("Pages / GET resources", [e for e in surface.web_eps if e.method == "GET"]),
    ]
    for name, eps in groups:
        if eps:
            entry_points.append({"name": name, "count": len(eps),
                                 "examples": [f"{e.method} {e.path}" for e in eps[:5]]})

    trust_boundaries = [
        {"name": "Internet -> Application", "description": "All HTTP(S) input from untrusted clients crosses this boundary.",
         "controls": ["TLS", "Authentication", "Input validation", "Rate limiting"]},
    ]
    if surface.params:
        trust_boundaries.append({"name": "Application -> Data stores", "description":
                                 "User-controlled values may reach databases or the file system.",
                                 "controls": ["Parameterised queries", "Least privilege"]})
    if surface.url_params:
        trust_boundaries.append({"name": "Application -> Internal / third-party services", "description":
                                 "Parameters that look like URLs may trigger server-side requests.",
                                 "controls": ["URL allow-list", "Egress filtering"]})
    if surface.authenticated_scan:
        trust_boundaries.append({"name": "Anonymous user -> Authenticated user -> Privileged user",
                                 "description": "Privilege boundaries enforced by access-control logic.",
                                 "controls": ["Object/function-level authorisation checks"]})

    assets = ["User credentials and sessions/tokens", "Application data reachable through forms and APIs"]
    if surface.api_eps:
        assets.append("API business logic and object data")
    if surface.authenticated_scan:
        assets.append("Authenticated user data and functions")

    by_stride: dict[str, int] = {}
    for t in threats:
        by_stride[t["stride"]] = by_stride.get(t["stride"], 0) + 1
    return {
        "methodology": "STRIDE applied to the attack surface discovered during the scan. Threats are marked "
                       "'Evidenced' when a scan finding supports them and 'Potential' otherwise; this is an "
                       "automated starting point, not a replacement for a design-level review.",
        "scan_mode": "authenticated" if surface.authenticated_scan else "unauthenticated",
        "assets": assets,
        "entry_points": entry_points,
        "trust_boundaries": trust_boundaries,
        "api_info": surface.meta,
        "threats": threats,
        "stride_counts": by_stride,
        "attack_surface": {
            "endpoints": len(surface.endpoints),
            "parameters": len(surface.params),
            "api_operations": len(surface.api_eps),
            "forms": len(surface.forms),
            "authentication_endpoints": len(surface.login_eps),
        },
    }
