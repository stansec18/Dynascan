"""Active checks. All payloads are non-destructive probes (markers, quote characters, read-only file
paths); no data is modified, deleted or exfiltrated beyond a short proof string."""
from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urlsplit, urljoin

import httpx

from ..models import Endpoint
from .base import Check, CheckContext, register
from .util import SAFE_METHODS, mutable_params, rand_token, send

# --------------------------------------------------------------------------- injection

@register
class ReflectedXSS(Check):
    id = "xss-reflected"
    title = "Reflected cross-site scripting (XSS)"
    kind = "active"
    severity = "high"
    owasp_web = ["A03:2021"]
    owasp_api = []
    cwe = ["CWE-79"]
    remediation = "Contextually encode all untrusted output (HTML, attribute, JS, URL) and add a strict CSP."
    references = ["https://owasp.org/www-community/attacks/xss/"]

    async def run_endpoint(self, ctx: CheckContext, ep: Endpoint) -> None:
        for p in mutable_params(ep):
            if p.location == "path":
                continue
            tok = rand_token()
            payload = f'dast{tok}"\'<x{tok}>'
            resp = await send(ctx.client, ep, {p.name: payload})
            if resp is None:
                continue
            ctype = resp.headers.get("content-type", "").lower()
            if "html" in ctype and f"<x{tok}>" in resp.text:
                ctx.report(self.finding(
                    url=ep.url, method=ep.method, parameter=p.name, resp=resp, needle=f"<x{tok}>",
                    description=f"The value of '{p.name}' is reflected into an HTML response without encoding "
                                "angle brackets, so script can be injected.",
                    evidence=f"Injected marker <x{tok}> returned unencoded", confidence="high"))


_SQL_ERRORS = re.compile(
    r"(you have an error in your sql syntax|warning: mysql|unclosed quotation mark|quoted string not properly "
    r"terminated|pg_query\(\)|postgresql.*error|sqlite3?\.operationalerror|sqlite error|SQLSTATE\[|"
    r"ora-\d{5}|odbc .*driver|microsoft ole db|syntax error at or near|unterminated string literal)", re.I)


@register
class SQLInjectionError(Check):
    id = "sqli-error"
    title = "SQL injection (error-based)"
    kind = "active"
    severity = "high"
    owasp_web = ["A03:2021"]
    owasp_api = []
    cwe = ["CWE-89"]
    remediation = "Use parameterised queries / prepared statements and an ORM; never concatenate input into SQL."
    references = ["https://owasp.org/www-community/attacks/SQL_Injection"]

    async def run_endpoint(self, ctx: CheckContext, ep: Endpoint) -> None:
        base = ctx.baselines.get(ep.key)
        base_has_err = bool(base is not None and _SQL_ERRORS.search(base.text or ""))
        for p in mutable_params(ep):
            for payload in ("'", '"', "')"):
                resp = await send(ctx.client, ep, {p.name: (p.value or "1") + payload})
                if resp is None:
                    continue
                m = _SQL_ERRORS.search(resp.text or "")
                if m and not base_has_err:
                    ctx.report(self.finding(
                        url=ep.url, method=ep.method, parameter=p.name, resp=resp, needle=m.group(0),
                        description=f"Appending a quote to '{p.name}' produced a database error message, "
                                    "indicating unsanitised input reaches a SQL query.",
                        evidence=m.group(0)[:100], confidence="high"))
                    break


@register
class TemplateInjection(Check):
    id = "ssti"
    title = "Server-side template injection"
    kind = "active"
    severity = "high"
    owasp_web = ["A03:2021"]
    owasp_api = []
    cwe = ["CWE-20"]
    remediation = "Never render user input as a template; use sandboxed template engines with static templates."

    async def run_endpoint(self, ctx: CheckContext, ep: Endpoint) -> None:
        base = ctx.baselines.get(ep.key)
        base_text = base.text if base is not None else ""
        for p in mutable_params(ep):
            if p.location == "path":
                continue
            for payload, expect in (("{{1337*3}}", "4011"), ("${1337*3}", "4011"), ("<%= 1337*3 %>", "4011")):
                resp = await send(ctx.client, ep, {p.name: payload})
                if resp is None:
                    continue
                if expect in resp.text and expect not in base_text and payload not in resp.text:
                    ctx.report(self.finding(
                        url=ep.url, method=ep.method, parameter=p.name, resp=resp, needle=expect,
                        description=f"The template expression {payload} sent in '{p.name}' was evaluated "
                                    f"(result {expect}), indicating server-side template injection.",
                        evidence=f"{payload} -> {expect}", confidence="high"))
                    break


_FILEISH = re.compile(r"(file|path|page|doc|template|include|name|dir|folder|load|read|resource|img|image)", re.I)


@register
class PathTraversal(Check):
    id = "path-traversal"
    title = "Path traversal / local file read"
    kind = "active"
    severity = "high"
    owasp_web = ["A01:2021", "A03:2021"]
    owasp_api = ["API1:2023"]
    cwe = ["CWE-22"]
    remediation = "Resolve paths against an allow-listed base directory and reject '..' sequences; avoid user-controlled file names."

    async def run_endpoint(self, ctx: CheckContext, ep: Endpoint) -> None:
        for p in mutable_params(ep):
            if not _FILEISH.search(p.name):
                continue
            for payload, sig in (
                ("../../../../../../../etc/passwd", re.compile(r"root:[x*]:0:0:")),
                ("..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", re.compile(r"root:[x*]:0:0:")),
                ("..\\..\\..\\..\\..\\windows\\win.ini", re.compile(r"\[(fonts|extensions)\]", re.I)),
            ):
                resp = await send(ctx.client, ep, {p.name: payload})
                if resp is None:
                    continue
                m = sig.search(resp.text or "")
                if m:
                    ctx.report(self.finding(
                        url=ep.url, method=ep.method, parameter=p.name, resp=resp, needle=m.group(0),
                        description=f"Directory traversal sequences in '{p.name}' returned the contents of a "
                                    "system file.",
                        evidence=f"matched: {m.group(0)}", confidence="high"))
                    break


_REDIRECT_NAMES = re.compile(r"^(url|redirect|redirect_uri|redirect_url|next|return|returnurl|return_to|"
                             r"dest|destination|continue|goto|target|r|u|callback)$", re.I)


@register
class OpenRedirect(Check):
    id = "open-redirect"
    title = "Open redirect"
    kind = "active"
    severity = "medium"
    owasp_web = ["A01:2021"]
    owasp_api = []
    cwe = ["CWE-601"]
    remediation = "Only redirect to relative paths or an allow-list of hosts; never trust a user-supplied URL."

    async def run_endpoint(self, ctx: CheckContext, ep: Endpoint) -> None:
        for p in mutable_params(ep):
            if not _REDIRECT_NAMES.match(p.name):
                continue
            target = "https://dynascan-redirect.example.org/x"
            resp = await send(ctx.client, ep, {p.name: target})
            if resp is None:
                continue
            loc = resp.headers.get("location", "")
            if resp.status_code in (301, 302, 303, 307, 308) and \
                    (urlsplit(loc).hostname or "") == "dynascan-redirect.example.org":
                ctx.report(self.finding(
                    url=ep.url, method=ep.method, parameter=p.name, resp=resp,
                    description=f"'{p.name}' controls the redirect destination and accepts an external host.",
                    evidence=f"Location: {loc}", confidence="high"))


# --------------------------------------------------------------------------- host-level

@register
class CorsMisconfiguration(Check):
    id = "cors-misconfig"
    title = "Permissive CORS policy"
    kind = "host"
    severity = "medium"
    owasp_web = ["A05:2021"]
    owasp_api = ["API8:2023"]
    cwe = ["CWE-346"]
    remediation = "Allow-list specific trusted origins; never reflect arbitrary Origin values or combine with credentials."

    async def run_host(self, ctx: CheckContext) -> None:
        urls = {ctx.base_url}
        for ep in ctx.endpoints:
            if ep.source == "openapi" or "api" in ep.path.lower():
                urls.add(ep.url.split("?")[0])
            if len(urls) >= 6:
                break
        for url in sorted(urls):
            evil = "https://evil.dynascan.example"
            resp = await ctx.client.get(url, headers={"Origin": evil})
            if resp is None:
                continue
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
            if acao == evil and acac:
                ctx.report(self.finding(
                    url=url, resp=resp, severity="high", parameter="Origin",
                    description="The server reflects an arbitrary Origin and allows credentials, so any website "
                                "can read authenticated responses.",
                    evidence=f"ACAO: {acao}; ACAC: true", confidence="high"))
            elif acao == evil:
                ctx.report(self.finding(
                    url=url, resp=resp, parameter="Origin",
                    description="The server reflects an arbitrary Origin in Access-Control-Allow-Origin.",
                    evidence=f"ACAO: {acao}", confidence="high"))
            elif acao == "*" and acac:
                ctx.report(self.finding(url=url, resp=resp, parameter="Origin",
                                        description="Wildcard ACAO combined with credentials flag.",
                                        evidence="ACAO: *; ACAC: true", confidence="medium"))


@register
class DangerousMethods(Check):
    id = "http-methods"
    title = "Dangerous HTTP methods enabled"
    kind = "host"
    severity = "low"
    owasp_web = ["A05:2021"]
    owasp_api = ["API8:2023"]
    cwe = ["CWE-16"]
    remediation = "Disable TRACE/TRACK and any methods not required by the application."

    async def run_host(self, ctx: CheckContext) -> None:
        resp = await ctx.client.request("TRACE", ctx.base_url)
        if resp is not None and resp.status_code == 200 and "TRACE" in resp.text[:300].upper():
            ctx.report(self.finding(
                url=ctx.base_url, method="TRACE", resp=resp,
                description="The server answers TRACE requests, which can aid cross-site tracing attacks.",
                evidence="TRACE echoed the request", confidence="high"))


_SENSITIVE_PATHS = [
    # (path, signature regex on body, title, severity, owasp_web, owasp_api, cwe)
    ("/.git/HEAD", r"^ref:\s+refs/", "Exposed Git repository", "high", ["A05:2021"], ["API8:2023"], ["CWE-538"]),
    ("/.env", r"(?m)^[A-Z_]{3,}=.+", "Exposed environment file (.env)", "critical", ["A05:2021"], ["API8:2023"], ["CWE-538"]),
    ("/.DS_Store", r"Bud1", "Exposed .DS_Store file", "low", ["A05:2021"], [], ["CWE-538"]),
    ("/phpinfo.php", r"phpinfo\(\)|PHP Version", "phpinfo() page exposed", "medium", ["A05:2021"], ["API8:2023"], ["CWE-200"]),
    ("/server-status", r"Apache Server Status", "Apache server-status exposed", "medium", ["A05:2021"], ["API8:2023"], ["CWE-200"]),
    ("/actuator/env", r"propertySources|activeProfiles", "Spring Boot actuator /env exposed", "high", ["A05:2021"], ["API8:2023"], ["CWE-200"]),
    ("/actuator/heapdump", r"", "Spring Boot heap dump endpoint", "high", ["A05:2021"], ["API8:2023"], ["CWE-200"]),
    ("/actuator", r"\"_links\"", "Spring Boot actuator index exposed", "low", ["A05:2021"], ["API8:2023", "API9:2023"], ["CWE-200"]),
    ("/web.config", r"<configuration", "web.config exposed", "high", ["A05:2021"], ["API8:2023"], ["CWE-538"]),
    ("/config.json", r"(?i)(password|secret|api[_-]?key)", "Configuration file with secrets exposed", "high", ["A05:2021"], ["API8:2023"], ["CWE-538"]),
    ("/backup.sql", r"(?i)(CREATE TABLE|INSERT INTO)", "Database backup exposed", "critical", ["A05:2021"], ["API8:2023"], ["CWE-538"]),
    ("/robots.txt", r"(?i)(disallow|user-agent)", "robots.txt present (review disclosed paths)", "info", ["A05:2021"], [], ["CWE-200"]),
]

_API_DOC_PATHS = ["/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs", "/api-docs",
                  "/swagger/v1/swagger.json", "/swagger-ui.html", "/swagger-ui/", "/docs", "/redoc"]


async def _soft404_profile(ctx: CheckContext) -> tuple[int, int]:
    r = await ctx.client.get(urljoin(ctx.base_url, f"/dynascan-{rand_token(10)}"))
    return (r.status_code, len(r.text)) if r is not None else (404, 0)


@register
class SensitiveFiles(Check):
    id = "exposed-files"
    title = "Sensitive file or endpoint exposed"
    kind = "host"
    severity = "high"
    owasp_web = ["A05:2021"]
    owasp_api = ["API8:2023"]
    cwe = ["CWE-538"]
    remediation = "Remove the resource from the web root or block it at the web server / WAF."

    async def run_host(self, ctx: CheckContext) -> None:
        s404_status, s404_len = await _soft404_profile(ctx)

        async def probe(entry):
            path, sig, title, sev, web, api, cwe = entry
            resp = await ctx.client.get(urljoin(ctx.base_url, path))
            if resp is None or resp.status_code != 200:
                return
            body = resp.text[:20000]
            if s404_status == 200 and abs(len(resp.text) - s404_len) < 40:
                return  # soft-404 page
            if sig and not re.search(sig, body):
                return
            if not sig and "text/html" in resp.headers.get("content-type", ""):
                return
            f = self.finding(url=resp.url.__str__(), resp=resp, severity=sev, title=title,
                             description=f"{path} is publicly reachable and its content matches the expected signature.",
                             evidence=f"HTTP 200, {len(resp.content)} bytes", confidence="high")
            f.owasp_web, f.owasp_api, f.cwe = list(web), list(api), list(cwe)
            f.check_id = f"{self.id}:{path}"
            ctx.report(f)

        await asyncio.gather(*(probe(e) for e in _SENSITIVE_PATHS))


@register
class ApiDocsExposure(Check):
    id = "api-docs-exposed"
    title = "API documentation / specification publicly exposed"
    kind = "host"
    severity = "low"
    owasp_web = ["A05:2021"]
    owasp_api = ["API9:2023", "API8:2023"]
    cwe = ["CWE-200"]
    remediation = "Restrict API docs to authenticated/internal users in production and keep the inventory of exposed versions current."

    async def run_host(self, ctx: CheckContext) -> None:
        s404_status, s404_len = await _soft404_profile(ctx)
        for path in _API_DOC_PATHS:
            resp = await ctx.client.get(urljoin(ctx.base_url, path))
            if resp is None or resp.status_code != 200:
                continue
            if s404_status == 200 and abs(len(resp.text) - s404_len) < 40:
                continue
            body = resp.text[:5000]
            looks = re.search(r'"(openapi|swagger)"\s*:|swagger-ui|redoc|openapi:\s', body, re.I)
            if looks:
                f = self.finding(url=str(resp.url), resp=resp, evidence=f"{path} returned an API description",
                                 description="Interactive API docs or an OpenAPI/Swagger document are reachable "
                                             "without restriction, revealing the full attack surface.",
                                 confidence="high")
                f.check_id = f"{self.id}:{path}"
                ctx.report(f)


@register
class GraphQLIntrospection(Check):
    id = "graphql-introspection"
    title = "GraphQL introspection enabled"
    kind = "host"
    severity = "low"
    owasp_web = ["A05:2021"]
    owasp_api = ["API8:2023", "API9:2023"]
    cwe = ["CWE-200"]
    remediation = "Disable introspection in production or restrict it to authenticated developers."

    async def run_host(self, ctx: CheckContext) -> None:
        for path in ("/graphql", "/api/graphql", "/graphiql"):
            resp = await ctx.client.post(urljoin(ctx.base_url, path), json={"query": "{__schema{queryType{name}}}"})
            if resp is None or resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except ValueError:
                continue
            if isinstance(data, dict) and isinstance(data.get("data"), dict) and "__schema" in data["data"]:
                ctx.report(self.finding(url=str(resp.url), method="POST", resp=resp,
                                        description="The GraphQL endpoint answers introspection queries, exposing the full schema.",
                                        evidence="__schema returned", confidence="high"))
                return


_SSRF_NAMES = re.compile(r"(url|uri|link|webhook|callback|dest|redirect|image_?url|fetch|proxy|feed|host)", re.I)


@register
class SsrfCandidates(Check):
    id = "ssrf-candidate"
    title = "Parameter may accept a server-fetched URL (SSRF candidate)"
    kind = "host"
    severity = "info"
    owasp_web = ["A10:2021"]
    owasp_api = ["API7:2023"]
    cwe = ["CWE-20"]
    remediation = ("Validate URLs against an allow-list, block internal address ranges and metadata endpoints, "
                   "and use an egress proxy. Verify manually with an out-of-band listener.")

    async def run_host(self, ctx: CheckContext) -> None:
        seen: set[str] = set()
        for ep in ctx.endpoints:
            for p in ep.params:
                if p.location in ("query", "form", "json") and _SSRF_NAMES.search(p.name) and \
                        (p.value.startswith("http") or _SSRF_NAMES.search(p.name)):
                    key = f"{ep.method} {ep.path} {p.name}"
                    if key in seen:
                        continue
                    seen.add(key)
                    ctx.report(self.finding(
                        url=ep.url, method=ep.method, parameter=p.name,
                        description=f"Parameter '{p.name}' looks like it may carry a URL fetched by the server. "
                                    "The scanner cannot confirm SSRF without an out-of-band callback, so manual "
                                    "verification is recommended.",
                        evidence="name-based heuristic", confidence="low"))


# --------------------------------------------------------------------------- authn/authz

_LOGIN_PATH = re.compile(r"(login|signin|sign-in|authenticate|auth|token|session)", re.I)


@register
class NoRateLimitOnLogin(Check):
    id = "login-no-ratelimit"
    title = "No brute-force protection observed on login"
    kind = "host"
    severity = "medium"
    owasp_web = ["A07:2021", "A04:2021"]
    owasp_api = ["API2:2023", "API4:2023", "API6:2023"]
    cwe = ["CWE-307", "CWE-770"]
    remediation = "Add rate limiting, progressive delays/lockout, CAPTCHA or MFA on authentication endpoints."

    async def run_host(self, ctx: CheckContext) -> None:
        attempts = int(ctx.options.get("login_attempts", 12))
        if attempts <= 0:
            return
        for ep in ctx.endpoints:
            if ep.method != "POST" or not _LOGIN_PATH.search(ep.path):
                continue
            pw = next((p for p in ep.params if re.search(r"pass", p.name, re.I)), None)
            usr = next((p for p in ep.params if re.search(r"(user|email|login|name)", p.name, re.I)), None)
            if not pw or not usr:
                continue
            ghost = f"dynascan-{rand_token()}"  # non-existent account: no real lockout side effects
            statuses = []
            for i in range(attempts):
                r = await send(ctx.anon_client, ep, {usr.name: ghost, pw.name: f"Wrong-{rand_token()}!"})
                if r is None:
                    break
                statuses.append(r.status_code)
                if r.status_code == 429 or re.search(r"(?i)(too many|locked|rate.?limit|try again later)", r.text[:2000]):
                    return
            if len(statuses) >= attempts:
                ctx.report(self.finding(
                    url=ep.url, method="POST", parameter=usr.name,
                    description=f"{attempts} consecutive failed logins for a non-existent account were all "
                                "processed with no throttling, lockout or CAPTCHA response.",
                    evidence=f"statuses: {sorted(set(statuses))}", confidence="medium"))
            return


def _similar(a: httpx.Response, b: httpx.Response) -> bool:
    la, lb = len(a.content), len(b.content)
    if la == 0 and lb == 0:
        return True
    return abs(la - lb) / max(la, lb, 1) < 0.1


_LOGIN_PAGE = re.compile(r'type=["\']password["\']', re.I)


@register
class AuthBypassUnauthenticated(Check):
    id = "authz-unauth-access"
    title = "Authenticated resource accessible without credentials"
    kind = "active"
    severity = "high"
    owasp_web = ["A01:2021", "A07:2021"]
    owasp_api = ["API2:2023", "API5:2023"]
    cwe = ["CWE-284", "CWE-287"]
    remediation = "Enforce authentication and authorisation server-side on every route (deny by default)."

    async def run_endpoint(self, ctx: CheckContext, ep: Endpoint) -> None:
        if not ctx.authenticated or ep.method not in SAFE_METHODS:
            return
        if ep.key in ctx.options.get("public_keys", set()) and not ep.requires_auth:
            return  # linked from public pages -> intentionally public
        auth = ctx.baselines.get(ep.key)
        if auth is None or auth.status_code != 200 or not auth.content:
            return
        anon = await send(ctx.anon_client, ep)
        if anon is None or anon.status_code != 200 or _LOGIN_PAGE.search(anon.text[:5000]):
            return
        if _similar(auth, anon):
            sev = "high" if ep.requires_auth or "json" in auth.headers.get("content-type", "") else "medium"
            ctx.report(self.finding(
                url=ep.url, method=ep.method, resp=anon, severity=sev,
                description="The same content is returned to an unauthenticated client as to the logged-in "
                            "user. The endpoint was discovered during the authenticated crawl, so it may be "
                            "intended to be protected.",
                evidence=f"anon: HTTP {anon.status_code}, {len(anon.content)} bytes; auth: {len(auth.content)} bytes",
                confidence="medium" if ep.requires_auth is None else "high"))


_ID_NAMES = re.compile(r"^(id|user_?id|uid|account_?id|order_?id|invoice_?id|doc(ument)?_?id|profile_?id|customer_?id)$", re.I)


@register
class BolaCandidate(Check):
    id = "bola-candidate"
    title = "Possible Broken Object Level Authorization (IDOR)"
    kind = "active"
    severity = "medium"
    owasp_web = ["A01:2021"]
    owasp_api = ["API1:2023"]
    cwe = ["CWE-639", "CWE-285"]
    remediation = ("Check object ownership/permissions on every request using the authenticated principal; "
                   "prefer unpredictable identifiers but never rely on them for authorisation.")

    async def run_endpoint(self, ctx: CheckContext, ep: Endpoint) -> None:
        if not ctx.authenticated or ep.method != "GET":
            return
        base = ctx.baselines.get(ep.key)
        if base is None or base.status_code != 200:
            return
        for p in ep.params:
            if p.location not in ("query", "path") or not p.value.isdigit():
                continue
            if p.location == "query" and not _ID_NAMES.match(p.name):
                continue
            neighbours = [str(int(p.value) + 1), str(max(0, int(p.value) - 1))]
            for nid in neighbours:
                if nid == p.value:
                    continue
                other = await send(ctx.client, ep, {p.name: nid})
                if other is None or other.status_code != 200 or other.content == base.content:
                    continue
                if "json" in other.headers.get("content-type", "") or "html" in other.headers.get("content-type", ""):
                    ctx.report(self.finding(
                        url=ep.url, method="GET", parameter=p.name, resp=other, severity="medium",
                        description=f"Changing the object identifier '{p.name}' from {p.value} to {nid} returned a "
                                    "different 200 response. If the object belongs to another user this is an "
                                    "IDOR/BOLA flaw; confirm with a second test account.",
                        evidence=f"{p.value} -> {nid}: both HTTP 200, bodies differ", confidence="low"))
                    return


@register
class OldApiVersions(Check):
    id = "api-old-version"
    title = "Older API version still reachable"
    kind = "active"
    severity = "low"
    owasp_web = ["A06:2021", "A05:2021"]
    owasp_api = ["API9:2023"]
    cwe = ["CWE-200"]
    remediation = "Retire deprecated API versions, or apply the same security controls to every version in production."

    async def run_endpoint(self, ctx: CheckContext, ep: Endpoint) -> None:
        m = re.search(r"/v(\d+)(/|$)", ep.path)
        if not m or ep.method != "GET":
            return
        ver = int(m.group(1))
        for old in range(ver - 1, max(-1, ver - 3), -1):
            new_path = re.sub(r"/v\d+(/|$)", f"/v{old}\\1", ep.path, count=1)
            url = urlsplit(ep.url)._replace(path=new_path, query="").geturl()
            resp = await ctx.client.get(url)
            if resp is not None and resp.status_code == 200 and len(resp.content) > 0:
                ctx.report(self.finding(
                    url=url, resp=resp,
                    description=f"The endpoint also responds on the older version v{old}, which may lack current "
                                "security controls.", evidence=f"v{ver} -> v{old}: HTTP 200", confidence="medium"))
                return
