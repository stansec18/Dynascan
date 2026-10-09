"""Passive checks: analyse responses already fetched; they generate no extra traffic."""
from __future__ import annotations

import base64
import json
import re
from urllib.parse import urlsplit

import httpx

from ..models import Endpoint
from .base import Check, CheckContext, register


def _is_html(resp: httpx.Response) -> bool:
    return "html" in resp.headers.get("content-type", "").lower()


@register
class SecurityHeaders(Check):
    id = "headers-missing"
    title = "Missing or weak HTTP security headers"
    kind = "host"
    severity = "low"
    owasp_web = ["A05:2021"]
    owasp_api = ["API8:2023"]
    cwe = ["CWE-693"]
    remediation = ("Send a restrictive Content-Security-Policy, X-Content-Type-Options: nosniff, "
                   "frame-ancestors/X-Frame-Options, Referrer-Policy and (over HTTPS) "
                   "Strict-Transport-Security on every response.")
    references = ["https://owasp.org/www-project-secure-headers/"]

    async def run_host(self, ctx: CheckContext) -> None:
        resp = await ctx.client.get(ctx.base_url)
        if resp is None:
            return
        h = {k.lower(): v for k, v in resp.headers.items()}
        https = urlsplit(ctx.base_url).scheme == "https"
        html = _is_html(resp)
        missing: list[tuple[str, str, str]] = []  # (header, severity, why)
        if html and "content-security-policy" not in h:
            missing.append(("Content-Security-Policy", "low", "no CSP to mitigate XSS/data injection"))
        elif "content-security-policy" in h and re.search(r"'unsafe-(inline|eval)'", h["content-security-policy"]) \
                and "script-src" in h["content-security-policy"]:
            missing.append(("Content-Security-Policy", "low", "policy allows 'unsafe-inline'/'unsafe-eval' scripts"))
        if html and "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
            missing.append(("X-Frame-Options", "low", "page can be framed (clickjacking, CWE-1021)"))
        if "x-content-type-options" not in h:
            missing.append(("X-Content-Type-Options", "low", "MIME sniffing not disabled"))
        if https and "strict-transport-security" not in h:
            missing.append(("Strict-Transport-Security", "medium", "no HSTS - downgrade/MITM risk"))
        if html and "referrer-policy" not in h:
            missing.append(("Referrer-Policy", "info", "URLs may leak via the Referer header"))
        for name, sev, why in missing:
            f = self.finding(
                url=ctx.base_url, resp=resp, severity=sev,
                title=f"Missing/weak security header: {name}",
                parameter=name, description=f"{name}: {why}.",
                evidence=f"Header {name} absent or weak.",
                confidence="high")
            f.check_id = f"{self.id}:{name.lower()}"
            ctx.report(f)


@register
class InsecureTransport(Check):
    id = "transport-http"
    title = "Application served over cleartext HTTP"
    kind = "host"
    severity = "medium"
    owasp_web = ["A02:2021"]
    owasp_api = ["API8:2023"]
    cwe = ["CWE-319"]
    remediation = "Serve all traffic over TLS 1.2+ and redirect HTTP to HTTPS with HSTS."

    async def run_host(self, ctx: CheckContext) -> None:
        if urlsplit(ctx.base_url).scheme == "http":
            host = urlsplit(ctx.base_url).hostname or ""
            if host in ("localhost", "127.0.0.1", "::1"):
                return  # local test targets are exempt
            ctx.report(self.finding(
                url=ctx.base_url, description="The target is reachable over unencrypted HTTP; "
                "credentials, tokens and data can be intercepted or modified on the network.",
                evidence="Scheme is http://", confidence="high"))


@register
class ServerBanner(Check):
    id = "info-banner"
    title = "Server technology/version disclosure"
    kind = "host"
    severity = "info"
    owasp_web = ["A05:2021", "A06:2021"]
    owasp_api = ["API8:2023"]
    cwe = ["CWE-200"]
    remediation = "Remove or genericise Server, X-Powered-By and X-AspNet-Version headers."

    async def run_host(self, ctx: CheckContext) -> None:
        resp = await ctx.client.get(ctx.base_url)
        if resp is None:
            return
        for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            val = resp.headers.get(hdr, "")
            if val and re.search(r"\d+\.\d+", val):
                ctx.report(self.finding(
                    url=ctx.base_url, resp=resp, parameter=hdr,
                    description=f"The {hdr} header discloses a specific version ({val}), helping attackers "
                                "target known vulnerabilities (outdated component check).",
                    evidence=f"{hdr}: {val}", confidence="high"))


@register
class CookieFlags(Check):
    id = "cookie-flags"
    title = "Cookie missing security attributes"
    kind = "passive"
    severity = "low"
    owasp_web = ["A05:2021", "A07:2021"]
    owasp_api = ["API2:2023"]
    cwe = ["CWE-614", "CWE-1004"]
    remediation = "Set Secure, HttpOnly and SameSite=Lax/Strict on session and auth cookies."

    async def run_response(self, ctx: CheckContext, ep: Endpoint, resp: httpx.Response) -> None:
        https = urlsplit(str(resp.url)).scheme == "https"
        for raw in resp.headers.get_list("set-cookie"):
            name = raw.split("=", 1)[0].strip()
            low = raw.lower()
            sessionish = bool(re.search(r"(sess|auth|token|jwt|sid|login)", name, re.I))
            problems = []
            if "httponly" not in low:
                problems.append("HttpOnly")
            if https and "secure" not in low:
                problems.append("Secure")
            if "samesite" not in low:
                problems.append("SameSite")
            if problems and (sessionish or "httponly" not in low):
                sev = "medium" if sessionish and ("HttpOnly" in problems or "Secure" in problems) else "low"
                f = self.finding(
                    url=str(resp.url), resp=resp, parameter=name, severity=sev,
                    description=f"Cookie '{name}' lacks: {', '.join(problems)}.",
                    evidence=raw.split(";")[0].split("=")[0] + "=<redacted>; " + "; ".join(
                        p.strip() for p in raw.split(";")[1:]),
                    confidence="high")
                f.check_id = f"{self.id}:{name}"
                ctx.report(f)


_ERROR_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python stack trace"),
    (re.compile(r"at [\w.$]+\([\w]+\.java:\d+\)"), "Java stack trace"),
    (re.compile(r"System\.[\w.]+Exception"), ".NET exception"),
    (re.compile(r"(?i)you have an error in your sql syntax|unclosed quotation mark|"
                r"pg_query\(\)|ORA-\d{5}|sqlite3?\.OperationalError|SQLSTATE\["), "database error message"),
    (re.compile(r"(?i)<b>(warning|fatal error)</b>:\s.* on line <b>\d+</b>"), "PHP error"),
    (re.compile(r"(?i)(werkzeug|django) .*debugger|DEBUG = True"), "framework debug page"),
]


@register
class VerboseErrors(Check):
    id = "info-errors"
    title = "Verbose error message / stack trace disclosure"
    kind = "passive"
    severity = "medium"
    owasp_web = ["A05:2021"]
    owasp_api = ["API8:2023"]
    cwe = ["CWE-209"]
    remediation = "Return generic error messages to clients and log details server-side; disable debug mode."

    async def run_response(self, ctx: CheckContext, ep: Endpoint, resp: httpx.Response) -> None:
        body = resp.text[:100_000]
        for rx, label in _ERROR_PATTERNS:
            m = rx.search(body)
            if m:
                ctx.report(self.finding(
                    url=str(resp.url), resp=resp, needle=m.group(0),
                    description=f"The response contains a {label}, revealing internals useful to attackers.",
                    evidence=m.group(0)[:120], confidence="high"))
                return


_SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "private key", "high"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key ID", "high"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "GitHub personal access token", "high"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "Slack token", "high"),
    (re.compile(r"(?i)(api[_-]?key|secret|passwd|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "hard-coded secret", "medium"),
]


@register
class SecretsInResponses(Check):
    id = "secrets-exposed"
    title = "Secret or credential exposed in response"
    kind = "passive"
    severity = "high"
    owasp_web = ["A02:2021", "A05:2021"]
    owasp_api = ["API8:2023"]
    cwe = ["CWE-200", "CWE-798"]
    remediation = "Remove secrets from client-delivered content, rotate any exposed credential, use a secrets manager."

    async def run_response(self, ctx: CheckContext, ep: Endpoint, resp: httpx.Response) -> None:
        body = resp.text[:300_000]
        for rx, label, conf in _SECRET_PATTERNS:
            m = rx.search(body)
            if m:
                shown = m.group(0)
                shown = shown[:6] + "…[redacted]"
                f = self.finding(url=str(resp.url), resp=None,
                                 description=f"A {label} appears in the response body.",
                                 evidence=shown, confidence=conf)
                f.check_id = f"{self.id}:{label}"
                ctx.report(f)


_SENSITIVE_FIELDS = re.compile(
    r'"(password|passwd|pwd|password_hash|hash|secret|api_?key|ssn|social_security|credit_?card|'
    r'card_number|cvv|private_key|token|refresh_token|otp)"\s*:', re.I)


@register
class ExcessiveDataExposure(Check):
    id = "api-excessive-data"
    title = "API response exposes sensitive object properties"
    kind = "passive"
    severity = "medium"
    owasp_web = ["A01:2021", "A04:2021"]
    owasp_api = ["API3:2023"]
    cwe = ["CWE-200"]
    remediation = ("Return only the properties each client needs (explicit response schemas / DTOs); "
                   "never serialise password hashes, tokens or PII by default.")

    async def run_response(self, ctx: CheckContext, ep: Endpoint, resp: httpx.Response) -> None:
        if "json" not in resp.headers.get("content-type", "").lower():
            return
        m = _SENSITIVE_FIELDS.search(resp.text[:200_000])
        if m:
            name = m.group(1).lower()
            if name in ("token", "refresh_token") and ep.method == "POST" and "login" in ep.path.lower():
                return  # expected on a login response
            f = self.finding(url=str(resp.url), resp=resp, parameter=name, needle=m.group(0),
                             description=f"JSON response contains a sensitive-looking property '{name}'.",
                             evidence=f'property "{name}" present', confidence="medium")
            f.check_id = f"{self.id}:{name}"
            ctx.report(f)


@register
class MissingCSRF(Check):
    id = "csrf-missing"
    title = "State-changing form without anti-CSRF token"
    kind = "host"
    severity = "medium"
    owasp_web = ["A01:2021", "A04:2021"]
    owasp_api = []
    cwe = ["CWE-352"]
    remediation = "Add per-session anti-CSRF tokens (or rely on SameSite=Strict cookies plus custom headers)."

    _TOKEN = re.compile(r"(csrf|xsrf|authenticity_token|__requestverificationtoken|_token|nonce)", re.I)

    async def run_host(self, ctx: CheckContext) -> None:
        for ep in ctx.endpoints:
            if ep.method != "POST" or ep.source != "crawl" or not ep.params or ep.body_type != "form":
                continue
            names = " ".join(p.name for p in ep.params)
            if self._TOKEN.search(names):
                continue
            is_login = any(re.search(r"(?i)pass", p.name) for p in ep.params) and \
                re.search(r"login|signin", ep.url, re.I)
            f = self.finding(
                url=ep.url, method="POST", severity="low" if is_login else self.severity,
                description="A POST form has no recognisable anti-CSRF token, so a third-party site "
                            "may be able to submit it on behalf of a logged-in user.",
                evidence=f"form fields: {names}", confidence="low")
            ctx.report(f)


@register
class DirectoryListing(Check):
    id = "dir-listing"
    title = "Directory listing enabled"
    kind = "passive"
    severity = "medium"
    owasp_web = ["A05:2021"]
    owasp_api = ["API8:2023"]
    cwe = ["CWE-548"]
    remediation = "Disable auto-indexing on the web server."

    async def run_response(self, ctx: CheckContext, ep: Endpoint, resp: httpx.Response) -> None:
        if resp.status_code == 200 and re.search(r"<title>Index of /|Directory listing for /", resp.text[:2000]):
            ctx.report(self.finding(url=str(resp.url), resp=resp, needle="Index of",
                                    description="The server returns an auto-generated directory index.",
                                    evidence="Index page title detected", confidence="high"))


def _b64json(seg: str) -> dict | None:
    try:
        pad = "=" * (-len(seg) % 4)
        data = json.loads(base64.urlsafe_b64decode(seg + pad))
        return data if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001
        return None


_JWT_RX = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")


@register
class JWTWeaknesses(Check):
    id = "jwt-weak"
    title = "Weak JSON Web Token configuration"
    kind = "passive"
    severity = "medium"
    owasp_web = ["A02:2021", "A07:2021"]
    owasp_api = ["API2:2023"]
    cwe = ["CWE-287"]
    remediation = ("Use strong asymmetric or long random HMAC keys, never accept alg=none, always set short 'exp' "
                   "and validate 'aud'/'iss'. Do not store sensitive data in token payloads.")

    async def run_response(self, ctx: CheckContext, ep: Endpoint, resp: httpx.Response) -> None:
        haystacks = [resp.text[:50_000]] + resp.headers.get_list("set-cookie") + \
                    [resp.request.headers.get("authorization", "")]
        seen: set[str] = set()
        for hay in haystacks:
            for tok in _JWT_RX.findall(hay):
                if tok in seen:
                    continue
                seen.add(tok)
                hdr_s, pay_s = tok.split(".")[:2]
                header, payload = _b64json(hdr_s), _b64json(pay_s)
                if not header or payload is None:
                    continue
                alg = str(header.get("alg", ""))
                issues: list[tuple[str, str]] = []
                if alg.lower() == "none":
                    issues.append(("high", "token uses alg=none (unsigned)"))
                if "exp" not in payload:
                    issues.append(("medium", "token has no 'exp' claim (never expires)"))
                elif isinstance(payload.get("iat"), (int, float)) and isinstance(payload["exp"], (int, float)) \
                        and payload["exp"] - payload["iat"] > 60 * 60 * 24 * 30:
                    issues.append(("low", "token lifetime exceeds 30 days"))
                if alg.upper() == "HS256":
                    issues.append(("info", "HS256 in use - ensure the signing secret is long and random"))
                if any(k in payload for k in ("password", "pwd", "ssn", "secret")):
                    issues.append(("high", "sensitive data stored in readable JWT payload"))
                for sev, text in issues:
                    f = self.finding(url=str(resp.url), resp=None, severity=sev,
                                     description=f"JWT issue: {text}.",
                                     evidence=f"alg={alg}, claims={sorted(payload)[:8]}", confidence="high",
                                     parameter="jwt")
                    f.check_id = f"{self.id}:{text[:24]}"
                    ctx.report(f)
