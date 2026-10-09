"""Core tests. They use an in-process mock transport serving a benign static site, plus fixture
responses for individual checks - no vulnerable server is involved."""
from __future__ import annotations

import asyncio
import base64
import json

import httpx
import pytest

from dynascan.auth import AuthError, build_auth
from dynascan.checks import CheckContext, all_checks
from dynascan.config import ScanConfig
from dynascan.engine import ScanEngine
from dynascan.http_client import ClientConfig, ScanClient
from dynascan.models import Endpoint, Finding, Param, ScanResult
from dynascan.openapi import endpoints_from_spec
from dynascan.owasp import API_TOP10, WEB_TOP10, coverage
from dynascan.report import to_html, to_json, to_markdown, to_sarif, write_reports
from dynascan.scope import OutOfScopeError, Scope
from dynascan.threatmodel import Surface, build_threat_model

BASE = "https://shop.example.test"


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


JWT_NO_EXP = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': 'u1'})}."


def benign_site(request: httpx.Request) -> httpx.Response:
    """A plain static site: a few pages, a login form, a cookie, no injection sinks."""
    path = request.url.path
    cookie = request.headers.get("cookie", "")
    if path == "/":
        return httpx.Response(200, headers={"content-type": "text/html", "server": "nginx/1.18.0"}, text=(
            '<html><body><a href="/about">About</a> <a href="/dashboard">Dashboard</a>'
            '<form method="post" action="/login"><input name="username"><input type="password" name="password">'
            '<input type="hidden" name="_token" value="t0k"></form></body></html>'))
    if path == "/about":
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html><body>About us</body></html>")
    if path == "/login" and request.method == "GET":
        return httpx.Response(200, headers={"content-type": "text/html"}, text=(
            '<form method="post" action="/login"><input name="username"><input type="password" name="password">'
            '<input type="hidden" name="_token" value="t0k"></form>'))
    if path == "/login" and request.method == "POST":
        body = request.content.decode()
        if "username=alice" in body and "password=s3cret" in body and "_token=t0k" in body:
            return httpx.Response(200, headers={"content-type": "text/html", "set-cookie": "session=s1; Path=/"},
                                  text="<html>Welcome back alice</html>")
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html>Invalid credentials</html>")
    if path == "/dashboard":
        if "session=s1" in cookie:
            return httpx.Response(200, headers={"content-type": "text/html"},
                                  text=f"<html>Dashboard for alice <script>var t='{JWT_NO_EXP}'</script></html>")
        return httpx.Response(302, headers={"location": "/login"})
    return httpx.Response(404, headers={"content-type": "text/html"}, text="not found")


def make_cfg(**kw) -> ScanConfig:
    base = dict(target=BASE, authorized=True, requests_per_second=0, max_pages=30, login_attempts=0)
    base.update(kw)
    return ScanConfig(**base)


def run(cfg: ScanConfig):
    eng = ScanEngine(cfg, transport=httpx.MockTransport(benign_site))
    return asyncio.run(eng.run())


# ---------------------------------------------------------------- scope
def test_scope_requires_authorization_flag():
    with pytest.raises(OutOfScopeError):
        asyncio.run(ScanEngine(ScanConfig(target=BASE), transport=httpx.MockTransport(benign_site)).run())


def test_scope_blocks_foreign_hosts_and_excluded_paths():
    s = Scope(BASE, exclude_paths=[r"^/admin"], authorized=True)
    assert s.allows(BASE + "/x")
    assert not s.allows("https://evil.example.test/x")
    assert not s.allows(BASE + "/admin/users")
    s2 = Scope(BASE, allowed_hosts=["*.example.test"], authorized=True)
    assert s2.allows("https://api.example.test/")


def test_client_refuses_out_of_scope_request():
    async def go():
        c = ScanClient(Scope(BASE, authorized=True), ClientConfig(requests_per_second=0),
                       transport=httpx.MockTransport(benign_site))
        with pytest.raises(OutOfScopeError):
            await c.get("https://other.test/")
        await c.aclose()
    asyncio.run(go())


# ---------------------------------------------------------------- config / reference data
def test_config_rejects_unknown_keys():
    with pytest.raises(ValueError):
        ScanConfig.from_dict({"target": BASE, "nope": 1})


def test_config_redacts_secrets():
    cfg = ScanConfig(target=BASE, auth={"type": "form", "username": "a", "password": "p"})
    assert cfg.redacted()["auth"]["password"] == "***"


def test_owasp_catalogs_complete():
    assert len(WEB_TOP10) == 10 and len(API_TOP10) == 10
    assert all(k.endswith(":2021") for k in WEB_TOP10) and all(k.endswith(":2023") for k in API_TOP10)


def test_every_check_maps_to_owasp_and_has_remediation():
    for c in all_checks():
        assert c.owasp_web or c.owasp_api, c.id
        assert c.remediation, c.id
        for code in c.owasp_web:
            assert code in WEB_TOP10, (c.id, code)
        for code in c.owasp_api:
            assert code in API_TOP10, (c.id, code)


def test_finding_dedup_by_fingerprint():
    r = ScanResult(target=BASE)
    f1 = Finding("x", "T", "low", "d", BASE + "/a?q=1", parameter="q")
    f2 = Finding("x", "T", "low", "d", BASE + "/a?q=2", parameter="q")
    assert r.add(f1) and not r.add(f2)


# ---------------------------------------------------------------- openapi
SPEC = {
    "openapi": "3.0.0", "info": {"title": "T", "version": "1"},
    "servers": [{"url": "/api/v1"}], "security": [{"b": []}],
    "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}},
    "paths": {
        "/orders/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}}]}},
        "/orders": {"post": {"requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "properties": {"item": {"type": "string"}, "qty": {"type": "integer"}}}}}}}},
        "/health": {"get": {"security": []}},
    },
}


def test_openapi_import():
    eps, meta = endpoints_from_spec(SPEC, BASE)
    by = {(e.method, e.path): e for e in eps}
    assert ("GET", "/api/v1/orders/1") in by
    post = by[("POST", "/api/v1/orders")]
    assert post.body_type == "json" and {p.name for p in post.params} == {"item", "qty"}
    assert by[("GET", "/api/v1/health")].requires_auth is False
    assert meta["operations"] == 3 and meta["secured_operations"] == 2


# ---------------------------------------------------------------- auth handlers
def test_form_login_success_and_failure():
    async def go(pw):
        c = ScanClient(Scope(BASE, authorized=True), ClientConfig(requests_per_second=0),
                       transport=httpx.MockTransport(benign_site))
        try:
            h = build_auth({"type": "form", "login_url": "/login", "username": "alice", "password": pw,
                            "success_indicator": "Welcome back"})
            await h.apply(c, BASE)
            return (await c.get(BASE + "/dashboard")).status_code
        finally:
            await c.aclose()
    assert asyncio.run(go("s3cret")) == 200
    with pytest.raises(AuthError):
        asyncio.run(go("wrong"))


def test_bearer_and_apikey_set_headers():
    async def go():
        c = ScanClient(Scope(BASE, authorized=True), ClientConfig(requests_per_second=0),
                       transport=httpx.MockTransport(benign_site))
        await build_auth({"type": "bearer", "token": "abc"}).apply(c, BASE)
        await build_auth({"type": "apikey", "key": "k1", "header": "X-Key"}).apply(c, BASE)
        h = dict(c.headers)
        await c.aclose()
        return h
    h = asyncio.run(go())
    assert h["authorization"] == "Bearer abc" and h["x-key"] == "k1"


def test_unknown_auth_type():
    with pytest.raises(AuthError):
        build_auth({"type": "magic"})


# ---------------------------------------------------------------- passive checks on fixtures
def _ctx(authenticated=False) -> CheckContext:
    scope = Scope(BASE, authorized=True)
    cl = ScanClient(scope, ClientConfig(requests_per_second=0), transport=httpx.MockTransport(benign_site))
    return CheckContext(base_url=BASE, client=cl, anon_client=cl, result=ScanResult(BASE), authenticated=authenticated)


def _resp(url="/", status=200, headers=None, text="") -> httpx.Response:
    req = httpx.Request("GET", BASE + url)
    return httpx.Response(status, headers=headers or {}, text=text, request=req)


def _run_passive(resp: httpx.Response, check_id: str):
    ctx = _ctx()
    chk = next(c for c in all_checks() if c.id == check_id)
    ep = Endpoint("GET", str(resp.url))
    asyncio.run(chk.run_response(ctx, ep, resp))
    return ctx.result.findings


def test_cookie_flags_detected():
    fs = _run_passive(_resp(headers=[("set-cookie", "session=abc; Path=/")]), "cookie-flags")
    assert fs and fs[0].severity == "medium" and "HttpOnly" in fs[0].description
    assert "abc" not in fs[0].evidence  # value is redacted


def test_cookie_with_all_flags_is_clean():
    fs = _run_passive(_resp(headers=[("set-cookie", "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax")]), "cookie-flags")
    assert fs == []


def test_jwt_alg_none_and_no_exp():
    fs = _run_passive(_resp(text=f"token={JWT_NO_EXP}"), "jwt-weak")
    sev = {f.severity for f in fs}
    assert "high" in sev and "medium" in sev


def test_verbose_error_detected():
    fs = _run_passive(_resp(text="Traceback (most recent call last):\n  File x"), "info-errors")
    assert fs and fs[0].owasp_web == ["A05:2021"]


def test_secret_is_redacted_in_evidence():
    fs = _run_passive(_resp(text="key AKIAABCDEFGHIJKLMNOP end"), "secrets-exposed")
    assert fs and "redacted" in fs[0].evidence


def test_excessive_data_in_json():
    fs = _run_passive(_resp(headers={"content-type": "application/json"},
                            text='{"id":1,"password_hash":"x"}'), "api-excessive-data")
    assert fs and fs[0].owasp_api == ["API3:2023"]


# ---------------------------------------------------------------- engine end to end (benign mock)
def test_unauthenticated_scan_on_benign_site():
    res = run(make_cfg())
    assert res.mode == "unauthenticated"
    ids = {f.check_id.split(":")[0] for f in res.findings}
    assert "headers-missing" in ids and "info-banner" in ids
    # no injection findings against a site with no sinks (false-positive guard)
    assert not ids & {"xss-reflected", "sqli-error", "ssti", "path-traversal", "open-redirect"}
    assert res.threat_model["threats"]


def test_authenticated_scan_reaches_protected_pages_and_flags_cookie():
    cfg = make_cfg(auth={"type": "form", "login_url": "/login", "username": "alice", "password": "s3cret",
                         "success_indicator": "Welcome back"})
    res = run(cfg)
    assert res.mode == "authenticated"
    assert any(e.path == "/dashboard" for e in res.endpoints)
    ids = {f.check_id.split(":")[0] for f in res.findings}
    assert "jwt-weak" in ids          # token only visible on the authenticated page
    assert "authz-unauth-access" not in ids  # anon gets redirected -> no false positive
    assert all(f.authenticated for f in res.findings if f.check_id.startswith("jwt-weak"))


def test_page_only_linked_after_login_but_open_to_anon_is_flagged():
    """A page reachable only via a logged-in link yet served to anonymous clients is a finding."""
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/dashboard" and "session=s1" in req.headers.get("cookie", ""):
            return httpx.Response(200, headers={"content-type": "text/html"},
                                  text='<html>Dashboard <a href="/reports">Reports</a></html>')
        if req.url.path == "/reports":  # no authentication check at all
            return httpx.Response(200, headers={"content-type": "text/html"},
                                  text="<html>Quarterly report: " + "data " * 40 + "</html>")
        return benign_site(req)

    cfg = make_cfg(auth={"type": "form", "login_url": "/login", "username": "alice", "password": "s3cret",
                         "success_indicator": "Welcome back"})
    res = asyncio.run(ScanEngine(cfg, transport=httpx.MockTransport(handler)).run())
    hits = [f for f in res.findings if f.check_id == "authz-unauth-access"]
    assert [h.url for h in hits] == [BASE + "/reports"]
    assert "A01:2021" in hits[0].owasp_web and "API5:2023" in hits[0].owasp_api


def test_failed_login_aborts_scan():
    cfg = make_cfg(auth={"type": "form", "login_url": "/login", "username": "alice", "password": "nope",
                         "success_indicator": "Welcome back"})
    with pytest.raises(AuthError):
        run(cfg)


def test_passive_mode_sends_no_payloads():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        return benign_site(req)

    eng = ScanEngine(make_cfg(active=False), transport=httpx.MockTransport(handler))
    asyncio.run(eng.run())
    assert not any("dast" in u.lower() and "<" in u for u in seen)
    assert not any("etc" in u and "passwd" in u for u in seen)


# ---------------------------------------------------------------- threat model + reports
def _sample_result() -> ScanResult:
    r = run(make_cfg())
    return r


def test_threat_model_structure():
    tm = _sample_result().threat_model
    assert {"assets", "entry_points", "trust_boundaries", "threats", "attack_surface"} <= set(tm)
    for t in tm["threats"]:
        assert t["stride"] in {"Spoofing", "Tampering", "Repudiation", "Information disclosure",
                               "Denial of service", "Elevation of privilege"}
        assert 1 <= t["risk_score"] <= 9
    # logging/monitoring cannot be validated by DAST and must say so
    r1 = next(t for t in tm["threats"] if t["id"] == "R1")
    assert "Manual review" in r1["status"]


def test_threat_model_marks_evidenced_threats():
    r = ScanResult(target=BASE)
    r.add(Finding("sqli-error", "SQLi", "high", "d", BASE + "/x", parameter="id", owasp_web=["A03:2021"]))
    surface = Surface([Endpoint("GET", BASE + "/x?id=1", [Param("id", "query", "1")])])
    tm = build_threat_model(r, surface)
    t1 = next(t for t in tm["threats"] if t["id"] == "T1")
    assert t1["status"] == "Evidenced by scan" and t1["risk"] in ("Critical", "High")


def test_reports_render_in_all_formats(tmp_path):
    r = _sample_result()
    html = to_html(r)
    assert "OWASP Top 10 - Web (2021)" in html and "OWASP API Security Top 10 (2023)" in html
    assert "Threat model (STRIDE)" in html and "A01:2021" in html and "API1:2023" in html
    data = json.loads(to_json(r))
    assert "owasp_coverage" in data and set(data["owasp_coverage"]["web_top10_2021"]) == set(WEB_TOP10)
    sarif = json.loads(to_sarif(r))
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["tool"]["driver"]["name"] == "Dynascan"
    assert "# DAST Report" in to_markdown(r)
    out = write_reports(r, tmp_path, ["html", "json", "sarif", "md"])
    assert all(p.exists() and p.stat().st_size > 0 for p in out.values())


def test_html_report_escapes_untrusted_content():
    r = ScanResult(target=BASE)
    r.add(Finding("x", "<script>alert(1)</script>", "low", "<img src=x onerror=alert(1)>", BASE))
    html = to_html(r)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_coverage_groups_findings():
    r = ScanResult(target=BASE)
    r.add(Finding("a", "A", "high", "d", BASE, owasp_web=["A03:2021"], owasp_api=["API8:2023"]))
    cov = coverage(r.findings)
    assert len(cov["web"]["A03:2021"]) == 1 and len(cov["api"]["API8:2023"]) == 1
