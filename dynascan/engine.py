"""Scan orchestration: authenticate -> discover -> passive -> host -> active -> threat model."""
from __future__ import annotations

import asyncio
import time
from typing import Callable
from urllib.parse import urljoin

import httpx

from .auth import AuthError, build_auth
from .checks import CheckContext, all_checks
from .config import ScanConfig
from .crawler import Crawler
from .http_client import ClientConfig, RequestBudgetExceeded, ScanClient
from .models import Endpoint, ScanResult
from .openapi import endpoints_from_spec, load_spec
from .scope import Scope
from .threatmodel import Surface, build_threat_model

ProgressFn = Callable[[str, float], None]  # (message, fraction 0..1)

_UNSAFE = {"PUT", "PATCH", "DELETE"}


class ScanEngine:
    def __init__(self, cfg: ScanConfig, progress: ProgressFn | None = None,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.cfg = cfg
        self._progress = progress or (lambda msg, frac: None)
        self._transport = transport  # lets tests run the scanner against an in-process app
        self._stop = False
        self.result = ScanResult(target=cfg.target)

    # -- control ---------------------------------------------------------------
    def stop(self) -> None:
        self._stop = True

    def _say(self, msg: str, frac: float) -> None:
        self._progress(msg, min(max(frac, 0.0), 1.0))

    # -- main ------------------------------------------------------------------
    async def run(self) -> ScanResult:
        cfg, result = self.cfg, self.result
        scope = Scope(cfg.target, cfg.allowed_hosts, cfg.exclude_paths, cfg.authorized)
        scope.require_authorization()
        ccfg = ClientConfig(timeout=cfg.timeout, max_concurrency=cfg.concurrency,
                            requests_per_second=cfg.requests_per_second, verify_tls=cfg.verify_tls,
                            headers=dict(cfg.headers), proxy=cfg.proxy, max_requests=cfg.max_requests)
        anon = ScanClient(scope, ccfg, transport=self._transport, label="anon")
        main = anon
        auth_client: ScanClient | None = None
        handler = build_auth(cfg.auth)
        try:
            if handler is not None:
                self._say("Authenticating…", 0.02)
                auth_client = ScanClient(scope, ccfg, transport=self._transport, label="auth")
                try:
                    await handler.apply(auth_client, cfg.target)
                    if not await handler.verify(auth_client, cfg.target):
                        raise AuthError("post-login verification URL did not return HTTP 200")
                except AuthError as e:
                    result.notes.append(f"Authentication failed: {e}. Aborting authenticated scan.")
                    raise
                main = auth_client
                result.mode = "authenticated"
                result.auth_summary = handler.description
                self._say(f"Authenticated ({handler.description})", 0.05)
            await self._scan(main, anon, handler is not None)
        finally:
            result.requests_made = anon.request_count + (auth_client.request_count if auth_client else 0)
            result.finished = time.time()
            await anon.aclose()
            if auth_client:
                await auth_client.aclose()
        return result

    async def _scan(self, main: ScanClient, anon: ScanClient, authenticated: bool) -> None:
        cfg, result = self.cfg, self.result
        meta: dict = {}

        # ---- discovery
        self._say("Crawling application…", 0.08)
        crawler = Crawler(main, cfg.max_pages, cfg.max_depth)
        endpoints: dict[str, Endpoint] = {}
        try:
            for ep in await crawler.crawl([cfg.target, *cfg.seeds]):
                endpoints[ep.key] = ep
        except RequestBudgetExceeded as e:
            result.notes.append(str(e))
        if cfg.openapi:
            self._say("Importing OpenAPI specification…", 0.2)
            try:
                spec = await self._load_openapi(main, cfg.openapi)
                api_eps, meta = endpoints_from_spec(spec, cfg.target)
                for ep in api_eps:
                    endpoints.setdefault(ep.key, ep)
                result.notes.append(f"Imported {len(api_eps)} operations from OpenAPI spec.")
            except Exception as e:  # noqa: BLE001
                result.notes.append(f"OpenAPI import failed: {e}")
        eps = list(endpoints.values())
        result.endpoints = eps
        self._say(f"Discovered {len(eps)} endpoints", 0.25)

        # In authenticated mode, also crawl anonymously. Pages linked publicly are public by design;
        # only resources found *solely* through the logged-in session are candidates for
        # "reachable without credentials" findings.
        public_keys: set[str] = set()
        if authenticated:
            self._say("Mapping publicly reachable pages…", 0.27)
            try:
                anon_crawler = Crawler(anon, min(cfg.max_pages, 60), cfg.max_depth)
                public_keys = {ep.key for ep in await anon_crawler.crawl([cfg.target, *cfg.seeds])}
            except RequestBudgetExceeded as e:
                result.notes.append(str(e))

        ctx = CheckContext(base_url=cfg.target, client=main, anon_client=anon, result=result,
                           authenticated=authenticated, endpoints=eps, pages=crawler.pages,
                           options={"login_attempts": cfg.login_attempts, "public_keys": public_keys})
        checks = all_checks(cfg.only_checks or None, cfg.skip_checks or None)

        # ---- baselines (safe methods only: never replay POST/PUT/DELETE without payloads)
        self._say("Collecting baseline responses…", 0.3)
        safe = [e for e in eps if e.method in ("GET", "HEAD")]
        responses = await asyncio.gather(*(main.get(e.url) for e in safe), return_exceptions=True)
        for ep, resp in zip(safe, responses):
            if isinstance(resp, Exception):
                resp = None
            ctx.baselines[ep.key] = resp

        # ---- passive checks on baselines
        self._say("Running passive checks…", 0.4)
        for ep in safe:
            resp = ctx.baselines.get(ep.key)
            if resp is None:
                continue
            for chk in checks:
                if chk.kind == "passive":
                    await chk.run_response(ctx, ep, resp)

        # ---- host-level checks
        host_checks = [c for c in checks if c.kind == "host" and (cfg.active or c.id in _PASSIVE_HOST)]
        for i, chk in enumerate(host_checks):
            if self._stop:
                break
            self._say(f"Host check: {chk.title}", 0.45 + 0.15 * i / max(len(host_checks), 1))
            try:
                await chk.run_host(ctx)
            except RequestBudgetExceeded as e:
                result.notes.append(str(e))
                break

        # ---- active checks
        if cfg.active:
            targets = [e for e in eps if e.method not in _UNSAFE or cfg.allow_unsafe_methods]
            active = [c for c in checks if c.kind == "active"]
            total = max(len(targets) * max(len(active), 1), 1)
            done = 0
            for ep in targets:
                if self._stop:
                    result.notes.append("Scan stopped by user.")
                    break
                for chk in active:
                    self._say(f"{chk.title}: {ep.method} {ep.path}", 0.6 + 0.35 * done / total)
                    done += 1
                    try:
                        await chk.run_endpoint(ctx, ep)
                    except RequestBudgetExceeded as e:
                        result.notes.append(str(e))
                        self._stop = True
                        break
                    except Exception as e:  # noqa: BLE001  a faulty check must not kill the scan
                        result.notes.append(f"check {chk.id} failed on {ep.path}: {type(e).__name__}: {e}")
        else:
            result.notes.append("Passive mode: no attack payloads were sent.")

        # ---- threat model
        self._say("Building threat model…", 0.97)
        surface = Surface(eps, meta, authenticated, result.auth_summary)
        result.threat_model = build_threat_model(result, surface)
        self._say("Done", 1.0)

    async def _load_openapi(self, client: ScanClient, source: str) -> dict:
        if source.startswith(("http://", "https://")):
            resp = await client.get(source)
            if resp is None or resp.status_code != 200:
                raise RuntimeError(f"could not download spec ({resp.status_code if resp else 'network error'})")
            import json, yaml
            try:
                return resp.json()
            except ValueError:
                return yaml.safe_load(resp.text)
        return load_spec(source)


# host checks that send no attack payloads (safe in passive mode)
_PASSIVE_HOST = {"headers-missing", "transport-http", "info-banner", "csrf-missing", "ssrf-candidate"}
