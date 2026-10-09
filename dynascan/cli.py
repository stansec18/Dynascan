"""Command line interface."""
from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
from pathlib import Path

from . import __version__
from .auth import AuthError
from .config import ScanConfig
from .engine import ScanEngine
from .report import write_reports
from .scope import OutOfScopeError

BANNER = f"Dynascan {__version__} - use only against systems you are authorised to test."


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dynascan", description=BANNER)
    p.add_argument("target", nargs="?", help="Target base URL (e.g. https://app.example.com)")
    p.add_argument("-c", "--config", help="YAML/JSON scan config file (CLI flags override it)")
    p.add_argument("--i-am-authorized", action="store_true", dest="authorized",
                   help="Confirm you have permission to test this target (required)")
    p.add_argument("--openapi", help="OpenAPI/Swagger file or URL to import for API scanning")
    p.add_argument("--passive", action="store_true", help="Passive mode: no attack payloads are sent")
    p.add_argument("-o", "--output", default="dynascan-output", help="Output directory (default: dynascan-output)")
    p.add_argument("-f", "--format", default="html,json", help="Report formats: html,json,sarif,md (comma separated)")
    # authentication
    g = p.add_argument_group("authentication (omit for an unauthenticated scan)")
    g.add_argument("--auth", choices=["form", "bearer", "apikey", "headers", "token-login"],
                   help="Authentication method")
    g.add_argument("--login-url", help="Login URL (form / token-login)")
    g.add_argument("--username", help="Username (password via DYNASCAN_PASSWORD env or prompt)")
    g.add_argument("--username-field", default="username")
    g.add_argument("--password-field", default="password")
    g.add_argument("--token-path", default="token", help="Dotted JSON path of the token in the login response")
    g.add_argument("--success-indicator", default="", help="Text expected in the page after a successful login")
    g.add_argument("--token", help="Bearer token / API key (or DYNASCAN_TOKEN env)")
    g.add_argument("--api-key-header", default="X-API-Key")
    g.add_argument("-H", "--header", action="append", default=[], metavar="NAME:VALUE", help="Extra header (repeatable)")
    g.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE", help="Session cookie (repeatable)")
    # tuning
    t = p.add_argument_group("tuning")
    t.add_argument("--max-pages", type=int)
    t.add_argument("--rate", type=float, help="Max requests per second")
    t.add_argument("--exclude", action="append", default=[], help="Regex of paths to never request (repeatable)")
    t.add_argument("--skip-check", action="append", default=[], help="Skip checks by id prefix (repeatable)")
    t.add_argument("--only-check", action="append", default=[], help="Run only checks by id prefix (repeatable)")
    t.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")
    t.add_argument("--proxy", help="HTTP(S) proxy, e.g. http://127.0.0.1:8080 (Burp/ZAP)")
    t.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"],
                   help="Exit with code 2 if a finding of at least this severity exists (for CI)")
    p.add_argument("--list-checks", action="store_true", help="List available checks and exit")
    p.add_argument("--version", action="version", version=BANNER)
    return p


def _auth_from_args(a: argparse.Namespace) -> dict | None:
    if not a.auth:
        return None
    pw = os.environ.get("DYNASCAN_PASSWORD")
    tok = a.token or os.environ.get("DYNASCAN_TOKEN")
    if a.auth in ("form", "token-login"):
        if not (a.login_url and a.username):
            raise SystemExit("--login-url and --username are required for this auth type")
        pw = pw or getpass.getpass(f"Password for {a.username}: ")
        cfg = {"type": "form" if a.auth == "form" else "token_login", "login_url": a.login_url,
               "username": a.username, "password": pw, "username_field": a.username_field,
               "password_field": a.password_field}
        if a.auth == "form":
            cfg["success_indicator"] = a.success_indicator
        else:
            cfg["token_path"] = a.token_path
        return cfg
    if a.auth == "bearer":
        if not tok:
            raise SystemExit("--token (or DYNASCAN_TOKEN) required for bearer auth")
        return {"type": "bearer", "token": tok}
    if a.auth == "apikey":
        if not tok:
            raise SystemExit("--token (or DYNASCAN_TOKEN) required for apikey auth")
        return {"type": "apikey", "key": tok, "header": a.api_key_header}
    headers = dict(h.split(":", 1) for h in a.header if ":" in h)
    cookies = dict(c.split("=", 1) for c in a.cookie if "=" in c)
    return {"type": "headers", "headers": {k.strip(): v.strip() for k, v in headers.items()},
            "cookies": cookies}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    a = parser.parse_args(argv)
    if a.list_checks:
        from .checks import all_checks
        for c in all_checks():
            print(f"{c.id:24} {c.kind:8} {c.severity:8} {c.title}")
        return 0

    try:
        cfg = ScanConfig.from_file(a.config) if a.config else None
        if cfg is None:
            if not a.target:
                parser.error("a target URL or --config is required")
            cfg = ScanConfig(target=a.target)
        elif a.target:
            cfg.target = a.target
    except (ValueError, OSError) as e:
        print(f"config error: {e}", file=sys.stderr)
        return 1

    if a.authorized:
        cfg.authorized = True
    if a.openapi:
        cfg.openapi = a.openapi
    if a.passive:
        cfg.active = False
    auth = _auth_from_args(a)
    if auth:
        cfg.auth = auth
    if a.header and not a.auth:
        cfg.headers.update(dict((k.strip(), v.strip()) for k, v in (h.split(":", 1) for h in a.header if ":" in h)))
    if a.max_pages:
        cfg.max_pages = a.max_pages
    if a.rate:
        cfg.requests_per_second = a.rate
    cfg.exclude_paths += a.exclude
    cfg.skip_checks += a.skip_check
    cfg.only_checks += a.only_check
    if a.insecure:
        cfg.verify_tls = False
    if a.proxy:
        cfg.proxy = a.proxy

    print(BANNER)
    print(f"Target: {cfg.target}  mode: {'authenticated' if cfg.auth else 'unauthenticated'}"
          f"{'' if cfg.active else ' (passive)'}")

    last = {"msg": ""}

    def progress(msg: str, frac: float) -> None:
        if msg != last["msg"] and sys.stderr.isatty():
            print(f"[{int(frac * 100):3d}%] {msg[:100]}", file=sys.stderr)
            last["msg"] = msg

    engine = ScanEngine(cfg, progress)
    try:
        result = asyncio.run(engine.run())
    except OutOfScopeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except AuthError as e:
        print(f"authentication error: {e}", file=sys.stderr)
        return 4
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

    formats = [x.strip() for x in a.format.split(",") if x.strip()]
    written = write_reports(result, Path(a.output), formats, cfg.redacted())
    c = result.counts()
    print(f"\nFindings: critical={c['critical']} high={c['high']} medium={c['medium']} "
          f"low={c['low']} info={c['info']}  ({result.requests_made} requests)")
    for fmt, path in written.items():
        print(f"  {fmt:5} -> {path}")

    if a.fail_on:
        order = ["critical", "high", "medium", "low", "info"]
        limit = order.index(a.fail_on)
        if any(c[s] for s in order[: limit + 1]):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
