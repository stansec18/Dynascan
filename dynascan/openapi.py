"""Import OpenAPI 3.x / Swagger 2.0 specs (JSON or YAML) into scannable endpoints."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import yaml

from .models import Endpoint, Param

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
# Methods the scanner will actively fuzz. DELETE is only fuzzed when explicitly enabled.
_SAMPLE = {"string": "test", "integer": "1", "number": "1", "boolean": "true"}


def load_spec(source: str | Path) -> dict[str, Any]:
    text = Path(source).read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except ValueError:
        return yaml.safe_load(text)


def _resolve(spec: dict[str, Any], node: Any, depth: int = 0) -> Any:
    if depth > 8 or not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        cur: Any = spec
        for part in ref[2:].split("/"):
            cur = cur.get(part.replace("~1", "/").replace("~0", "~"), {}) if isinstance(cur, dict) else {}
        return _resolve(spec, cur, depth + 1)
    return node


def _sample_value(schema: dict[str, Any]) -> str:
    if "example" in schema:
        return str(schema["example"])
    if "enum" in schema and schema["enum"]:
        return str(schema["enum"][0])
    return _SAMPLE.get(schema.get("type", "string"), "test")


def _body_params(spec: dict[str, Any], schema: dict[str, Any]) -> list[Param]:
    schema = _resolve(spec, schema)
    params: list[Param] = []
    for name, sub in (schema.get("properties") or {}).items():
        sub = _resolve(spec, sub)
        params.append(Param(name, "json", _sample_value(sub)))
    return params


def base_urls(spec: dict[str, Any], fallback: str) -> str:
    servers = spec.get("servers")
    if servers and isinstance(servers, list) and servers[0].get("url"):
        return urljoin(fallback, servers[0]["url"])
    if spec.get("host"):  # swagger 2
        scheme = (spec.get("schemes") or ["https"])[0]
        return f"{scheme}://{spec['host']}{spec.get('basePath', '')}"
    return fallback


def endpoints_from_spec(spec: dict[str, Any], fallback_base: str) -> tuple[list[Endpoint], dict[str, Any]]:
    """Return (endpoints, meta). ``meta`` carries info useful for threat modelling."""
    base = base_urls(spec, fallback_base).rstrip("/")
    out: list[Endpoint] = []
    secured = 0
    sec_schemes = list((spec.get("components", {}).get("securitySchemes")
                        or spec.get("securityDefinitions") or {}).keys())
    global_sec = bool(spec.get("security"))
    for path, item in (spec.get("paths") or {}).items():
        item = _resolve(spec, item)
        shared = [_resolve(spec, p) for p in item.get("parameters", [])]
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            params: list[Param] = []
            url_path = path
            for p in shared + [_resolve(spec, p) for p in op.get("parameters", [])]:
                name, where = p.get("name"), p.get("in")
                schema = _resolve(spec, p.get("schema") or p)
                val = _sample_value(schema)
                if where == "path":
                    url_path = url_path.replace("{" + str(name) + "}", val)
                    params.append(Param(str(name), "path", val))
                elif where == "query":
                    params.append(Param(str(name), "query", val))
                elif where == "header":
                    params.append(Param(str(name), "header", val))
                elif where == "body":  # swagger 2
                    params += _body_params(spec, p.get("schema", {}))
            body_type = ""
            rb = _resolve(spec, op.get("requestBody") or {})
            for ctype, media in (rb.get("content") or {}).items():
                if "json" in ctype:
                    body_type = "json"
                    params += _body_params(spec, media.get("schema", {}))
                    break
                if "form" in ctype:
                    body_type = "form"
                    for pp in _body_params(spec, media.get("schema", {})):
                        pp.location = "form"
                        params.append(pp)
                    break
            if body_type == "" and any(p.location == "json" for p in params):
                body_type = "json"
            url = base + re.sub(r"\{[^}]+\}", "1", url_path)
            ep = Endpoint(method.upper(), url, params, body_type=body_type, source="openapi")
            ep.description = op.get("summary") or op.get("operationId") or ""
            ep.requires_auth = bool(op.get("security")) or (global_sec and op.get("security") != [])
            if ep.requires_auth:
                secured += 1
            out.append(ep)
    meta = {"title": spec.get("info", {}).get("title", ""),
            "version": spec.get("info", {}).get("version", ""),
            "security_schemes": sec_schemes,
            "operations": len(out), "secured_operations": secured,
            "declared_base": base}
    return out, meta
