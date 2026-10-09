"""Report generation: HTML (primary), JSON, SARIF and Markdown."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import __version__
from ..models import SEVERITIES, SEVERITY_RANK, ScanResult
from ..owasp import API_TOP10, CWE_NAMES, WEB_TOP10, coverage

_TEMPLATES = Path(__file__).parent / "templates"

SEV_COLORS = {"critical": "#7f1d1d", "high": "#dc2626", "medium": "#d97706", "low": "#2563eb", "info": "#6b7280"}


def _category_rows(groups: dict[str, list], catalog: dict[str, tuple[str, str]]) -> list[dict[str, Any]]:
    rows = []
    for code, (name, desc) in catalog.items():
        fs = groups.get(code, [])
        worst = min((SEVERITY_RANK[f.severity] for f in fs), default=None)
        rows.append({
            "code": code, "name": name, "description": desc, "count": len(fs),
            "worst": SEVERITIES[worst] if worst is not None else None,
            "findings": [f.fingerprint for f in fs],
        })
    return rows


def build_context(result: ScanResult, config: dict[str, Any] | None = None) -> dict[str, Any]:
    cov = coverage(result.findings)
    findings = result.sorted_findings()
    counts = result.counts()
    total = len(findings)
    risk = "Critical" if counts["critical"] else "High" if counts["high"] else \
        "Medium" if counts["medium"] else "Low" if counts["low"] else "Informational" if counts["info"] else "None"
    return {
        "version": __version__,
        "result": result,
        "findings": findings,
        "counts": counts,
        "total": total,
        "overall_risk": risk,
        "web_rows": _category_rows(cov["web"], WEB_TOP10),
        "api_rows": _category_rows(cov["api"], API_TOP10),
        "tm": result.threat_model or {},
        "cwe_names": CWE_NAMES,
        "sev_colors": SEV_COLORS,
        "generated": dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "started": dt.datetime.fromtimestamp(result.started).strftime("%Y-%m-%d %H:%M:%S"),
        "duration": int((result.finished or result.started) - result.started),
        "config": config or {},
        "sev_order": SEVERITIES,
        "finding_titles": {f.fingerprint: f.title for f in findings},
    }


def to_html(result: ScanResult, config: dict[str, Any] | None = None) -> str:
    env = Environment(loader=FileSystemLoader(_TEMPLATES), autoescape=select_autoescape(["html"]))
    return env.get_template("report.html").render(**build_context(result, config))


def to_json(result: ScanResult, config: dict[str, Any] | None = None) -> str:
    data = result.to_dict()
    data["tool"] = {"name": "Dynascan", "version": __version__}
    if config:
        data["config"] = config
    cov = coverage(result.findings)
    data["owasp_coverage"] = {
        "web_top10_2021": {k: [f.fingerprint for f in v] for k, v in cov["web"].items()},
        "api_top10_2023": {k: [f.fingerprint for f in v] for k, v in cov["api"].items()},
    }
    return json.dumps(data, indent=2, default=str)


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(result: ScanResult) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in result.sorted_findings():
        rid = f.check_id.split(":")[0]
        rules.setdefault(rid, {
            "id": rid, "name": f.title, "shortDescription": {"text": f.title},
            "help": {"text": f.remediation or "See report."},
            "properties": {"tags": f.owasp_web + f.owasp_api + f.cwe},
        })
        results.append({
            "ruleId": rid, "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f"{f.description} {('Parameter: ' + f.parameter) if f.parameter else ''}".strip()},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.url}}}],
            "partialFingerprints": {"dynascan/v1": f.fingerprint},
            "properties": {"severity": f.severity, "confidence": f.confidence, "owaspWeb": f.owasp_web,
                           "owaspApi": f.owasp_api, "cwe": f.cwe},
        })
    sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": "Dynascan", "version": __version__,
                                           "rules": list(rules.values())}}, "results": results}]}
    return json.dumps(sarif, indent=2)


def to_markdown(result: ScanResult) -> str:
    c = result.counts()
    L = [f"# DAST Report - {result.target}", "",
         f"Mode: **{result.mode}** | Requests: {result.requests_made} | Endpoints: {len(result.endpoints)}", "",
         "| Critical | High | Medium | Low | Info |", "|---|---|---|---|---|",
         f"| {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | {c['info']} |", "",
         "## OWASP Top 10 (2021) coverage", ""]
    cov = coverage(result.findings)
    for code, (name, _) in WEB_TOP10.items():
        L.append(f"- **{code} {name}**: {len(cov['web'].get(code, []))} finding(s)")
    L += ["", "## OWASP API Security Top 10 (2023) coverage", ""]
    for code, (name, _) in API_TOP10.items():
        L.append(f"- **{code} {name}**: {len(cov['api'].get(code, []))} finding(s)")
    L += ["", "## Findings", ""]
    for f in result.sorted_findings():
        L += [f"### [{f.severity.upper()}] {f.title}",
              f"- URL: `{f.method} {f.url}`" + (f" (parameter `{f.parameter}`)" if f.parameter else ""),
              f"- OWASP: {', '.join(f.owasp_web + f.owasp_api) or 'n/a'} | CWE: {', '.join(f.cwe) or 'n/a'} | Confidence: {f.confidence}",
              f"- {f.description}", f"- Evidence: `{f.evidence}`" if f.evidence else "",
              f"- Fix: {f.remediation}", ""]
    tm = result.threat_model or {}
    if tm:
        L += ["## Threat model (STRIDE)", ""]
        for t in tm.get("threats", []):
            L.append(f"- **{t['id']} {t['stride']} / {t['component']}** [{t['risk']}] - {t['threat']} _({t['status']})_")
    return "\n".join(L) + "\n"


def write_reports(result: ScanResult, out_dir: str | Path, formats: list[str] | None = None,
                  config: dict[str, Any] | None = None, basename: str = "dynascan-report") -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    formats = formats or ["html", "json"]
    written: dict[str, Path] = {}
    makers = {
        "html": lambda: to_html(result, config), "json": lambda: to_json(result, config),
        "sarif": lambda: to_sarif(result), "md": lambda: to_markdown(result),
    }
    ext = {"html": "html", "json": "json", "sarif": "sarif", "md": "md"}
    for fmt in formats:
        if fmt not in makers:
            raise ValueError(f"unknown report format: {fmt}")
        p = out / f"{basename}.{ext[fmt]}"
        p.write_text(makers[fmt](), encoding="utf-8")
        written[fmt] = p
    return written
