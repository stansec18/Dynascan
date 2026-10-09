# Dynascan

Dynamic application security testing (DAST) tool with:

- **Unauthenticated and authenticated scans** (form login, JSON token login, Bearer/JWT, API key, custom headers/cookies)
- **Web + API coverage**: HTML crawler and OpenAPI/Swagger import
- **OWASP mapping**: every finding is tagged with OWASP Top 10 (2021, web), OWASP API Security Top 10 (2023) and CWE
- **Threat modelling**: STRIDE model generated from the discovered attack surface and linked to findings
- **Reports**: HTML (primary), JSON, SARIF (for CI/code scanning), Markdown
- **CLI and desktop GUI** (PySide6) sharing one engine; Windows `.exe` installer packaging included

> Use only against systems you are explicitly authorised to test. The scanner refuses to run unless you confirm
> authorisation (`--i-am-authorized` / GUI checkbox) and never sends requests outside the declared scope.

## Install

### Kali / Debian / Ubuntu (recommended)

Kali's system Python blocks global `pip install` (PEP 668), so Dynascan installs into a virtualenv:

```bash
git clone https://github.com/stansec18/dynascan.git && cd dynascan
./scripts/install-kali.sh            # CLI + GUI   (use --no-gui for CLI only)
source .venv/bin/activate
dynascan --help
```

### Any platform

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[gui]"     # GUI is optional; CLI works without PySide6
```

Requires Python 3.10+.

## Quick start

```bash
dynascan https://target.example.com --i-am-authorized -o dynascan-output -f html,json
xdg-open dynascan-output/dynascan-report.html
```

## CLI

```bash
# Unauthenticated
dynascan https://app.example.com --i-am-authorized -o out

# Authenticated form login (password via env var or prompt, never on the command line)
export DYNASCAN_PASSWORD='...'
dynascan https://app.example.com --i-am-authorized --auth form \
   --login-url /login --username alice --success-indicator "Sign out"

# API scan with a bearer token and an OpenAPI spec
export DYNASCAN_TOKEN='eyJ...'
dynascan https://api.example.com --i-am-authorized --auth bearer --openapi openapi.yaml -f html,json,sarif

# Passive only (no attack payloads), through Burp/ZAP, fail CI on high+
dynascan https://app.example.com --i-am-authorized --passive --proxy http://127.0.0.1:8080 --fail-on high

dynascan --list-checks
```

Config file (`-c scan.yaml`; CLI flags override it):

```yaml
target: https://app.example.com
authorized: true
openapi: ./openapi.yaml
auth:
  type: token_login          # form | token_login | bearer | apikey | headers
  login_url: /api/auth/login
  username: alice
  password: change-me          # keep config files with real passwords out of version control
  token_path: data.access_token
exclude_paths: ["^/logout", "^/admin/delete"]
requests_per_second: 10
```

Exit codes: `0` ok, `2` findings at/above `--fail-on`, `3` not authorised/out of scope, `4` authentication failed.

## GUI

```bash
dynascan-gui         # or: python -m dynascan.gui.app
```

## Windows installer

PyInstaller cannot cross-compile, so build on Windows (or let CI do it):

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
```

Produces `dist\Dynascan\Dynascan.exe` and, if Inno Setup is installed, `installer-out\Dynascan-Setup-0.1.0.exe`.
The GitHub Actions workflow `.github/workflows/build-windows.yml` does the same on `windows-latest`.
Sign the installer with a code-signing certificate to avoid SmartScreen/antivirus warnings.

## What is checked

Run `dynascan --list-checks`. Highlights: security headers, cookie flags, CORS, TLS/HSTS posture, verbose errors,
secrets in responses, exposed files (`.git`, `.env`, actuator...), API docs/GraphQL introspection exposure, reflected XSS,
error-based SQLi, SSTI, path traversal, open redirect, login brute-force protection, JWT weaknesses, excessive data
exposure, unauthenticated access to resources found while logged in, IDOR/BOLA candidates, old API versions, SSRF candidates.

Active checks send non-destructive probes only. By default `PUT/PATCH/DELETE` endpoints are **not** fuzzed
(`allow_unsafe_methods: true` to enable). POST forms are fuzzed, which may create records on a test environment -
prefer staging systems for authenticated active scans.

## Limitations

DAST cannot prove business-logic flaws, multi-user authorisation (BOLA/BFLA are heuristics that need a second
account to confirm), SSRF without an out-of-band listener, or logging/monitoring adequacy. JavaScript-heavy SPAs are
only crawled statically; import their OpenAPI spec or seed URLs. Low-confidence findings need manual verification.

## Tests

```bash
pip install -e ".[dev]" && pytest
```

## Contributing / publishing notes

- Tests run in CI on Python 3.10-3.13 (`.github/workflows/ci.yml`); the Windows installer is built by
  `.github/workflows/build-windows.yml` (manual run or on `v*` tags).
- Please read [SECURITY.md](SECURITY.md) for responsible-use rules and how to report vulnerabilities in Dynascan itself.
- Licensed under the MIT License (see `LICENSE`).
