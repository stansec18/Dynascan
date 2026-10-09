# Responsible use and security policy

Dynascan is a security testing tool. Use it only against systems you own or have **explicit written
permission** to test. Unauthorised scanning may be illegal in your jurisdiction.

Built-in safeguards (please keep them if you fork):
- A scan will not start without an explicit authorisation confirmation (`--i-am-authorized` / GUI checkbox).
- Requests are restricted to the declared scope (target host plus any hosts you add); out-of-scope requests are refused.
- Active payloads are non-destructive probes; `PUT/PATCH/DELETE` endpoints are not fuzzed unless you opt in.
- Credentials are never written to reports; cookie/secret evidence is redacted.

## Reporting a vulnerability in Dynascan

Please open a private security advisory on the GitHub repository (Security tab -> "Report a vulnerability")
rather than a public issue.
