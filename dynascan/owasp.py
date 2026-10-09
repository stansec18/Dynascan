"""OWASP Top 10 (2021, web) and OWASP API Security Top 10 (2023) reference data."""
from __future__ import annotations

WEB_TOP10 = {
    "A01:2021": ("Broken Access Control", "Restrictions on what authenticated users may do are not properly enforced."),
    "A02:2021": ("Cryptographic Failures", "Missing or weak protection of data in transit and at rest."),
    "A03:2021": ("Injection", "Untrusted data is sent to an interpreter as part of a command or query (SQL, OS, XSS, ...)."),
    "A04:2021": ("Insecure Design", "Missing or ineffective security controls caused by design flaws."),
    "A05:2021": ("Security Misconfiguration", "Missing hardening, unnecessary features, default settings, verbose errors."),
    "A06:2021": ("Vulnerable and Outdated Components", "Use of components with known vulnerabilities or no longer supported."),
    "A07:2021": ("Identification and Authentication Failures", "Weak authentication, session management or credential handling."),
    "A08:2021": ("Software and Data Integrity Failures", "Code and infrastructure that does not protect against integrity violations."),
    "A09:2021": ("Security Logging and Monitoring Failures", "Insufficient logging/monitoring allowing attacks to go undetected."),
    "A10:2021": ("Server-Side Request Forgery", "The application fetches a remote resource without validating a user-supplied URL."),
}

API_TOP10 = {
    "API1:2023": ("Broken Object Level Authorization", "APIs expose object identifiers and fail to verify the caller may access each object."),
    "API2:2023": ("Broken Authentication", "Authentication mechanisms are implemented incorrectly or are missing."),
    "API3:2023": ("Broken Object Property Level Authorization", "Excessive data exposure or mass assignment of object properties."),
    "API4:2023": ("Unrestricted Resource Consumption", "No limits on requests, payload sizes or resources per client."),
    "API5:2023": ("Broken Function Level Authorization", "Complex access-control policies leave administrative or privileged functions reachable."),
    "API6:2023": ("Unrestricted Access to Sensitive Business Flows", "Business flows can be abused through automation."),
    "API7:2023": ("Server Side Request Forgery", "API fetches a remote resource from a user-supplied URI without validation."),
    "API8:2023": ("Security Misconfiguration", "Missing hardening, permissive CORS, verbose errors, missing security headers."),
    "API9:2023": ("Improper Inventory Management", "Outdated, undocumented or exposed API versions and endpoints."),
    "API10:2023": ("Unsafe Consumption of APIs", "Trusting data from third-party APIs more than user input."),
}

CWE_NAMES = {
    "CWE-16": "Configuration",
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-209": "Information Exposure Through an Error Message",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-346": "Origin Validation Error",
    "CWE-538": "Insertion of Sensitive Information into Externally-Accessible File",
    "CWE-548": "Exposure of Information Through Directory Listing",
    "CWE-601": "Open Redirect",
    "CWE-614": "Sensitive Cookie Without 'Secure' Attribute",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-770": "Allocation of Resources Without Limits",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-915": "Mass Assignment",
    "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
    "CWE-1021": "Improper Restriction of Rendered UI Layers (Clickjacking)",
    "CWE-1275": "Sensitive Cookie with Improper SameSite Attribute",
}


def web_name(code: str) -> str:
    return WEB_TOP10.get(code, ("Unknown", ""))[0]


def api_name(code: str) -> str:
    return API_TOP10.get(code, ("Unknown", ""))[0]


def coverage(findings) -> dict[str, dict[str, list]]:
    """Group findings per OWASP category for both lists (used in reports)."""
    web: dict[str, list] = {k: [] for k in WEB_TOP10}
    api: dict[str, list] = {k: [] for k in API_TOP10}
    for f in findings:
        for c in f.owasp_web:
            web.setdefault(c, []).append(f)
        for c in f.owasp_api:
            api.setdefault(c, []).append(f)
    return {"web": web, "api": api}
