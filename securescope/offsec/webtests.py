from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl
import re
import time

import requests


SQLI_ERROR_PATTERNS = (
    r"you have an error in your sql syntax",
    r"warning:\s+mysql",
    r"unclosed quotation mark after the character string",
    r"pg_query\(",
    r"sqlite error",
    r"sqlstate\[\w+\]",
)


@dataclass(frozen=True)
class WebTestConfig:
    user_agent: str = "SecureScope-OffSec/0.1 (safe-mode)"
    timeout_s: float = 10.0
    max_requests: int = 30
    delay_s: float = 0.25  # throttling
    verify_tls: bool = True


def _with_params(url: str, new_params: dict[str, str]) -> str:
    parts = urlsplit(url)
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    params.update(new_params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params, doseq=True), parts.fragment))


def security_headers_check(url: str, *, cfg: WebTestConfig) -> list[dict[str, Any]]:
    sess = requests.Session()
    resp = sess.get(
        url,
        headers={"User-Agent": cfg.user_agent},
        timeout=cfg.timeout_s,
        allow_redirects=True,
        verify=cfg.verify_tls,
    )
    headers = {k.lower(): v for k, v in resp.headers.items()}

    wanted = {
        "strict-transport-security": ("HSTS Enabled", "High"),
        "content-security-policy": ("CSP Configured", "High"),
        "x-frame-options": ("Clickjacking Protection", "High"),
        "x-content-type-options": ("MIME Sniffing Protection", "Medium"),
        "referrer-policy": ("Referrer Policy", "Low"),
        "permissions-policy": ("Permissions Policy", "Low"),
    }

    checks: list[dict[str, Any]] = []
    for h, (name, sev) in wanted.items():
        if h in headers:
            checks.append({"category": "Web", "check": name, "status": "PASS", "severity": sev, "details": f"{h} present"})
        else:
            checks.append({"category": "Web", "check": name, "status": "FAIL", "severity": sev, "details": f"Missing {h}"})

    server = headers.get("server", "")
    if server:
        checks.append({"category": "Web", "check": "Server Banner", "status": "WARNING", "severity": "Medium", "details": f"Server header disclosed: {server}"})
    else:
        checks.append({"category": "Web", "check": "Server Banner", "status": "PASS", "severity": "Low", "details": "No Server header disclosed"})

    return checks


def sqli_detection_safe(url: str, *, cfg: WebTestConfig) -> list[dict[str, Any]]:
    """
    Non-destructive SQLi signal detection:
    - only modifies URL query string (GET)
    - uses benign payloads
    - looks for common error strings
    """
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    if not q:
        return [{"category": "Web", "check": "SQLi (safe) - parameters", "status": "WARNING", "severity": "Low", "details": "No query parameters to test"}]

    sess = requests.Session()
    base = sess.get(url, headers={"User-Agent": cfg.user_agent}, timeout=cfg.timeout_s, verify=cfg.verify_tls).text

    checks: list[dict[str, Any]] = []
    tested = 0
    for k in list(q.keys()):
        if tested >= cfg.max_requests:
            break
        tested += 1
        time.sleep(cfg.delay_s)
        test_url = _with_params(url, {k: (q.get(k, "") + "'")})
        body = sess.get(test_url, headers={"User-Agent": cfg.user_agent}, timeout=cfg.timeout_s, verify=cfg.verify_tls).text
        hay = (body[:20000]).lower()
        if any(re.search(p, hay) for p in SQLI_ERROR_PATTERNS):
            checks.append({"category": "Web", "check": f"SQLi (safe) signal in {k}", "status": "FAIL", "severity": "High", "details": "Database error pattern detected after benign quote injection"})
        elif body != base:
            checks.append({"category": "Web", "check": f"SQLi (safe) heuristic in {k}", "status": "WARNING", "severity": "Medium", "details": "Response changed after benign quote injection; review manually"})
        else:
            checks.append({"category": "Web", "check": f"SQLi (safe) in {k}", "status": "PASS", "severity": "Low", "details": "No obvious SQL error patterns detected"})

    return checks


def xss_detection_safe(url: str, *, cfg: WebTestConfig) -> list[dict[str, Any]]:
    """
    Non-destructive reflected XSS signal detection:
    - sends a harmless marker string
    - checks if marker is reflected in response body
    """
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    if not q:
        return [{"category": "Web", "check": "XSS (safe) - parameters", "status": "WARNING", "severity": "Low", "details": "No query parameters to test"}]

    marker = "SECURESCOPE_XSS_TEST"
    sess = requests.Session()
    checks: list[dict[str, Any]] = []
    tested = 0

    for k in list(q.keys()):
        if tested >= cfg.max_requests:
            break
        tested += 1
        time.sleep(cfg.delay_s)
        test_url = _with_params(url, {k: marker})
        resp = sess.get(test_url, headers={"User-Agent": cfg.user_agent}, timeout=cfg.timeout_s, verify=cfg.verify_tls)
        body = resp.text[:20000]
        if marker in body:
            checks.append({"category": "Web", "check": f"Reflected XSS (safe) in {k}", "status": "WARNING", "severity": "High", "details": "Marker reflected in response; verify output encoding + context"})
        else:
            checks.append({"category": "Web", "check": f"Reflected XSS (safe) in {k}", "status": "PASS", "severity": "Low", "details": "Marker not reflected in response"})

    return checks


def dir_bruteforce_safe(base_url: str, *, cfg: WebTestConfig, paths: list[str] | None = None) -> list[dict[str, Any]]:
    """
    Safe directory discovery:
    - small built-in list
    - throttled
    - stops after max_requests
    """
    if paths is None:
        paths = ["/admin", "/login", "/robots.txt", "/.git/", "/.env", "/api", "/swagger", "/openapi.json"]

    sess = requests.Session()
    checks: list[dict[str, Any]] = []

    tested = 0
    found: list[str] = []
    for p in paths:
        if tested >= cfg.max_requests:
            break
        tested += 1
        time.sleep(cfg.delay_s)
        url = base_url.rstrip("/") + p
        try:
            r = sess.get(
                url,
                headers={"User-Agent": cfg.user_agent},
                timeout=cfg.timeout_s,
                allow_redirects=False,
                verify=cfg.verify_tls,
            )
            if r.status_code in (200, 204, 301, 302, 307, 308, 401, 403):
                found.append(f"{p} -> {r.status_code}")
        except Exception:
            continue

    if found:
        checks.append({"category": "Web", "check": "Directory discovery (safe)", "status": "WARNING", "severity": "Medium", "details": "Interesting paths: " + ", ".join(found[:25])})
    else:
        checks.append({"category": "Web", "check": "Directory discovery (safe)", "status": "PASS", "severity": "Low", "details": "No interesting common paths found (safe list)"})
    return checks

