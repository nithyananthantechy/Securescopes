from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import time

import requests


@dataclass(frozen=True)
class ApiTestConfig:
    user_agent: str = "SecureScope-OffSec/0.1 (safe-mode)"
    timeout_s: float = 10.0
    delay_s: float = 0.25
    max_requests: int = 40
    verify_tls: bool = True


COMMON_API_PATHS = (
    "/api",
    "/api/v1",
    "/api/v2",
    "/swagger",
    "/swagger/index.html",
    "/openapi.json",
    "/v1",
    "/v2",
    "/graphql",
    "/health",
    "/status",
)


def endpoint_discovery(base_url: str, *, cfg: ApiTestConfig) -> list[dict[str, Any]]:
    sess = requests.Session()
    found: list[str] = []
    tested = 0
    for p in COMMON_API_PATHS:
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
            if r.status_code in (200, 204, 301, 302, 401, 403):
                found.append(f"{p} -> {r.status_code}")
        except Exception:
            continue

    if found:
        return [{"category": "API", "check": "Endpoint discovery (safe)", "status": "WARNING", "severity": "Low", "details": "Found: " + ", ".join(found[:25])}]
    return [{"category": "API", "check": "Endpoint discovery (safe)", "status": "PASS", "severity": "Low", "details": "No common endpoints detected"}]


def auth_flaws_signal(base_url: str, *, cfg: ApiTestConfig) -> list[dict[str, Any]]:
    """
    Safe auth checks (signal-only):
    - request common endpoints without auth header
    - flags if protected-looking endpoints return 200 with sensitive-ish content type
    """
    sess = requests.Session()
    checks: list[dict[str, Any]] = []
    candidates = ["/api", "/api/v1", "/swagger", "/openapi.json", "/graphql"]
    tested = 0
    for p in candidates:
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
            ct = (r.headers.get("content-type") or "").lower()
            if r.status_code == 200 and any(x in ct for x in ("json", "graphql", "openapi")):
                checks.append({"category": "API", "check": f"Auth signal on {p}", "status": "WARNING", "severity": "Medium", "details": "Endpoint accessible without auth; verify intended exposure"})
            elif r.status_code in (401, 403):
                checks.append({"category": "API", "check": f"Auth required on {p}", "status": "PASS", "severity": "Low", "details": f"Returned {r.status_code} (good)"} )
        except Exception:
            continue

    if not checks:
        checks.append({"category": "API", "check": "Auth signals", "status": "WARNING", "severity": "Low", "details": "No candidates reachable for auth signal checks"})
    return checks


def rate_limit_probe(base_url: str, *, cfg: ApiTestConfig, path: str = "/") -> list[dict[str, Any]]:
    """
    Controlled rate-limit probe:
    - very small burst
    - stops immediately on 429
    """
    sess = requests.Session()
    url = base_url.rstrip("/") + path
    statuses: list[int] = []
    for _ in range(10):
        time.sleep(cfg.delay_s)
        try:
            r = sess.get(url, headers={"User-Agent": cfg.user_agent}, timeout=cfg.timeout_s, verify=cfg.verify_tls)
            statuses.append(r.status_code)
            if r.status_code == 429:
                return [{"category": "API", "check": "Rate limiting", "status": "PASS", "severity": "Low", "details": "429 observed during small probe burst (rate limiting present)"}]
        except Exception:
            break
    if statuses and all(s != 429 for s in statuses):
        return [{"category": "API", "check": "Rate limiting", "status": "WARNING", "severity": "Low", "details": "No 429 during small probe burst; confirm rate limiting policy"}]
    return [{"category": "API", "check": "Rate limiting", "status": "WARNING", "severity": "Low", "details": "Probe incomplete; target unreachable or timed out"}]

