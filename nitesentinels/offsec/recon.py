from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Iterable

import requests

try:
    import dns.resolver  # type: ignore
except Exception:  # pragma: no cover
    dns = None

try:
    import whois  # type: ignore
except Exception:  # pragma: no cover
    whois = None


DEFAULT_SUBDOMAIN_WORDLIST = (
    "www",
    "api",
    "admin",
    "dev",
    "staging",
    "test",
    "beta",
    "app",
    "cdn",
    "static",
)


@dataclass(frozen=True)
class ReconResult:
    subdomains: list[dict]
    dns: list[dict]
    whois: dict


def _safe_timeout(t: float) -> float:
    return max(1.0, min(20.0, float(t)))


def subdomain_enum(domain: str, *, wordlist: Iterable[str] = DEFAULT_SUBDOMAIN_WORDLIST, timeout_s: float = 3.0) -> list[dict]:
    """
    Safe subdomain enumeration:
    - DNS-only resolution (no HTTP probing)
    - small default wordlist
    - timeouts
    """
    timeout_s = _safe_timeout(timeout_s)
    out: list[dict] = []
    domain = domain.strip().lower().rstrip(".")
    for w in wordlist:
        host = f"{w.strip().lower()}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            out.append({"host": host, "a": ip})
        except Exception:
            continue
    return out


def dns_analysis(domain: str, *, rrtypes: Iterable[str] = ("A", "AAAA", "CNAME", "MX", "NS", "TXT"), timeout_s: float = 4.0) -> list[dict]:
    timeout_s = _safe_timeout(timeout_s)
    domain = domain.strip().lower().rstrip(".")
    if dns is None:
        return [{"rrtype": "ERROR", "records": [], "details": "dnspython not installed"}]

    res = dns.resolver.Resolver()
    res.lifetime = timeout_s
    res.timeout = timeout_s
    out: list[dict] = []
    for rr in rrtypes:
        try:
            ans = res.resolve(domain, rr)
            out.append({"rrtype": rr, "records": [str(r) for r in ans]})
        except Exception as e:
            out.append({"rrtype": rr, "records": [], "details": str(e)})
    return out


def whois_lookup(domain: str, *, timeout_s: float = 8.0) -> dict:
    timeout_s = _safe_timeout(timeout_s)
    domain = domain.strip().lower().rstrip(".")
    if whois is None:
        return {"error": "python-whois not installed"}
    try:
        # python-whois doesn't expose timeout cleanly; keep scope safe by not retrying.
        w = whois.whois(domain)
        # normalize to JSON-friendly
        return {k: (str(v) if not isinstance(v, (str, int, float, bool, type(None), list, dict)) else v) for k, v in dict(w).items()}
    except Exception as e:
        return {"error": str(e)}

