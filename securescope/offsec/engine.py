from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

from securescope.offsec.audit import AuditLogger, new_run_id
from securescope.offsec.scope import Scope
from securescope.offsec import recon as recon_mod
from securescope.offsec import webtests as web_mod
from securescope.offsec import api_tests as api_mod


ScanKind = Literal["recon", "web", "api"]


def _norm_url(url: str) -> str:
    url = url.strip()
    if not url:
        return url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _host_from_url(url: str) -> str:
    return urlsplit(url).hostname or ""


@dataclass
class OffsecEngine:
    scope: Scope
    audit: AuditLogger
    actor: str = "cli"
    safe_mode: bool = True
    verify_tls: bool = True

    def __post_init__(self) -> None:
        self.scope.validate()

    def run(self, kind: ScanKind, target: str) -> dict[str, Any]:
        run_id = new_run_id()

        if kind == "recon":
            domain = target.strip().lower().rstrip(".")
            in_scope = self.scope.is_in_scope(domain)
            self.audit.log(
                run_id=run_id,
                actor=self.actor,
                action="offsec.recon",
                target=domain,
                mode=self.scope.mode,
                in_scope=in_scope,
                safe_mode=self.safe_mode,
                meta={"project": self.scope.project},
            )
            if not in_scope:
                raise PermissionError("Target is out of scope.")
            return {
                "run_id": run_id,
                "kind": kind,
                "target": domain,
                "mode": self.scope.mode,
                "results": {
                    "subdomains": recon_mod.subdomain_enum(domain),
                    "dns": recon_mod.dns_analysis(domain),
                    "whois": recon_mod.whois_lookup(domain),
                },
            }

        if kind in ("web", "api"):
            url = _norm_url(target)
            host = _host_from_url(url)
            in_scope = self.scope.is_in_scope(host)
            self.audit.log(
                run_id=run_id,
                actor=self.actor,
                action=f"offsec.{kind}",
                target=url,
                mode=self.scope.mode,
                in_scope=in_scope,
                safe_mode=self.safe_mode,
                meta={"host": host, "project": self.scope.project},
            )
            if not in_scope:
                raise PermissionError("Target host is out of scope.")

            if kind == "web":
                cfg = web_mod.WebTestConfig(verify_tls=self.verify_tls)
                checks: list[dict[str, Any]] = []
                checks.extend(web_mod.security_headers_check(url, cfg=cfg))
                checks.extend(web_mod.sqli_detection_safe(url, cfg=cfg))
                checks.extend(web_mod.xss_detection_safe(url, cfg=cfg))
                checks.extend(web_mod.dir_bruteforce_safe(url, cfg=cfg))
                return {"run_id": run_id, "kind": kind, "target": url, "mode": self.scope.mode, "checks": checks}

            cfg2 = api_mod.ApiTestConfig(verify_tls=self.verify_tls)
            checks2: list[dict[str, Any]] = []
            checks2.extend(api_mod.endpoint_discovery(url, cfg=cfg2))
            checks2.extend(api_mod.auth_flaws_signal(url, cfg=cfg2))
            checks2.extend(api_mod.rate_limit_probe(url, cfg=cfg2))
            return {"run_id": run_id, "kind": kind, "target": url, "mode": self.scope.mode, "checks": checks2}

        raise ValueError(f"Unknown scan kind: {kind}")

