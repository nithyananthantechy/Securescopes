from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

import yaml
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from securescope.core.reporter import Reporter
from securescope.offsec.audit import AuditLogger
from securescope.offsec.engine import OffsecEngine
from securescope.offsec.scope import Scope


class ScopeModel(BaseModel):
    mode: Literal["ctf", "business"]
    ack: str
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    expires_utc: datetime | None = None
    project: str | None = None
    notes: str | None = None

    def to_scope(self) -> Scope:
        return Scope(
            mode=self.mode,
            ack=self.ack,
            allowed_hosts=tuple(self.allowed_hosts),
            allowed_domains=tuple(self.allowed_domains),
            allowed_cidrs=tuple(self.allowed_cidrs),
            expires_utc=self.expires_utc,
            project=self.project,
            notes=self.notes,
        )


class ScanRequest(BaseModel):
    scope: ScopeModel
    kind: Literal["recon", "web", "api"]
    target: str
    actor: str = "api"


app = FastAPI(
    title="SecureScope API (Ethical OffSec)",
    version="0.1.0",
    description="Scope-gated, safe-by-default security assessments for CTF and authorized business engagements.",
)


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"ok": True, "ts_utc": datetime.now(timezone.utc).isoformat()}


@app.post("/v1/offsec/scan")
def offsec_scan(req: ScanRequest) -> dict[str, Any]:
    try:
        scope = req.scope.to_scope()
        audit = AuditLogger()
        engine = OffsecEngine(scope=scope, audit=audit, actor=req.actor, safe_mode=True, verify_tls=True)
        res = engine.run(req.kind, req.target)
        return {"ok": True, "data": res}
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")


@app.post("/v1/offsec/report/html")
def offsec_report_html(req: ScanRequest) -> dict[str, Any]:
    """
    Generates an HTML report from the scan output.
    MVP uses your existing `Reporter` format (checks table + score).
    """
    data = offsec_scan(req)
    payload = data["data"]

    checks = payload.get("checks") or []
    # simple score: percent PASS-like checks
    passed = sum(1 for c in checks if c.get("status") == "PASS")
    score = int((passed / max(1, len(checks))) * 100)
    report_input = {"checks": checks, "score": score}

    html = Reporter().generate(report_input, org=req.scope.project or "SecureScope")
    return {"ok": True, "html": html, "score": score, "run_id": payload.get("run_id")}

