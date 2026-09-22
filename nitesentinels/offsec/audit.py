from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class AuditEvent:
    ts_utc: str
    run_id: str
    actor: str
    action: str
    target: str
    mode: str
    in_scope: bool
    safe_mode: bool
    meta: dict[str, Any]


def new_run_id() -> str:
    return uuid.uuid4().hex


class AuditLogger:
    def __init__(self, path: str = "audit/audit.jsonl"):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def log(
        self,
        *,
        run_id: str,
        actor: str,
        action: str,
        target: str,
        mode: str,
        in_scope: bool,
        safe_mode: bool,
        meta: dict[str, Any] | None = None,
    ) -> None:
        ev = AuditEvent(
            ts_utc=_utcnow_iso(),
            run_id=run_id,
            actor=actor,
            action=action,
            target=target,
            mode=mode,
            in_scope=in_scope,
            safe_mode=safe_mode,
            meta=meta or {},
        )
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")

