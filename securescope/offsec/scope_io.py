from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from securescope.offsec.scope import Scope


def _parse_dt(v: Any) -> datetime | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, str):
        # Accept ISO 8601; assume UTC if no tzinfo.
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    raise ValueError("expires_utc must be ISO datetime string")


def load_scope_yaml(path: str | Path) -> Scope:
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    scope = Scope(
        mode=data.get("mode"),
        ack=data.get("ack"),
        allowed_hosts=tuple(data.get("allowed_hosts") or ()),
        allowed_domains=tuple(data.get("allowed_domains") or ()),
        allowed_cidrs=tuple(data.get("allowed_cidrs") or ()),
        expires_utc=_parse_dt(data.get("expires_utc")),
        project=data.get("project"),
        notes=data.get("notes"),
    )
    scope.validate()
    return scope

