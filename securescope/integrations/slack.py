from __future__ import annotations

import os
from typing import Any

import requests


def send_slack_alert(payload: dict[str, Any], webhook_url: str | None = None) -> tuple[bool, str]:
    """Send a Slack webhook message."""
    hook = webhook_url or os.environ.get("SECURESCOPE_SLACK_WEBHOOK", "")
    if not hook:
        return False, "Slack webhook is not configured"
    text = (
        f"*SecureScope LLM Alert*\n"
        f"Model: {payload.get('model_name', 'unknown')}\n"
        f"Severity: {payload.get('severity', 'unknown')}\n"
        f"Score: {payload.get('security_score', 'n/a')}/100\n"
        f"Summary: {payload.get('summary', 'No summary')}\n"
        f"Report: {payload.get('report_url', '-')}"
    )
    try:
        r = requests.post(hook, json={"text": text}, timeout=8)
        if r.status_code >= 400:
            return False, f"Slack API error {r.status_code}: {r.text[:200]}"
        return True, "sent"
    except Exception as exc:
        return False, str(exc)

