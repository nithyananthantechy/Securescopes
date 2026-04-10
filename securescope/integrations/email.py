from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage


def send_email_report(
    recipients: list[str],
    subject: str,
    body: str,
    html: str | None = None,
) -> tuple[bool, str]:
    """Send an email using SMTP settings from environment."""
    host = os.environ.get("SECURESCOPE_SMTP_HOST", "")
    port = int(os.environ.get("SECURESCOPE_SMTP_PORT", "587"))
    user = os.environ.get("SECURESCOPE_SMTP_USER", "")
    password = os.environ.get("SECURESCOPE_SMTP_PASSWORD", "")
    sender = os.environ.get("SECURESCOPE_SMTP_FROM", user or "securescope@localhost")
    if not host:
        return False, "SMTP host is not configured"
    if not recipients:
        return False, "No recipients provided"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")

    try:
        with smtplib.SMTP(host, port, timeout=12) as smtp:
            smtp.starttls()
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)
        return True, "sent"
    except Exception as exc:
        return False, str(exc)

