from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Iterable, Literal
import re


Mode = Literal["ctf", "business"]


_ACK = "I_HAVE_AUTHORIZATION_AND_WILL_STAY_IN_SCOPE"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _norm_host(s: str) -> str:
    return s.strip().lower().rstrip(".")


def _is_ip(s: str) -> bool:
    try:
        ip_address(s)
        return True
    except Exception:
        return False


def _hostname_like(s: str) -> bool:
    s = _norm_host(s)
    if not s or len(s) > 253:
        return False
    # conservative: labels 1..63, alnum + hyphen (not leading/trailing)
    label = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
    return re.fullmatch(rf"{label}(\.{label})*", s) is not None


@dataclass(frozen=True)
class Scope:
    """
    Enforces legal/ethical constraints.

    This is intentionally strict: it refuses to run unless explicit authorization
    is provided and the target is within the declared allowlist.
    """

    mode: Mode
    ack: str
    allowed_hosts: tuple[str, ...] = field(default_factory=tuple)
    allowed_domains: tuple[str, ...] = field(default_factory=tuple)  # suffix match
    allowed_cidrs: tuple[str, ...] = field(default_factory=tuple)
    expires_utc: datetime | None = None
    project: str | None = None  # business: client/project identifier
    notes: str | None = None

    def validate(self) -> None:
        if self.ack != _ACK:
            raise ValueError(
                f"Scope ack missing/invalid. Set ack to exactly {_ACK!r}."
            )
        if self.expires_utc and _utcnow() > self.expires_utc:
            raise ValueError("Scope is expired.")
        if self.mode == "business" and not (self.project and self.project.strip()):
            raise ValueError("Business mode requires a non-empty project identifier.")

        if not (self.allowed_hosts or self.allowed_domains or self.allowed_cidrs):
            raise ValueError("Scope allowlist is empty.")

        for h in self.allowed_hosts:
            h2 = _norm_host(h)
            if not (_is_ip(h2) or _hostname_like(h2)):
                raise ValueError(f"Invalid allowed_hosts entry: {h!r}")

        for d in self.allowed_domains:
            d2 = _norm_host(d)
            if not _hostname_like(d2):
                raise ValueError(f"Invalid allowed_domains entry: {d!r}")

        for c in self.allowed_cidrs:
            try:
                ip_network(c, strict=False)
            except Exception as e:
                raise ValueError(f"Invalid allowed_cidrs entry: {c!r} ({e})") from e

    def is_in_scope(self, target: str) -> bool:
        t = _norm_host(target)
        if not t:
            return False

        if t in {_norm_host(x) for x in self.allowed_hosts}:
            return True

        if _is_ip(t):
            ip = ip_address(t)
            for c in self.allowed_cidrs:
                if ip in ip_network(c, strict=False):
                    return True
            return False

        # hostname: allow exact domain or subdomain of allowed_domains
        for d in self.allowed_domains:
            d2 = _norm_host(d)
            if t == d2 or t.endswith("." + d2):
                return True
        return False


def default_ack() -> str:
    return _ACK

