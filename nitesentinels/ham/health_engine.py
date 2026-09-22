"""
HAM Asset Health Engine
=======================
Evaluates the health of a hardware asset from structured asset data
(from HAMStore) and optionally from linked security findings.

Health States:
  HEALTHY   — No issues detected; all monitored systems nominal
  WARNING   — One or more soft issues (warranty near expiry, minor patch gap, etc.)
  CRITICAL  — Hard issues (end-of-life, critical vulns, offline, encryption missing)
  OFFLINE   — Agent-enrolled asset with no recent check-in
  UNKNOWN   — Not enough data to evaluate

Scoring methodology (0–100, higher = healthier):
  Base score: 100
  Deductions applied per factor (see DEDUCTIONS below).
  Final health state is derived from the final score bucket.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any


# Points deducted per negative finding
DEDUCTIONS: dict[str, int] = {
    "no_agent_checkin_ever":      5,   # No agent data at all
    "agent_offline_30d":         30,   # Agent enrolled but not seen in 30 days
    "agent_offline_7d":          10,   # Enrolled but not seen in 7 days
    "critical_vulns_any":        25,   # Any unresolved critical CVEs
    "high_vulns_3plus":          15,   # 3+ high vulns
    "high_vulns_any":             8,   # 1-2 high vulns
    "no_antivirus":              15,   # antivirus_status indicates not running
    "antivirus_outdated":        10,   # antivirus present but outdated
    "encryption_missing":        20,   # disk encryption not enabled
    "firewall_disabled":         15,   # host firewall disabled
    "patch_missing":             20,   # patch_level indicates missing critical patches
    "warranty_expired":           5,   # warranty has lapsed
    "eol_reached":               20,   # device is at or past EOL date
    "eol_90d":                   10,   # within 90 days of EOL
    "lifecycle_missing":         15,   # lifecycle_status is 'missing' or 'stolen'
    "lifecycle_maintenance":      5,   # under maintenance
}


def evaluate_asset_health(asset: dict[str, Any], findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Convenience helper to evaluate asset health."""
    return AssetHealthEngine().evaluate(asset, findings)


class AssetHealthEngine:
    """Compute health state and score for a single hardware asset."""

    def evaluate(
        self,
        asset: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Return a health assessment dict for the given asset.

        Args:
            asset:    Asset dict from HAMStore.get_asset().
            findings: Optional list of linked security findings (from stored_scan_results).

        Returns:
            {
                "health_status":  "healthy" | "warning" | "critical" | "offline" | "unknown",
                "health_score":   int (0–100),
                "issues":         [{"factor": str, "severity": str, "message": str}],
                "evaluated_at":   ISO timestamp,
            }
        """
        score  = 100
        issues: list[dict[str, str]] = []
        now    = datetime.utcnow()

        def deduct(key: str, sev: str, msg: str) -> None:
            nonlocal score
            pts = DEDUCTIONS.get(key, 0)
            score -= pts
            issues.append({"factor": key, "severity": sev, "message": msg, "points": str(pts)})

        # ------------------------------------------------------------------
        # Lifecycle hard-stop
        lc = (asset.get("lifecycle_status") or "").lower()
        if lc in ("missing", "stolen"):
            deduct("lifecycle_missing", "critical", f"Asset lifecycle is '{lc}'")
        if lc == "maintenance":
            deduct("lifecycle_maintenance", "warning", "Asset is under maintenance")

        # ------------------------------------------------------------------
        # EOL / warranty
        eol_str = asset.get("eol_date")
        if eol_str:
            try:
                eol = datetime.strptime(eol_str[:10], "%Y-%m-%d")
                if eol <= now:
                    deduct("eol_reached", "critical", f"End-of-life date reached ({eol_str[:10]})")
                elif eol <= now + timedelta(days=90):
                    deduct("eol_90d", "warning", f"EOL in <90 days ({eol_str[:10]})")
            except ValueError:
                pass

        warranty_str = asset.get("warranty_end")
        if warranty_str:
            try:
                wexp = datetime.strptime(warranty_str[:10], "%Y-%m-%d")
                if wexp < now:
                    deduct("warranty_expired", "warning", f"Warranty expired ({warranty_str[:10]})")
            except ValueError:
                pass

        # ------------------------------------------------------------------
        # Agent / connectivity
        agent_id    = asset.get("agent_id")
        last_checkin = asset.get("last_agent_checkin")
        if agent_id:
            if not last_checkin:
                deduct("no_agent_checkin_ever", "warning", "Agent enrolled but has never checked in")
            else:
                try:
                    lc_dt = datetime.fromisoformat(last_checkin)
                    delta  = (now - lc_dt).total_seconds() / 3600  # hours
                    if delta > 30 * 24:
                        deduct("agent_offline_30d", "critical", f"No check-in for {int(delta/24)} days")
                    elif delta > 7 * 24:
                        deduct("agent_offline_7d", "warning", f"No check-in for {int(delta/24)} days")
                except ValueError:
                    pass

        # ------------------------------------------------------------------
        # Security posture from agent telemetry
        av = (asset.get("antivirus_status") or "").lower()
        if av in ("not_installed", "not_running", "disabled", "unknown") and av:
            if av == "unknown":
                pass   # no deduction — unknown data
            else:
                deduct("no_antivirus", "critical", f"Antivirus is {av}")
        elif av in ("outdated",):
            deduct("antivirus_outdated", "warning", "Antivirus definitions are outdated")

        enc = (asset.get("encryption_status") or "").lower()
        if enc in ("not_enabled", "disabled", "off"):
            deduct("encryption_missing", "critical", "Disk encryption is not enabled")

        fw = (asset.get("firewall_status") or "").lower()
        if fw in ("disabled", "off", "not_running"):
            deduct("firewall_disabled", "critical", "Host firewall is disabled")

        patch = (asset.get("patch_level") or "").lower()
        if patch in ("critical_missing", "out_of_date"):
            deduct("patch_missing", "critical", "Critical patches are missing")

        # ------------------------------------------------------------------
        # Vulnerability correlation
        crit_v = int(asset.get("critical_vulns") or 0)
        high_v = int(asset.get("high_vulns") or 0)
        if crit_v > 0:
            deduct("critical_vulns_any", "critical", f"{crit_v} unresolved critical vulnerability(ies)")
        if high_v >= 3:
            deduct("high_vulns_3plus", "high", f"{high_v} high-severity vulnerabilities")
        elif high_v > 0:
            deduct("high_vulns_any", "high", f"{high_v} high-severity vulnerability(ies)")

        # If live findings were passed in, also count them
        if findings:
            extra_crit = sum(1 for f in findings if (f.get("severity") or "").lower() == "critical" and
                             (f.get("status") or "").lower() not in ("closed", "remediated"))
            extra_high = sum(1 for f in findings if (f.get("severity") or "").lower() == "high" and
                             (f.get("status") or "").lower() not in ("closed", "remediated"))
            if extra_crit > crit_v:
                adj = extra_crit - crit_v
                score -= adj * 5
            if extra_high > high_v:
                adj = extra_high - high_v
                score -= adj * 3

        # ------------------------------------------------------------------
        # Floor at 0
        score = max(0, score)

        # ------------------------------------------------------------------
        # Derive health state
        if lc in ("missing", "stolen"):
            health_status = "offline"
        elif score >= 80:
            health_status = "healthy"
        elif score >= 55:
            health_status = "warning"
        elif score >= 30:
            health_status = "critical"
        elif score >= 0:
            health_status = "critical"
        else:
            health_status = "unknown"

        # Offline override: agent enrolled but silent for 30+ days
        for issue in issues:
            if issue["factor"] == "agent_offline_30d":
                health_status = "offline"
                break

        # Not enough data
        if not agent_id and not asset.get("os_name") and score == 100:
            health_status = "unknown"
            score = 0

        return {
            "health_status":  health_status,
            "health_score":   score,
            "issues":         issues,
            "evaluated_at":   datetime.utcnow().isoformat(),
        }
