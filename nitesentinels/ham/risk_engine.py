"""
HAM Asset Risk Engine
=====================
Computes a composite risk score (0–100) and risk level for a hardware asset.
Higher score = higher risk.

Risk Factors (weighted):
  - Vulnerability exposure  (30 pts max)
  - Security posture gaps   (25 pts max)
  - Network exposure        (20 pts max)
  - Lifecycle / age risk    (15 pts max)
  - Compliance factors      (10 pts max)

Risk Levels:
  LOW      0–24
  MEDIUM  25–49
  HIGH    50–74
  CRITICAL 75+
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any


def compute_asset_risk_score(asset: dict[str, Any], findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Convenience helper to compute asset risk score."""
    return AssetRiskEngine().evaluate(asset, findings)


class AssetRiskEngine:
    """Compute a risk score and risk level for a single hardware asset."""

    # Weights by factor group
    _WEIGHTS = {
        "vuln":       30,
        "security":   25,
        "network":    20,
        "lifecycle":  15,
        "compliance": 10,
    }

    def evaluate(
        self,
        asset: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Return risk assessment dict.

        Returns:
            {
                "risk_level":  "low" | "medium" | "high" | "critical",
                "risk_score":  int (0–100),
                "factors":     [{"group": str, "factor": str, "contribution": int, "reason": str}],
                "evaluated_at": ISO timestamp,
            }
        """
        factors: list[dict[str, Any]] = []
        total_score = 0

        def add(group: str, factor: str, contribution: int, reason: str) -> None:
            nonlocal total_score
            total_score += contribution
            factors.append({
                "group":        group,
                "factor":       factor,
                "contribution": contribution,
                "reason":       reason,
            })

        now = datetime.utcnow()

        # ----------------------------------------------------------------
        # 1. Vulnerability exposure (max 30)
        crit_v = int(asset.get("critical_vulns") or 0)
        high_v = int(asset.get("high_vulns") or 0)

        # Also count from live findings if provided
        if findings:
            open_findings = [
                f for f in findings
                if (f.get("status") or "").lower() not in ("closed", "remediated")
            ]
            crit_v = max(crit_v, sum(1 for f in open_findings if (f.get("severity") or "").lower() == "critical"))
            high_v = max(high_v, sum(1 for f in open_findings if (f.get("severity") or "").lower() == "high"))

        if crit_v >= 3:
            add("vuln", "critical_vulns_many", 30, f"{crit_v} critical vulnerabilities")
        elif crit_v > 0:
            add("vuln", "critical_vulns", 20, f"{crit_v} critical vulnerability(ies)")
        elif high_v >= 5:
            add("vuln", "high_vulns_many", 18, f"{high_v} high-severity vulnerabilities")
        elif high_v > 0:
            add("vuln", "high_vulns", min(12, high_v * 3), f"{high_v} high-severity vulnerability(ies)")

        # ----------------------------------------------------------------
        # 2. Security posture (max 25)
        enc = (asset.get("encryption_status") or "").lower()
        if enc in ("not_enabled", "disabled", "off"):
            add("security", "no_encryption", 10, "Disk encryption not enabled")

        fw = (asset.get("firewall_status") or "").lower()
        if fw in ("disabled", "off", "not_running"):
            add("security", "no_firewall", 8, "Host firewall disabled")

        av = (asset.get("antivirus_status") or "").lower()
        if av in ("not_installed", "not_running", "disabled"):
            add("security", "no_antivirus", 7, f"Antivirus {av}")
        elif av == "outdated":
            add("security", "antivirus_outdated", 4, "Antivirus definitions outdated")

        patch = (asset.get("patch_level") or "").lower()
        if patch in ("critical_missing",):
            add("security", "missing_critical_patches", 10, "Critical OS patches missing")
        elif patch in ("out_of_date",):
            add("security", "patches_outdated", 5, "Patches are out of date")

        # Cap security at 25
        sec_total = sum(f["contribution"] for f in factors if f["group"] == "security")
        if sec_total > 25:
            # Scale down proportionally
            for f in factors:
                if f["group"] == "security":
                    f["contribution"] = int(f["contribution"] * 25 / sec_total)
                    f["contribution_adjusted"] = True
            # Recompute total_score
            total_score = sum(f["contribution"] for f in factors)

        # ----------------------------------------------------------------
        # 3. Network exposure (max 20)
        zone = (asset.get("network_zone") or "").lower()
        if zone in ("dmz", "public", "internet"):
            add("network", "internet_facing", 15, f"Asset is in {zone} zone")
        elif zone in ("guest",):
            add("network", "guest_network", 8, "Asset on guest network")

        # Open ports from linked scan
        if findings:
            exposed = [f for f in findings if "port" in (f.get("category") or "").lower() and
                       (f.get("scan_status") or "").upper() == "FAIL"]
            if len(exposed) >= 3:
                add("network", "many_exposed_ports", 12, f"{len(exposed)} exposed port findings")
            elif exposed:
                add("network", "exposed_ports", 6, f"{len(exposed)} exposed port finding(s)")

        # ----------------------------------------------------------------
        # 4. Lifecycle / age risk (max 15)
        lc = (asset.get("lifecycle_status") or "").lower()
        if lc in ("missing", "stolen"):
            add("lifecycle", "missing_asset", 15, f"Asset status is {lc}")
        elif lc == "retired":
            add("lifecycle", "retired_asset", 8, "Asset is retired but may still be active")

        eol_str = asset.get("eol_date")
        if eol_str:
            try:
                eol = datetime.strptime(eol_str[:10], "%Y-%m-%d")
                if eol <= now:
                    add("lifecycle", "eol_reached", 12, f"EOL reached {eol_str[:10]}")
                elif eol <= now + timedelta(days=90):
                    add("lifecycle", "eol_imminent", 6, f"EOL in <90 days ({eol_str[:10]})")
            except ValueError:
                pass

        # Unassigned active asset
        if lc == "deployed" and not (asset.get("assigned_to") or "").strip():
            add("lifecycle", "no_owner", 5, "Active asset has no owner assigned")

        # ----------------------------------------------------------------
        # 5. Compliance factors (max 10)
        warranty_str = asset.get("warranty_end")
        if warranty_str:
            try:
                wexp = datetime.strptime(warranty_str[:10], "%Y-%m-%d")
                if wexp < now:
                    add("compliance", "warranty_expired", 5, f"Warranty expired {warranty_str[:10]}")
            except ValueError:
                pass

        if not asset.get("asset_tag"):
            add("compliance", "no_asset_tag", 3, "No asset tag assigned")
        if not asset.get("serial_number"):
            add("compliance", "no_serial", 2, "No serial number recorded")

        # ----------------------------------------------------------------
        # Final score (capped at 100)
        total_score = min(100, total_score)

        if total_score >= 75:
            risk_level = "critical"
        elif total_score >= 50:
            risk_level = "high"
        elif total_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "risk_level":    risk_level,
            "risk_score":    total_score,
            "factors":       factors,
            "evaluated_at":  datetime.utcnow().isoformat(),
        }
