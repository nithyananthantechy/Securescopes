from __future__ import annotations

import io
from datetime import datetime
from typing import Any


class LLMReportGenerator:
    """Build polished HTML and PDF outputs for LLM scan reports."""

    def build_html(self, scan: dict[str, Any]) -> str:
        report = scan.get("report_json") or {}
        score = int(scan.get("security_score", 0))
        vulnerabilities = report.get("vulnerabilities", [])
        critical = sum(1 for v in vulnerabilities if v.get("severity") == "critical")
        high = sum(1 for v in vulnerabilities if v.get("severity") == "high")
        medium = sum(1 for v in vulnerabilities if v.get("severity") == "medium")
        low = sum(1 for v in vulnerabilities if v.get("severity") == "low")
        score_color = "#16a34a" if score >= 80 else "#ea580c" if score >= 50 else "#dc2626"

        rows = "".join(
            (
                "<tr>"
                f"<td>{idx}</td><td>{v.get('type','unknown')}</td><td>{v.get('severity','low').upper()}</td>"
                f"<td>{v.get('description','')}</td><td>{v.get('remediation','')}</td>"
                "</tr>"
            )
            for idx, v in enumerate(vulnerabilities, start=1)
        ) or "<tr><td colspan='5'>No vulnerabilities found.</td></tr>"

        compliance = report.get("compliance_status", {})
        compliance_html = "".join(
            f"<li><b>{name}</b>: {(data or {}).get('status', 'partial')}</li>"
            for name, data in compliance.items()
        ) or "<li>No mapping available</li>"

        return f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>NiteSentinel LLM Security Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; background:#071126; margin:0; color:#e7edf8; }}
    .top {{ background:#081b34; color:#f8fbff; padding:18px 24px; display:flex; align-items:center; gap:18px; box-shadow: inset 0 -1px 0 rgba(255,255,255,0.08); }}
    .top img {{ height:40px; filter: drop-shadow(0 0 25px rgba(0,212,255,0.25)); }}
    .container {{ padding:24px; }}
    .card {{ background:rgba(10,18,34,0.95); border:1px solid rgba(0,212,255,0.16); border-radius:16px; padding:18px; margin-bottom:18px; color:#e7edf8; }}
    .score {{ font-size:44px; font-weight:700; color:{score_color}; }}
    .grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-top:12px; }}
    .chip {{ border-radius:12px; padding:12px 10px; text-align:center; font-weight:700; color:#0f172a; }}
    .critical {{ background:#fee2e2; color:#991b1b; }}
    .high {{ background:#ffedd5; color:#9a3412; }}
    .medium {{ background:#fef9c3; color:#78350f; }}
    .low {{ background:#dcfce7; color:#14532d; }}
    .title-text {{ margin:0; font-weight:700; color:#e7edf8; }}
    .subtitle-text {{ margin:4px 0 0 0; opacity:.9; }}
    table {{ width:100%; border-collapse:collapse; color:#e7edf8; }}
    th, td {{ border:1px solid rgba(255,255,255,0.08); padding:10px; text-align:left; font-size:13px; }}
    th {{ background:rgba(0,212,255,0.08); color:#cbd5e1; }}
    tr:nth-child(even) {{ background:rgba(255,255,255,0.04); }}
    tr:hover {{ background:rgba(0,212,255,0.08); }}
    .summary-text {{ color:#cbd5e1; margin:12px 0 0; }}
  </style>
</head>
<body>
  <div class="top">
    <img src="/static/img/nitesentinel-logo.png" alt="NITECHSPARK logo" />
    <div>
      <div style="font-size:20px;font-weight:700;">NITECHSPARK NiteSentinel</div>
      <div style="font-size:12px;opacity:.9;">LLM & Chatbot Security Audit Report</div>
    </div>
  </div>
  <div class="container">
    <div class="card">
      <h2 style="margin:0 0 8px 0;">Executive Summary</h2>
      <div>Scan ID: {scan.get("scan_id")}</div>
      <div>Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</div>
      <div class="score">{score}/100</div>
      <div>Risk scoring: 80-100 Low Risk, 50-79 Medium Risk, below 50 High Risk.</div>
      <div class="grid">
        <div class="chip critical">Critical: {critical}</div>
        <div class="chip high">High: {high}</div>
        <div class="chip medium">Medium: {medium}</div>
        <div class="chip low">Low: {low}</div>
      </div>
    </div>
    <div class="card">
      <h3 style="margin-top:0;">Remediation Roadmap</h3>
      <ul>
        <li><b>Immediate (0-7 days):</b> Critical auth, injection, and data leakage issues.</li>
        <li><b>1 month:</b> Hardening tasks, CORS/rate limiting alignment, monitoring setup.</li>
        <li><b>3 months:</b> Process controls, validation expansion, regression scanning cadence.</li>
        <li><b>6 months:</b> Governance maturity, audit evidence automation, policy reviews.</li>
      </ul>
    </div>
    <div class="card">
      <h3 style="margin-top:0;">Detailed Findings</h3>
      <table>
        <thead><tr><th>#</th><th>Type</th><th>Severity</th><th>Description</th><th>Remediation</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
    <div class="card">
      <h3 style="margin-top:0;">Compliance Checklist</h3>
      <ul>{compliance_html}</ul>
    </div>
  </div>
</body>
</html>
"""

    def build_pdf(self, scan: dict[str, Any]) -> bytes:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        report = scan.get("report_json") or {}
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        elems = []
        elems.append(Paragraph("<b>NITECHSPARK NiteSentinel - LLM Security Report</b>", styles["Title"]))
        elems.append(Spacer(1, 12))
        elems.append(Paragraph(f"Scan ID: {scan.get('scan_id')}", styles["Normal"]))
        elems.append(Paragraph(f"Security Score: {scan.get('security_score', 0)}/100", styles["Normal"]))
        elems.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["Normal"]))
        elems.append(Spacer(1, 12))
        elems.append(Paragraph("<b>Executive Summary</b>", styles["Heading2"]))
        elems.append(
            Paragraph(
                "This report summarizes LLM/chatbot risks with remediation priorities and compliance status.",
                styles["Normal"],
            )
        )
        elems.append(Spacer(1, 8))
        vulns = report.get("vulnerabilities", [])
        critical = sum(1 for v in vulns if v.get("severity") == "critical")
        high = sum(1 for v in vulns if v.get("severity") == "high")
        medium = sum(1 for v in vulns if v.get("severity") == "medium")
        low = sum(1 for v in vulns if v.get("severity") == "low")
        summary_tbl = Table(
            [["Critical", "High", "Medium", "Low"], [str(critical), str(high), str(medium), str(low)]],
            colWidths=[45 * mm, 45 * mm, 45 * mm, 45 * mm],
        )
        summary_tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1730")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#fee2e2")),
                    ("BACKGROUND", (1, 1), (1, 1), colors.HexColor("#ffedd5")),
                    ("BACKGROUND", (2, 1), (2, 1), colors.HexColor("#fef9c3")),
                    ("BACKGROUND", (3, 1), (3, 1), colors.HexColor("#dcfce7")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ]
            )
        )
        elems.append(summary_tbl)
        elems.append(Spacer(1, 10))
        elems.append(Paragraph("<b>Vulnerabilities</b>", styles["Heading2"]))
        if not vulns:
            elems.append(Paragraph("No vulnerabilities found.", styles["Normal"]))
        else:
            data = [["#", "Type", "Severity", "Description", "Remediation"]]
            for idx, v in enumerate(vulns, start=1):
                data.append(
                    [
                        str(idx),
                        str(v.get("type", "unknown")),
                        str(v.get("severity", "low")).upper(),
                        str(v.get("description", ""))[:160],
                        str(v.get("remediation", ""))[:180],
                    ]
                )
            vuln_table = Table(data, repeatRows=1, colWidths=[10 * mm, 30 * mm, 22 * mm, 58 * mm, 62 * mm])
            vuln_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            elems.append(vuln_table)
        elems.append(Spacer(1, 10))
        elems.append(Paragraph("<b>Remediation Timeline</b>", styles["Heading2"]))
        elems.append(Paragraph("Immediate (0-7 days): Critical issues", styles["Normal"]))
        elems.append(Paragraph("1 month: High and policy-level fixes", styles["Normal"]))
        elems.append(Paragraph("3 months: Monitoring and validation expansion", styles["Normal"]))
        elems.append(Paragraph("6 months: Governance optimization", styles["Normal"]))
        doc.build(elems)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes
