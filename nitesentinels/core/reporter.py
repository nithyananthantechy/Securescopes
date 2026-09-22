import platform
import socket
from datetime import datetime

def get_report_os():
    """Consistent OS detection for reports."""
    if platform.system() == 'Windows':
        try:
            build = int(platform.version().split('.')[-1])
            return 'Windows 11' if build >= 22000 else 'Windows 10'
        except Exception:
            return 'Windows'
    return platform.platform()

class Reporter:
    def __init__(self, org_name="NiTechSpark"):
        self.org_name = org_name

    def generate_html(self, results, org="NiTechSpark"):
        """Generates a proper 4-page enterprise HTML report."""
        checks = results.get('checks', [])
        score = results.get('score', 0)
        
        # Enhanced defaults for local scans if missing from results
        hostname = results.get('hostname')
        if not hostname:
            hostname = socket.gethostname()
            
        os_name = results.get('os', get_report_os())
        is_windows = "Windows" in os_name
        
        ip_address = results.get('ip_address')
        if not ip_address:
            try:
                ip_address = socket.gethostbyname(hostname)
            except Exception:
                ip_address = '127.0.0.1'
                
        kernel = results.get('kernel', platform.version())
        timestamp = datetime.now().strftime('%d %b %Y, %H:%M:%S')
        
        # Determine score color
        score_color = "#ef4444" # Red
        if score >= 86: score_color = "#22c55e" # Green
        elif score >= 71: score_color = "#3b82f6" # Blue
        elif score >= 41: score_color = "#f97316" # Orange

        passed = sum(1 for c in checks if c['status'] == 'PASS')
        failed = sum(1 for c in checks if c['status'] == 'FAIL')
        warnings = sum(1 for c in checks if c['status'] == 'WARNING')

        # Page 2: Executive Summary - Top critical issues (FAIL)
        critical_items = [c for c in checks if c.get("status") == "FAIL" and c.get("severity") in ["Critical", "High"]][:5]
        top_issues_html = "".join(
            f"<li><b>{c.get('check')}</b>: {c.get('details')}</li>" for c in critical_items
        ) or "<li>No critical security issues detected.</li>"

        # Page 3: Technical Findings - Grouped by Category
        categories = {}
        for c in checks:
            cat = c.get('category', 'General')
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(c)

        findings_html = ""
        for cat, cat_checks in categories.items():
            findings_html += f"<h3 style='color: #1a237e; margin-top: 25px;'>{cat}</h3>"
            findings_html += """
            <table style='width: 100%; border-collapse: collapse; margin-bottom: 20px;'>
                <thead>
                    <tr style='background: #f8fafc; color: #64748b; text-transform: uppercase; font-size: 12px;'>
                        <th style='padding: 12px; border-bottom: 2px solid #eee; text-align: left;'>Check</th>
                        <th style='padding: 12px; border-bottom: 2px solid #eee; text-align: left;'>Status</th>
                        <th style='padding: 12px; border-bottom: 2px solid #eee; text-align: left;'>Severity</th>
                        <th style='padding: 12px; border-bottom: 2px solid #eee; text-align: left;'>Details</th>
                    </tr>
                </thead>
                <tbody>
            """
            for c in cat_checks:
                status = c.get('status', 'UNKNOWN')
                bg_color = "#ffffff"
                if status == 'PASS': bg_color = "#dcfce7"
                elif status == 'FAIL': bg_color = "#fee2e2"
                elif status == 'WARNING': bg_color = "#fef3c7"
                
                findings_html += f"""
                    <tr style='background-color: {bg_color};'>
                        <td style='padding: 10px; border-bottom: 1px solid #eee; font-size: 13px; font-weight: 600;'>{c.get('check')}</td>
                        <td style='padding: 10px; border-bottom: 1px solid #eee; font-size: 12px;'>
                            <span style='padding: 3px 8px; border-radius: 4px; font-weight: bold;'>{status}</span>
                        </td>
                        <td style='padding: 10px; border-bottom: 1px solid #eee; font-size: 12px;'>{c.get('severity')}</td>
                        <td style='padding: 10px; border-bottom: 1px solid #eee; font-size: 12px; color: #444;'>{c.get('details')}</td>
                    </tr>
                """
            findings_html += "</tbody></table>"

        # Page 4: Remediation Plan
        remediation_html = ""
        fail_checks = [c for c in checks if c.get('status') == 'FAIL']
        if not fail_checks:
            remediation_html = "<p>No remediation items required. All checks passed.</p>"
        else:
            for c in fail_checks:
                severity = c.get('severity', 'Medium')
                priority = "P1" if severity == "Critical" else ("P2" if severity == "High" else "P3")
                badge_color = "#ef4444" if priority == "P1" else ("#f97316" if priority == "P2" else "#3b82f6")
                
                check_name = c.get('check', '')
                fix_steps = [
                    "1. Access the system configuration settings.",
                    "2. Identify the specific security control mentioned above.",
                    "3. Apply the recommended security hardening parameters.",
                    "4. Restart the relevant services to apply changes.",
                    "5. Re-run the security scan to verify the fix."
                ]
                
                if "Firewall" in check_name:
                    if is_windows:
                        fix_steps = [
                            "1. Open PowerShell as Administrator.",
                            "2. Run: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
                            "3. Verify status: Get-NetFirewallProfile | Select Name, Enabled",
                            "4. Ensure no unauthorized rules exist: Get-NetFirewallRule -Enabled True"
                        ]
                    else:
                        fix_steps = [
                            "1. Install UFW: sudo apt install ufw.",
                            "2. Allow necessary ports (e.g., sudo ufw allow 22/tcp).",
                            "3. Enable the firewall: sudo ufw enable.",
                            "4. Check status: sudo ufw status verbose."
                        ]
                elif "SSH" in check_name or "Root login" in check_name:
                    fix_steps = [
                        "1. Open /etc/ssh/sshd_config with a text editor (e.g., sudo nano).",
                        "2. Set PermitRootLogin to 'no' and PasswordAuthentication to 'no'.",
                        "3. Save the file and exit.",
                        "4. Restart SSH service: sudo systemctl restart ssh.",
                        "5. Verify connection with an SSH key."
                    ]
                elif "SMBv1" in check_name:
                    if is_windows:
                        fix_steps = [
                            "1. Open PowerShell as Administrator.",
                            "2. Run: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
                            "3. Restart the computer when prompted.",
                            "4. Verify: Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
                        ]
                elif "Guest account" in check_name:
                    if is_windows:
                        fix_steps = [
                            "1. Open Command Prompt as Administrator.",
                            "2. Run: net user guest /active:no",
                            "3. Verify in Computer Management -> Local Users and Groups."
                        ]
                
                remediation_html += f"""
                <div style='margin-bottom: 25px; padding: 15px; border: 1px solid #eee; border-radius: 8px; break-inside: avoid;'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;'>
                        <h4 style='margin: 0; color: #1a237e;'>{check_name}</h4>
                        <span style='background: {badge_color}; color: white; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: bold;'>{priority}</span>
                    </div>
                    <p style='font-size: 13px; color: #666; margin: 5px 0;'><b>Issue:</b> {c.get('details')}</p>
                    <div style='background: #f8fafc; padding: 10px; border-radius: 4px;'>
                        <p style='font-size: 13px; margin: 0 0 5px 0; font-weight: bold;'>Fix Instructions:</p>
                        <ul style='font-size: 12px; margin: 0; padding-left: 20px; line-height: 1.6;'>
                            {"".join(f"<li>{step}</li>" for step in fix_steps)}
                        </ul>
                    </div>
                </div>
                """

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NiteSentinel Security Report - {org}</title>
    <style>
        @page {{
            size: A4;
            margin: 0;
        }}
        @media print {{
            body {{ background: white !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
            .page {{ 
                margin: 0 !important; 
                box-shadow: none !important; 
                border: none !important; 
                width: 100% !important;
                height: 100vh !important;
                page-break-after: always !important;
                overflow: hidden;
            }}
            .no-print {{ display: none !important; }}
        }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #081026; color: #e2e8f0; }}
        .page {{ 
            width: 210mm; 
            height: 297mm; 
            padding: 20mm; 
            margin: 10mm auto; 
            background: #091526; 
            box-shadow: 0 0 24px rgba(0,0,0,0.35); 
            box-sizing: border-box;
            position: relative;
            overflow: hidden;
            page-break-after: always;
        }}
        .cover {{ 
            background: linear-gradient(135deg, #020917 0%, #081a32 100%) !important; 
            color: #e8f1ff; 
            display: flex; 
            flex-direction: column; 
            justify-content: center; 
            align-items: center;
            text-align: center;
        }}
        .logo {{ font-size: 48px; font-weight: bold; color: #00d4ff; letter-spacing: 5px; margin-bottom: 10px; }}
        .subtitle {{ font-size: 24px; color: #e0e0e0; margin-bottom: 50px; border-top: 1px solid #00d4ff; padding-top: 10px; }}
        .cover-table {{ width: 80%; border-collapse: collapse; margin-top: 40px; color: white; }}
        .cover-table td {{ padding: 10px; border-bottom: 1px solid #1a2e44; text-align: left; font-size: 14px; }}
        .confidential {{ position: absolute; bottom: 20mm; font-weight: bold; color: #ff4d4d; letter-spacing: 2px; }}
        
        h2 {{ color: #1a237e; border-bottom: 2px solid #1a237e; padding-bottom: 10px; margin-top: 0; }}
        .score-container {{ text-align: center; margin: 20px 0; }}
        .score-circle {{ 
            width: 100px; height: 100px; border-radius: 50%; border: 10px solid {score_color};
            line-height: 100px; font-size: 36px; font-weight: bold; color: {score_color};
            margin: 0 auto;
        }}
        .stats-boxes {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat-box {{ padding: 10px 20px; border-radius: 8px; text-align: center; font-weight: bold; width: 25%; }}
        .stat-fail {{ background: #fee2e2 !important; color: #ef4444; border: 1px solid #fecaca; }}
        .stat-pass {{ background: #dcfce7 !important; color: #22c55e; border: 1px solid #bbf7d0; }}
        .stat-warn {{ background: #fef3c7 !important; color: #f97316; border: 1px solid #fde68a; }}
        
        .info-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        .info-table td {{ padding: 8px; border: 1px solid #eee; font-size: 14px; }}
        .info-label {{ background: #f8fafc !important; font-weight: bold; width: 30%; }}
        
        .footer-box {{ background: #0d1b2a !important; color: white; padding: 15px; border-radius: 8px; margin-top: 20px; text-align: center; position: absolute; bottom: 20mm; width: calc(100% - 40mm); }}
        .footer-box a {{ color: #00d4ff; text-decoration: none; }}
        .print-btn {{ position: fixed; top: 20px; right: 20px; background: #00d4ff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; z-index: 1000; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }}
    </style>
</head>
<body>
    <button class="print-btn no-print" onclick="window.print()">Print / Download PDF</button>

    <!-- PAGE 1: COVER -->
    <div class="page cover">
        <div class="logo">NITECHSPARK</div>
        <div class="subtitle">NiteSentinel Security Assessment Report</div>
        <table class="cover-table">
            <tr><td><b>Target</b></td><td>{hostname}</td></tr>
            <tr><td><b>Operating System</b></td><td>{os_name}</td></tr>
            <tr><td><b>IP Address</b></td><td>{ip_address}</td></tr>
            <tr><td><b>Date Generated</b></td><td>{timestamp}</td></tr>
            <tr><td><b>Prepared By</b></td><td>{org} Security Engine</td></tr>
        </table>
        <div class="confidential">CONFIDENTIAL</div>
    </div>

    <!-- PAGE 2: EXECUTIVE SUMMARY -->
    <div class="page">
        <h2>Executive Summary</h2>
        <div class="score-container">
            <div class="score-circle">{score}</div>
            <p style="font-weight: bold; margin-top: 10px; color: #666;">Security Compliance Score</p>
        </div>
        
        <div class="stats-boxes">
            <div class="stat-box stat-fail">{failed}<br>FAILED</div>
            <div class="stat-box stat-pass">{passed}<br>PASSED</div>
            <div class="stat-box stat-warn">{warnings}<br>WARNINGS</div>
        </div>

        <h3 style="color: #1a237e;">System Information</h3>
        <table class="info-table">
            <tr><td class="info-label">Hostname</td><td>{hostname}</td></tr>
            <tr><td class="info-label">Operating System</td><td>{os_name}</td></tr>
            <tr><td class="info-label">IP Address</td><td>{ip_address}</td></tr>
            <tr><td class="info-label">Kernel Version</td><td>{kernel}</td></tr>
        </table>

        <h3 style="color: #1a237e;">Top Critical Issues</h3>
        <ul style="line-height: 1.8; color: #444; font-size: 14px;">
            {top_issues_html}
        </ul>
    </div>

    <!-- PAGE 3: TECHNICAL FINDINGS -->
    <div class="page">
        <h2>Technical Findings</h2>
        <div style="overflow-y: auto; max-height: 230mm;">
            {findings_html}
        </div>
    </div>

    <!-- PAGE 4: REMEDIATION AND ABOUT -->
    <div class="page">
        <h2>Remediation Plan</h2>
        <div style="overflow-y: auto; max-height: 180mm;">
            {remediation_html}
        </div>

        <div class="footer-box">
            <p style="font-weight: bold; color: #00d4ff; margin-bottom: 5px;">About NITECHSPARK Security Systems</p>
            <p style="font-size: 12px; margin-bottom: 10px;">
                NITECHSPARK provides advanced security automation and hardening solutions for enterprise infrastructure.
            </p>
            <p style="font-size: 12px;">
                Email: <a href="mailto:nitechspark@gmail.com">nitechspark@gmail.com</a> | 
                Phone: +91 6385576354 | 
                Web: <a href="https://nitechspark.vercel.app" target="_blank">nitechspark.vercel.app</a>
            </p>
        </div>
    </div>
</body>
</html>
        """
        return html

    def generate(self, results, org="NiTechSpark"):
        """Main entry point to build the 4-page HTML report."""
        return self.generate_html(results, org=org)

    def generate_pdf(self, scan_results, score, target_info, output_path="report.pdf"):
        # Keep reportlab for CLI if needed
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
        
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        elements.append(Paragraph(f"<b>{self.org_name} NiteSentinel Security Assessment Report</b>", styles['Title']))
        elements.append(Spacer(1, 12))
        meta_data = [[f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"], [f"Target: {target_info.get('os')}"], [f"Security Score: {score}/100"]]
        t = Table(meta_data); elements.append(t); elements.append(Spacer(1, 12))
        elements.append(Paragraph("<b>Executive Summary</b>", styles['Heading2']))
        passed = len([r for r in scan_results if r["status"] == "PASS"])
        failed = len([r for r in scan_results if r["status"] == "FAIL"])
        risk = "Critical" if score < 40 else "High" if score < 70 else "Medium" if score < 85 else "Low"
        elements.append(Paragraph(f"Found {failed} failures and {passed} passes. Risk: <b>{risk}</b> Score: <b>{score}/100</b>.", styles['Normal']))
        elements.append(Spacer(1, 12))
        data = [['Category', 'Check', 'Status', 'Severity']]
        for r in scan_results: data.append([r['category'], r['check'], r['status'], r['severity']])
        table = Table(data, hAlign='LEFT')
        style = TableStyle([('BACKGROUND', (0,0), (-1,0), colors.grey), ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke), ('GRID', (0,0), (-1,-1), 1, colors.black)])
        table.setStyle(style); elements.append(table)
        doc.build(elements)
        return output_path


    # ==================================================================
    # Assessment Report Helpers (shared)
    # ==================================================================

    @staticmethod
    def _sev_badge(sev):
        s = (sev or "MEDIUM").upper()
        colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#16a34a", "INFORMATIONAL": "#6b7280"}
        c = colors.get(s, "#6b7280")
        return '<span style="background:' + c + ';color:#fff;padding:2px 8px;border-radius:9999px;font-size:11px;font-weight:700">' + s + '</span>'

    @staticmethod
    def _status_badge(st):
        s = (st or "NOT_ASSESSED").upper()
        colors = {"PASS": "#16a34a", "FAIL": "#dc2626", "PARTIAL": "#d97706", "NOT_APPLICABLE": "#9ca3af", "NOT_ASSESSED": "#bfdbfe"}
        c = colors.get(s, "#9ca3af")
        return '<span style="background:' + c + ';color:#fff;padding:2px 8px;border-radius:9999px;font-size:11px;font-weight:700">' + s + '</span>'

    @staticmethod
    def _report_css():
        return """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter','Segoe UI',sans-serif;color:#111827;background:#fff;font-size:14px;line-height:1.6}
.cover{background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 60%,#0f172a 100%);color:#fff;min-height:100vh;display:flex;flex-direction:column;justify-content:center;padding:80px;page-break-after:always}
.cover-logo{font-size:24px;font-weight:800;letter-spacing:2px;color:#38bdf8;margin-bottom:60px}
.cover-badge{display:inline-block;background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.4);color:#fca5a5;padding:4px 16px;border-radius:4px;font-size:11px;font-weight:600;letter-spacing:1px;margin-bottom:24px}
.cover-title{font-size:42px;font-weight:800;line-height:1.2;margin-bottom:16px}
.cover-subtitle{font-size:22px;font-weight:400;color:#93c5fd;margin-bottom:48px}
.cover-meta{border-top:1px solid rgba(255,255,255,0.15);padding-top:32px;display:grid;grid-template-columns:1fr 1fr;gap:24px}
.cover-meta-label{font-size:11px;font-weight:600;letter-spacing:1px;color:#93c5fd;margin-bottom:4px}
.cover-meta-value{font-size:16px;font-weight:600}
.section{padding:48px 64px;page-break-inside:avoid}
.section+.section{border-top:1px solid #f3f4f6}
.section-title{font-size:22px;font-weight:700;margin-bottom:24px;padding-bottom:12px;border-bottom:2px solid #e5e7eb;color:#111827}
.section-title span{color:#2563eb}
.metric-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px}
.metric-card{background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:20px;text-align:center}
.metric-value{font-size:36px;font-weight:800}
.metric-label{font-size:12px;color:#6b7280;margin-top:4px;font-weight:500}
table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px}
th{background:#f3f4f6;padding:10px 12px;text-align:left;font-weight:600;color:#374151;font-size:11px;letter-spacing:.5px;text-transform:uppercase}
td{padding:8px 12px;border-bottom:1px solid #f3f4f6;color:#374151;vertical-align:top}
.roadmap-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.roadmap-col{background:#f9fafb;border-radius:8px;padding:20px}
.roadmap-label{font-size:12px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#2563eb;margin-bottom:12px}
.disclaimer{background:#fafafa;border:1px solid #e5e7eb;border-radius:8px;padding:20px 24px;font-size:12px;color:#6b7280;line-height:1.7}
.finding-card{border:1px solid #e5e7eb;border-radius:8px;padding:20px;margin-bottom:16px;page-break-inside:avoid}
@media print{.cover{page-break-after:always}.section{page-break-inside:avoid}}
</style>"""

    # ==================================================================
    # Executive Assessment Report (new — v2.0)
    # ==================================================================

    def generate_executive_assessment_html(self, report_data):
        """
        Generate a professional executive assessment report as styled HTML.
        Suitable for browser print-to-PDF as a client deliverable.
        """
        eng = report_data.get("engagement") or {}
        client_name = eng.get("client_name") or "Client"
        assessment_name = eng.get("assessment_name") or "Security Assessment"
        assessor = eng.get("assessor") or "NITECHSPARK Security Team"
        start_date = eng.get("start_date") or ""
        end_date = eng.get("end_date") or ""
        generated_at = report_data.get("generated_at") or datetime.now().isoformat()
        risk_summary = report_data.get("risk_summary") or {}
        findings_data = report_data.get("findings") or {}
        roadmap = report_data.get("remediation_roadmap") or {}
        retests = report_data.get("retests") or []
        critical_findings = findings_data.get("critical") or []
        high_findings = findings_data.get("high") or []
        iam_responses = report_data.get("iam_responses") or []
        dlp_controls = report_data.get("dlp_controls") or []

        total_f = findings_data.get("total", 0)
        open_f = findings_data.get("open", 0)
        resolved_f = findings_data.get("resolved", 0)
        crit_c = risk_summary.get("critical", 0)
        high_c = risk_summary.get("high", 0)
        remediation_rate = findings_data.get("remediation_rate", 0)
        retest_count = len(retests)
        remediated_retest = sum(1 for r in retests if (r.get("result") or "") == "REMEDIATED")

        if crit_c > 0:
            posture = "CRITICAL"
            posture_color = "#dc2626"
        elif high_c > 3:
            posture = "HIGH"
            posture_color = "#ea580c"
        elif high_c > 0:
            posture = "ELEVATED"
            posture_color = "#d97706"
        else:
            posture = "MODERATE"
            posture_color = "#16a34a"

        # --- Build critical/high findings table ---
        ch_rows = ""
        for f in (critical_findings + high_findings)[:20]:
            sev = (f.get("severity") or "MEDIUM").upper()
            ch_rows += (
                "<tr>"
                "<td>" + (f.get("finding_ref") or "") + "</td>"
                "<td>" + (f.get("title") or "Untitled") + "</td>"
                "<td>" + (f.get("affected_asset") or "-") + "</td>"
                "<td>" + self._sev_badge(sev) + "</td>"
                "</tr>"
            )
        if not ch_rows:
            ch_rows = "<tr><td colspan='4' style='text-align:center;color:#9ca3af'>No critical or high findings identified</td></tr>"

        # --- Build IAM table ---
        iam_rows = ""
        for r in iam_responses[:10]:
            st = r.get("status") or "NOT_ASSESSED"
            iam_rows += (
                "<tr>"
                "<td>" + (r.get("question_ref") or "") + "</td>"
                "<td>" + (r.get("question_text") or "") + "</td>"
                "<td>" + self._status_badge(st) + "</td>"
                "</tr>"
            )
        if not iam_rows:
            iam_rows = "<tr><td colspan='3' style='text-align:center;color:#9ca3af'>No IAM assessment data available</td></tr>"

        # --- Build DLP controls table ---
        dlp_rows = ""
        for c in dlp_controls[:11]:
            st = c.get("status") or "NOT_ASSESSED"
            dlp_rows += (
                "<tr>"
                "<td>" + (c.get("control_area") or "").replace("_", " ").title() + "</td>"
                "<td>" + self._status_badge(st) + "</td>"
                "<td>" + (c.get("risk_level") or "-") + "</td>"
                "</tr>"
            )
        if not dlp_rows:
            dlp_rows = "<tr><td colspan='3' style='text-align:center;color:#9ca3af'>No DLP assessment data available</td></tr>"

        # --- Build roadmap lists ---
        def _roadmap_li(items):
            if not items:
                return "<li style='color:#9ca3af'>No items in this timeframe</li>"
            return "".join("<li style='margin-bottom:4px'>&#8226; " + str(i) + "</li>" for i in items[:10])

        # --- Posture banner ---
        posture_note = "Immediate action required on critical and high severity findings." if crit_c > 0 else "No critical findings were identified during this assessment period."

        parts = []
        parts.append("<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>")
        parts.append("<title>Executive Assessment Report - " + client_name + "</title>")
        parts.append(self._report_css())
        parts.append("</head><body>")

        # Cover
        parts.append("<div class='cover'>")
        parts.append("<div class='cover-logo'>&#9889; NITECHSPARK</div>")
        parts.append("<div class='cover-badge'>CONFIDENTIAL &mdash; " + (eng.get("assessment_type") or "IT SECURITY ASSESSMENT") + "</div>")
        parts.append("<div class='cover-title'>Executive Assessment Report</div>")
        parts.append("<div class='cover-subtitle'>" + client_name + "</div>")
        parts.append("<div class='cover-meta'>")
        parts.append("<div><div class='cover-meta-label'>ASSESSMENT NAME</div><div class='cover-meta-value'>" + assessment_name + "</div></div>")
        parts.append("<div><div class='cover-meta-label'>ASSESSMENT ID</div><div class='cover-meta-value'>" + (eng.get("id") or "")[:12].upper() + "</div></div>")
        parts.append("<div><div class='cover-meta-label'>ASSESSMENT PERIOD</div><div class='cover-meta-value'>" + start_date + " &ndash; " + end_date + "</div></div>")
        parts.append("<div><div class='cover-meta-label'>PREPARED BY</div><div class='cover-meta-value'>" + assessor + "</div></div>")
        parts.append("<div><div class='cover-meta-label'>GENERATED</div><div class='cover-meta-value'>" + generated_at[:10] + "</div></div>")
        parts.append("<div><div class='cover-meta-label'>CLASSIFICATION</div><div class='cover-meta-value' style='color:#fca5a5'>CONFIDENTIAL</div></div>")
        parts.append("</div></div>")

        # Section 01: Risk Posture
        parts.append("<div class='section'>")
        parts.append("<div class='section-title'><span>01.</span> Overall Risk Posture</div>")
        parts.append("<div style='background:" + posture_color + "15;border:2px solid " + posture_color + "40;border-radius:8px;padding:24px 32px;margin-bottom:32px;display:flex;align-items:center;gap:24px'>")
        parts.append("<div><div style='font-size:12px;font-weight:600;color:#6b7280;letter-spacing:1px;margin-bottom:4px'>OVERALL RISK POSTURE</div>")
        parts.append("<div style='font-size:28px;font-weight:800;color:" + posture_color + "'>" + posture + "</div></div>")
        parts.append("<div style='font-size:14px;color:#374151'>The assessment identified <strong>" + str(total_f) + " findings</strong> across all security domains. Of these, <strong>" + str(open_f) + " remain open</strong> and <strong>" + str(resolved_f) + " have been resolved</strong>. " + posture_note + "</div>")
        parts.append("</div>")
        parts.append("<div class='metric-grid'>")
        parts.append("<div class='metric-card'><div class='metric-value' style='color:#dc2626'>" + str(risk_summary.get("critical", 0)) + "</div><div class='metric-label'>Critical</div></div>")
        parts.append("<div class='metric-card'><div class='metric-value' style='color:#ea580c'>" + str(risk_summary.get("high", 0)) + "</div><div class='metric-label'>High</div></div>")
        parts.append("<div class='metric-card'><div class='metric-value' style='color:#d97706'>" + str(risk_summary.get("medium", 0)) + "</div><div class='metric-label'>Medium</div></div>")
        parts.append("<div class='metric-card'><div class='metric-value' style='color:#16a34a'>" + str(risk_summary.get("low", 0)) + "</div><div class='metric-label'>Low</div></div>")
        parts.append("</div>")
        parts.append("<div class='metric-grid'>")
        parts.append("<div class='metric-card'><div class='metric-value'>" + str(total_f) + "</div><div class='metric-label'>Total Findings</div></div>")
        parts.append("<div class='metric-card'><div class='metric-value' style='color:#dc2626'>" + str(open_f) + "</div><div class='metric-label'>Open</div></div>")
        parts.append("<div class='metric-card'><div class='metric-value' style='color:#16a34a'>" + str(resolved_f) + "</div><div class='metric-label'>Resolved</div></div>")
        parts.append("<div class='metric-card'><div class='metric-value'>" + str(remediation_rate) + "%</div><div class='metric-label'>Remediation Rate</div></div>")
        parts.append("</div></div>")

        # Section 02: Critical/High Findings
        parts.append("<div class='section'>")
        parts.append("<div class='section-title'><span>02.</span> Critical &amp; High Priority Findings</div>")
        parts.append("<table><thead><tr><th>Ref</th><th>Finding</th><th>Affected Asset</th><th>Severity</th></tr></thead><tbody>" + ch_rows + "</tbody></table>")
        parts.append("</div>")

        # Section 03: IAM
        parts.append("<div class='section'>")
        parts.append("<div class='section-title'><span>03.</span> Identity &amp; Access Management Summary</div>")
        parts.append("<table><thead><tr><th>Ref</th><th>Control / Question</th><th>Status</th></tr></thead><tbody>" + iam_rows + "</tbody></table>")
        parts.append("</div>")

        # Section 04: DLP
        parts.append("<div class='section'>")
        parts.append("<div class='section-title'><span>04.</span> Data Loss Prevention Summary</div>")
        parts.append("<table><thead><tr><th>DLP Control Area</th><th>Status</th><th>Risk Level</th></tr></thead><tbody>" + dlp_rows + "</tbody></table>")
        parts.append("</div>")

        # Section 05: Roadmap
        parts.append("<div class='section'>")
        parts.append("<div class='section-title'><span>05.</span> Recommended Remediation Roadmap</div>")
        parts.append("<div class='roadmap-grid'>")
        parts.append("<div class='roadmap-col'><div class='roadmap-label'>&#9889; 30 Days &mdash; Critical</div><ul style='list-style:none;font-size:13px;color:#374151'>" + _roadmap_li(roadmap.get("30_days", [])) + "</ul></div>")
        parts.append("<div class='roadmap-col'><div class='roadmap-label'>&#128310; 60 Days &mdash; High</div><ul style='list-style:none;font-size:13px;color:#374151'>" + _roadmap_li(roadmap.get("60_days", [])) + "</ul></div>")
        parts.append("<div class='roadmap-col'><div class='roadmap-label'>&#128311; 90 Days &mdash; Medium</div><ul style='list-style:none;font-size:13px;color:#374151'>" + _roadmap_li(roadmap.get("90_days", [])) + "</ul></div>")
        parts.append("</div></div>")

        # Section 06: Retest
        parts.append("<div class='section'>")
        parts.append("<div class='section-title'><span>06.</span> Retest Summary</div>")
        parts.append("<div class='metric-grid' style='grid-template-columns:repeat(3,1fr)'>")
        parts.append("<div class='metric-card'><div class='metric-value'>" + str(retest_count) + "</div><div class='metric-label'>Total Retests</div></div>")
        parts.append("<div class='metric-card'><div class='metric-value' style='color:#16a34a'>" + str(remediated_retest) + "</div><div class='metric-label'>Fully Remediated</div></div>")
        parts.append("<div class='metric-card'><div class='metric-value'>" + str(retest_count - remediated_retest) + "</div><div class='metric-label'>Pending / Partial</div></div>")
        parts.append("</div></div>")

        # Section 07: Disclaimer
        parts.append("<div class='section'>")
        parts.append("<div class='section-title'><span>07.</span> Important Notice</div>")
        parts.append("<div class='disclaimer'><strong>CONFIDENTIAL DOCUMENT</strong><br><br>")
        parts.append("This report has been prepared exclusively for <strong>" + client_name + "</strong> by <strong>NITECHSPARK</strong> and contains confidential and proprietary information. ")
        parts.append("This document must not be reproduced, distributed, or disclosed to any third party without the express written consent of NITECHSPARK.<br><br>")
        parts.append("<strong>Framework references</strong>: Any references to NIST CSF 2.0, ISO 27001, CIS Controls, PCI DSS, or DPDP 2023 are provided as informational references only and do not constitute formal compliance certification.<br><br>")
        parts.append("<strong>Assessment scope</strong>: Findings represent a point-in-time view within the agreed scope.<br><br>")
        parts.append("<strong>Evidence</strong>: All evidence is retained in the NiteSentinel assessment platform subject to the agreed retention policy.")
        parts.append("</div></div>")
        parts.append("</body></html>")
        return "".join(parts)

    # ==================================================================
    # Technical Assessment Report (new — v2.0)
    # ==================================================================

    def generate_technical_assessment_html(self, report_data):
        """
        Generate a professional technical assessment report as styled HTML.
        """
        eng = report_data.get("engagement") or {}
        client_name = eng.get("client_name") or "Client"
        assessment_name = eng.get("assessment_name") or "Security Assessment"
        assessor = eng.get("assessor") or "NITECHSPARK Security Team"
        generated_at = report_data.get("generated_at") or datetime.now().isoformat()
        scope = report_data.get("scope") or []
        assets = report_data.get("assets") or []
        sections_data = report_data.get("sections") or {}
        findings = report_data.get("findings") or []
        evidence = report_data.get("evidence") or []
        risk_register = report_data.get("risk_register") or []
        remediation = report_data.get("remediation") or []
        retests = report_data.get("retests") or []

        # --- Scope table ---
        scope_rows = ""
        for e in scope:
            scope_rows += (
                "<tr><td>" + (e.get("scope_type") or "") + "</td>"
                "<td>" + (e.get("value") or "") + "</td>"
                "<td>" + (e.get("description") or "-") + "</td>"
                "<td>" + ("EXCLUDED" if e.get("excluded") else "IN SCOPE") + "</td></tr>"
            )
        if not scope_rows:
            scope_rows = "<tr><td colspan='4' style='text-align:center;color:#9ca3af'>No scope entries defined</td></tr>"

        # --- Asset table ---
        asset_rows = ""
        for a in assets:
            asset_rows += (
                "<tr>"
                "<td>" + (a.get("hostname") or a.get("ip_address") or "") + "</td>"
                "<td>" + (a.get("ip_address") or "") + "</td>"
                "<td>" + (a.get("asset_type") or "") + "</td>"
                "<td>" + (a.get("os") or "") + "</td>"
                "<td>" + (a.get("criticality") or "") + "</td>"
                "<td>" + (a.get("data_sensitivity") or "") + "</td>"
                "</tr>"
            )
        if not asset_rows:
            asset_rows = "<tr><td colspan='6' style='text-align:center;color:#9ca3af'>No assets recorded</td></tr>"

        # --- Section progress table ---
        section_rows = ""
        for s, sd in sections_data.items():
            section_rows += (
                "<tr>"
                "<td>" + s.replace("_", " ").title() + "</td>"
                "<td>" + (sd.get("status") or "NOT_STARTED") + "</td>"
                "<td>" + str(sd.get("total", 0)) + "</td>"
                "<td>" + str(sd.get("assessed", 0)) + "</td>"
                "<td>" + str(sd.get("passed", 0)) + "</td>"
                "<td>" + str(sd.get("failed", 0)) + "</td>"
                "</tr>"
            )

        # --- Findings detail cards ---
        finding_cards = ""
        import json as _json
        for f in findings[:50]:
            fr = f.get("framework_refs")
            framework_str = "-"
            if fr:
                try:
                    fr_dict = _json.loads(fr) if isinstance(fr, str) else fr
                    if isinstance(fr_dict, dict):
                        framework_str = " | ".join(str(k) + ": " + str(v) for k, v in fr_dict.items())
                    else:
                        framework_str = str(fr_dict)
                except Exception:
                    framework_str = str(fr)
            finding_cards += "<div class='finding-card'>"
            finding_cards += "<div style='display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px'>"
            finding_cards += "<div><span style='font-size:12px;color:#9ca3af;font-weight:600'>" + (f.get("finding_ref") or "") + "</span>"
            finding_cards += "<div style='font-size:16px;font-weight:700;color:#111827;margin-top:4px'>" + (f.get("title") or "") + "</div>"
            finding_cards += "<div style='font-size:12px;color:#6b7280;margin-top:2px'>" + (f.get("section") or "").replace("_", " ").title() + " | " + (f.get("affected_asset") or "Not specified") + "</div></div>"
            finding_cards += "<div style='text-align:right'>" + self._sev_badge(f.get("severity")) + "<br><span style='font-size:11px;color:#9ca3af;margin-top:4px;display:block'>Risk: " + (f.get("risk_priority_override") or f.get("risk_priority") or "") + "</span></div>"
            finding_cards += "</div>"
            finding_cards += "<table style='font-size:12px;width:100%'>"
            finding_cards += "<tr><td style='font-weight:600;width:160px;padding:4px 0'>Description:</td><td>" + (f.get("description") or "") + "</td></tr>"
            finding_cards += "<tr><td style='font-weight:600;padding:4px 0'>Business Impact:</td><td>" + (f.get("business_impact") or "-") + "</td></tr>"
            finding_cards += "<tr><td style='font-weight:600;padding:4px 0'>Technical Impact:</td><td>" + (f.get("technical_impact") or "-") + "</td></tr>"
            finding_cards += "<tr><td style='font-weight:600;padding:4px 0'>Recommendation:</td><td>" + (f.get("recommendation") or "-") + "</td></tr>"
            finding_cards += "<tr><td style='font-weight:600;padding:4px 0'>Retest Requirement:</td><td>" + (f.get("retest_requirement") or "-") + "</td></tr>"
            finding_cards += "<tr><td style='font-weight:600;padding:4px 0'>Framework Refs:</td><td>" + framework_str + "</td></tr>"
            finding_cards += "<tr><td style='font-weight:600;padding:4px 0'>Status:</td><td>" + self._status_badge(f.get("status")) + "</td></tr>"
            finding_cards += "</table></div>"

        if not finding_cards:
            finding_cards = "<p style='color:#9ca3af'>No findings recorded for this engagement.</p>"

        # --- Risk register table ---
        risk_rows = ""
        for r in risk_register:
            risk_rows += (
                "<tr>"
                "<td>" + (r.get("risk_ref") or "") + "</td>"
                "<td>" + (r.get("title") or "") + "</td>"
                "<td>" + (r.get("asset") or "-") + "</td>"
                "<td>" + self._sev_badge(r.get("severity")) + "</td>"
                "<td>" + (r.get("likelihood") or "") + "</td>"
                "<td>" + (r.get("risk_priority_override") or r.get("risk_priority") or "") + "</td>"
                "<td>" + (r.get("owner") or "-") + "</td>"
                "<td>" + (r.get("due_date") or "-") + "</td>"
                "</tr>"
            )
        if not risk_rows:
            risk_rows = "<tr><td colspan='8' style='text-align:center;color:#9ca3af'>No risk register entries</td></tr>"

        # --- Evidence table ---
        ev_rows = ""
        for e in evidence[:30]:
            ev_rows += (
                "<tr>"
                "<td>" + (e.get("evidence_type") or "") + "</td>"
                "<td>" + (e.get("description") or "") + "</td>"
                "<td>" + (e.get("collected_by") or "") + "</td>"
                "<td>" + (e.get("collected_at") or "")[:10] + "</td>"
                "<td>" + (e.get("sensitivity") or "") + "</td>"
                "</tr>"
            )
        if not ev_rows:
            ev_rows = "<tr><td colspan='5' style='text-align:center;color:#9ca3af'>No evidence records</td></tr>"

        # --- Remediation table ---
        rem_rows = ""
        for r in remediation[:30]:
            rem_rows += (
                "<tr>"
                "<td>" + (r.get("finding_title") or "") + "</td>"
                "<td>" + (r.get("action_taken") or "") + "</td>"
                "<td>" + (r.get("assigned_to") or "-") + "</td>"
                "<td>" + (r.get("target_date") or "-") + "</td>"
                "<td>" + (r.get("status") or "") + "</td>"
                "</tr>"
            )
        if not rem_rows:
            rem_rows = "<tr><td colspan='5' style='text-align:center;color:#9ca3af'>No remediation records</td></tr>"

        # --- Retest table ---
        rt_rows = ""
        for r in retests:
            rt_rows += (
                "<tr>"
                "<td>" + (r.get("retest_ref") or "") + "</td>"
                "<td>" + (r.get("finding_title") or "") + "</td>"
                "<td>" + (r.get("retest_by") or "-") + "</td>"
                "<td>" + (r.get("retest_date") or "-") + "</td>"
                "<td>" + (r.get("result") or "NOT_RETESTED") + "</td>"
                "</tr>"
            )
        if not rt_rows:
            rt_rows = "<tr><td colspan='5' style='text-align:center;color:#9ca3af'>No retest records</td></tr>"

        parts = []
        parts.append("<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>")
        parts.append("<title>Technical Assessment Report - " + client_name + "</title>")
        parts.append(self._report_css())
        parts.append("</head><body>")

        # Cover
        parts.append("<div class='cover'>")
        parts.append("<div class='cover-logo'>&#9889; NITECHSPARK</div>")
        parts.append("<div class='cover-badge'>RESTRICTED &mdash; TECHNICAL ASSESSMENT REPORT</div>")
        parts.append("<div class='cover-title'>Technical Assessment Report</div>")
        parts.append("<div class='cover-subtitle'>" + client_name + "</div>")
        parts.append("<div class='cover-meta'>")
        parts.append("<div><div class='cover-meta-label'>ENGAGEMENT</div><div class='cover-meta-value'>" + assessment_name + "</div></div>")
        parts.append("<div><div class='cover-meta-label'>GENERATED</div><div class='cover-meta-value'>" + generated_at[:10] + "</div></div>")
        parts.append("<div><div class='cover-meta-label'>ASSESSOR</div><div class='cover-meta-value'>" + assessor + "</div></div>")
        parts.append("<div><div class='cover-meta-label'>CLASSIFICATION</div><div class='cover-meta-value' style='color:#fca5a5'>RESTRICTED</div></div>")
        parts.append("</div></div>")

        parts.append("<div class='section'><div class='section-title'><span>01.</span> Assessment Scope</div>")
        parts.append("<table><thead><tr><th>Type</th><th>Value</th><th>Description</th><th>Inclusion</th></tr></thead><tbody>" + scope_rows + "</tbody></table></div>")

        parts.append("<div class='section'><div class='section-title'><span>02.</span> Assets Assessed</div>")
        parts.append("<table><thead><tr><th>Hostname</th><th>IP Address</th><th>Type</th><th>OS</th><th>Criticality</th><th>Sensitivity</th></tr></thead><tbody>" + asset_rows + "</tbody></table></div>")

        methodology = eng.get("methodology") or "NITECHSPARK IT Infrastructure Assessment Methodology: questionnaire-based controls, automated scanning, evidence collection, and risk quantification."
        parts.append("<div class='section'><div class='section-title'><span>03.</span> Assessment Methodology</div>")
        parts.append("<p style='color:#374151;margin-bottom:16px'>" + methodology + "</p>")
        parts.append("<table><thead><tr><th>Section</th><th>Status</th><th>Total</th><th>Assessed</th><th>Passed</th><th>Failed</th></tr></thead><tbody>" + section_rows + "</tbody></table></div>")

        parts.append("<div class='section'><div class='section-title'><span>04.</span> Detailed Findings</div>" + finding_cards + "</div>")

        parts.append("<div class='section'><div class='section-title'><span>05.</span> Risk Register</div>")
        parts.append("<table><thead><tr><th>Ref</th><th>Finding</th><th>Asset</th><th>Severity</th><th>Likelihood</th><th>Priority</th><th>Owner</th><th>Due Date</th></tr></thead><tbody>" + risk_rows + "</tbody></table></div>")

        parts.append("<div class='section'><div class='section-title'><span>06.</span> Evidence Summary</div>")
        parts.append("<p style='color:#374151;margin-bottom:12px'>Total evidence items: <strong>" + str(len(evidence)) + "</strong></p>")
        parts.append("<table><thead><tr><th>Type</th><th>Description</th><th>Collected By</th><th>Date</th><th>Sensitivity</th></tr></thead><tbody>" + ev_rows + "</tbody></table></div>")

        parts.append("<div class='section'><div class='section-title'><span>07.</span> Remediation Status</div>")
        parts.append("<table><thead><tr><th>Finding</th><th>Action</th><th>Assigned To</th><th>Target Date</th><th>Status</th></tr></thead><tbody>" + rem_rows + "</tbody></table></div>")

        parts.append("<div class='section'><div class='section-title'><span>08.</span> Retest Results</div>")
        parts.append("<table><thead><tr><th>Ref</th><th>Finding</th><th>Retest By</th><th>Date</th><th>Result</th></tr></thead><tbody>" + rt_rows + "</tbody></table></div>")

        parts.append("<div class='section'><div class='section-title'><span>09.</span> Important Notice &amp; Disclaimer</div>")
        parts.append("<div class='disclaimer'><strong>RESTRICTED DOCUMENT</strong><br><br>")
        parts.append("This Technical Assessment Report has been prepared for <strong>" + client_name + "</strong>. ")
        parts.append("Framework references (NIST CSF 2.0, ISO 27001, CIS Controls, PCI DSS, DPDP 2023) are informational only and do not constitute formal compliance certification.<br><br>")
        parts.append("Evidence files are stored as-is; the platform does not perform malware scanning on uploaded files.</div></div>")
        parts.append("</body></html>")
        return "".join(parts)


# Alias for backward compatibility
SecureReporter = Reporter


