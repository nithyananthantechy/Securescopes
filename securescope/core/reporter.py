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
    <title>SecureScope Security Report - {org}</title>
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
        <div class="subtitle">SecureScope Security Assessment Report</div>
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
            <p style="font-weight: bold; color: #00d4ff; margin-bottom: 5px;">About NiTechSpark Security Systems</p>
            <p style="font-size: 12px; margin-bottom: 10px;">
                NiTechSpark provides advanced security automation and hardening solutions for enterprise infrastructure.
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
        elements.append(Paragraph(f"<b>{self.org_name} SecureScope Security Assessment Report</b>", styles['Title']))
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

# Alias for backward compatibility
SecureReporter = Reporter
