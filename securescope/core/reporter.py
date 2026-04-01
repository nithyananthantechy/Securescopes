import platform
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

class SecureReporter:
    def __init__(self, org_name="NiTechSpark"):
        self.org_name = org_name

    def generate(self, results, org="NiTechSpark"):
        """Generates a multi-section enterprise HTML report."""
        checks = results.get('checks', [])
        score = results.get('score', 0)
        os_name = get_report_os()
        timestamp = datetime.now().strftime('%d %b %Y, %H:%M:%S')
        
        # Determine score color
        score_color = "#ef4444" # Red
        if score >= 86: score_color = "#22c55e" # Green
        elif score >= 71: score_color = "#3b82f6" # Blue
        elif score >= 41: score_color = "#f97316" # Orange

        passed = sum(1 for c in checks if c['status'] == 'PASS')
        failed = sum(1 for c in checks if c['status'] == 'FAIL')
        warnings = sum(1 for c in checks if c['status'] == 'WARNING')

        critical_items = [c for c in checks if c.get("status") == "FAIL"][:3]
        top_issues = "".join(
            f"<li><b>{c.get('check')}</b>: {c.get('details')}</li>" for c in critical_items
        ) or "<li>No critical issues detected.</li>"

        rec_rows = []
        for c in checks:
            if c.get("status") == "FAIL":
                priority = "P1" if c.get("severity") == "Critical" else ("P2" if c.get("severity") == "High" else "P3")
                rec_rows.append(
                    f"<tr><td><b>{c.get('check')}</b></td><td>{c.get('details')}</td><td>Potential service compromise and compliance impact.</td><td>Review config, apply patch, validate controls.</td><td>{priority}</td></tr>"
                )
        if not rec_rows:
            rec_rows.append("<tr><td colspan='5'>No mandatory remediation items.</td></tr>")

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SecureScope Report - {org}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #333; margin: 0; background: #f4f7f9; }}
                .page {{ max-width: 900px; margin: 0 auto 24px; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); border-top: 8px solid #00d4ff; }}
                .header-flex {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #eee; padding-bottom: 20px; margin-bottom: 30px; }}
                .logo-text {{ font-weight: bold; font-size: 24px; color: #00d4ff; letter-spacing: 1px; }}
                h1 {{ color: #00d4ff; margin: 0 0 10px 0; font-size: 28px; }}
                .meta-info {{ color: #666; font-size: 14px; line-height: 1.6; }}
                .score-box {{ text-align: center; margin: 40px 0; padding: 30px; background: #fafafa; border-radius: 12px; border: 1px solid #eee; }}
                .score-circle {{ width: 120px; height: 120px; line-height: 120px; border-radius: 50%; border: 8px solid {score_color}; margin: auto; font-size: 48px; font-weight: bold; color: {score_color}; }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 40px; }}
                .stat-item {{ padding: 15px; border-radius: 8px; text-align: center; font-weight: bold; }}
                .stat-fail {{ background: #fee2e2; color: #ef4444; }}
                .stat-pass {{ background: #dcfce7; color: #22c55e; }}
                .stat-warn {{ background: #fef3c7; color: #f97316; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th {{ background: #f8fafc; color: #64748b; text-align: left; padding: 12px; font-size: 13px; text-transform: uppercase; border-bottom: 2px solid #eee; }}
                td {{ padding: 12px; border-bottom: 1px solid #eee; font-size: 14px; }}
                .status-badge {{ padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; }}
                .status-PASS {{ background: #22c55e; color: white; }}
                .status-FAIL {{ background: #ef4444; color: white; }}
                .status-WARNING {{ background: #f97316; color: white; }}
                .severity-Critical {{ color: #ef4444; font-weight: bold; }}
                .footer {{ text-align: center; margin-top: 50px; color: #999; font-size: 12px; border-top: 1px solid #eee; padding-top: 20px; }}
                .cover {{ background: #0a0e1a; color: #e8eaf6; text-align: center; min-height: 420px; }}
                .cover h1 {{ color: #00d4ff; font-size: 40px; }}
                .pagebreak {{ page-break-before: always; }}
                @media print {{ .page {{ box-shadow: none; margin: 0; border-radius: 0; }} .pagebreak {{ page-break-before: always; }} }}
            </style>
        </head>
        <body>
            <div class="page cover">
                <div class="logo-text">NITECHSPARK</div>
                <h1>Security Assessment Report</h1>
                <p><b>Client:</b> {org}</p>
                <p><b>Date:</b> {timestamp}</p>
                <p><b>Assessor:</b> SecureScope Engine v1.0</p>
                <p>Confidential. For authorized recipients only.</p>
                <p>Contact: nitechspark@gmail.com | nitechspark.vercel.app</p>
            </div>

            <div class="page pagebreak">
                <div class="header-flex">
                    <div>
                        <div class="logo-text">NITECHSPARK</div>
                        <h1>Executive Summary</h1>
                        <div class="meta-info">
                            Prepared by: NiTechSpark Security Team<br>
                            Website: <a href="https://nitechspark.vercel.app/" style="color:#00d4ff">nitechspark.vercel.app</a><br>
                            Contact: nitechspark@gmail.com
                        </div>
                    </div>
                    <div style="text-align: right;" class="meta-info">
                        <strong>Target:</strong> {os_name}<br>
                        <strong>Date:</strong> {timestamp}<br>
                        <strong>Assessor:</strong> SecureScope Engine v1.0
                    </div>
                </div>

                <div class="score-box">
                    <div class="score-circle">{score}</div>
                    <div style="margin-top: 15px; font-weight: 600; color: #64748b;">Overall Security Compliance Score</div>
                </div>

                <div class="stats-grid">
                    <div class="stat-item stat-fail">❌ {failed} Failed</div>
                    <div class="stat-item stat-pass">✅ {passed} Passed</div>
                    <div class="stat-item stat-warn">⚠️ {warnings} Warning</div>
                </div>
                <h3 style="color: #00d4ff;">Top Critical Findings</h3>
                <ul>{top_issues}</ul>
                <p><b>Scope:</b> Host and service configuration checks executed by SecureScope scanner modules.</p>
            </div>

            <div class="page pagebreak">
                <h3 style="color: #00d4ff; border-left: 4px solid #00d4ff; padding-left: 10px;">Technical Findings</h3>
                <h3 style="color: #00d4ff; border-left: 4px solid #00d4ff; padding-left: 10px;">Detailed Audit Findings</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Check</th>
                            <th>Status</th>
                            <th>Severity</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for c in checks:
            html += f"""
                        <tr>
                            <td style="color: #64748b;">{c['category']}</td>
                            <td style="font-weight: 600;">{c['check']}</td>
                            <td><span class="status-badge status-{c['status']}">{c['status']}</span></td>
                            <td class="severity-{c['severity']}">{c['severity']}</td>
                            <td style="color: #666; font-size: 12px;">{c['details']}</td>
                        </tr>
            """

        html += f"""
                    </tbody>
                </table>
            </div>

            <div class="page pagebreak">
                <h3 style="color: #00d4ff;">Recommendations</h3>
                <table>
                    <thead><tr><th>Issue</th><th>Description</th><th>Business Risk</th><th>Remediation</th><th>Priority</th></tr></thead>
                    <tbody>
                        {"".join(rec_rows)}
                    </tbody>
                </table>
            </div>

            <div class="page pagebreak">
                <h3 style="color: #00d4ff;">About NiTechSpark</h3>
                <p>{org} delivers cybersecurity assessments, hardening, and compliance-focused remediation for startups and enterprises.</p>
                <ul>
                    <li>Security Assessments and Hardening</li>
                    <li>Compliance Readiness (ISO 27001 / SOC 2 / NIST)</li>
                    <li>Continuous Security Monitoring</li>
                </ul>
                <div class="footer">Generated by SecureScope | NiTechSpark Security Systems | &copy; 2026</div>
            </div>
        </body>
        </html>
        """
        return html

    def generate_pdf(self, scan_results, score, target_info, output_path="report.pdf"):
        # Keep existing PDF method for CLI use if needed
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
