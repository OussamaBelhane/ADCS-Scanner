"""
Executive CISO HTML Reporting Engine
Generates self-contained, responsive, dark-slate HTML audit reports with MITRE ATT&CK mapping.
"""

from datetime import datetime
from colorama import Fore, Style

def generate_html_report(domain, dc_ip, admins, regular_users, active_vulns, inactive_vulns, safe_templates, output_file="adcs_esc1_report.html"):
    """
    Generates an executive, CISO-ready HTML security audit report.
    Self-contained, responsive, modern dark slate styling with MITRE ATT&CK mapping.
    """
    total_templates = len(active_vulns) + len(inactive_vulns) + len(safe_templates)
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    risk_level = "CRITICAL (CVSS 9.8)" if active_vulns else ("MEDIUM" if inactive_vulns else "LOW")
    risk_color = "#ef4444" if active_vulns else ("#f59e0b" if inactive_vulns else "#10b981")
    risk_bg = "rgba(239, 68, 68, 0.15)" if active_vulns else ("rgba(245, 158, 11, 0.15)" if inactive_vulns else "rgba(16, 185, 129, 0.15)")

    # 1. Build Vulnerable Templates Rows
    vuln_rows = ""
    if active_vulns:
        for v in active_vulns:
            cas_badge = "".join([f'<span class="badge badge-ca">{ca}</span>' for ca in v.get('published_cas', [])])
            ekus_str = ", ".join(v.get('auth_ekus', []))
            enrollees_list = v.get('enrollees', [])
            enrollees_html = ""
            for e in enrollees_list:
                if e in ["Domain Users", "Authenticated Users", "Everyone", "BUILTIN\\Users"]:
                    enrollees_html += f'<span class="badge badge-crit" style="font-size:10px; margin-right:3px;">{e}</span>'
                else:
                    enrollees_html += f'<span class="badge badge-user" style="font-size:10px; margin-right:3px;">{e}</span>'

            is_unpriv = v.get('has_unprivileged_enroll', False)
            status_badge = '<span class="badge badge-crit">P1 / EXPLOITABLE</span>' if is_unpriv else '<span class="badge badge-warn">ADMIN ONLY</span>'

            vuln_rows += f"""
            <tr>
                <td><strong class="text-danger">{v['name']}</strong><br><small class="text-muted">{v.get('display_name', '')}</small></td>
                <td>{cas_badge}</td>
                <td><code>{v['name_flag']}</code> (Enrollee Supplies SAN)</td>
                <td><span class="text-warning">{ekus_str}</span></td>
                <td>{enrollees_html or '<span class="text-muted">None</span>'}</td>
                <td>{status_badge}</td>
            </tr>"""
    else:
        vuln_rows = "<tr><td colspan='6' class='text-center text-success' style='padding: 20px;'>✔ No active published templates are vulnerable to ESC1.</td></tr>"

    # 2. Build Inactive Schema Rows
    inactive_rows = ""
    if inactive_vulns:
        for iv in inactive_vulns:
            ekus_str = ", ".join(iv.get('auth_ekus', []))
            inactive_rows += f"""
            <tr>
                <td><strong>{iv['name']}</strong><br><small class="text-muted">{iv.get('display_name', '')}</small></td>
                <td><span class="badge badge-dormant">Not Published on any CA</span></td>
                <td><code>{iv['name_flag']}</code></td>
                <td>{ekus_str}</td>
                <td><span class="badge badge-warn">Schema Flaw (Dormant)</span></td>
            </tr>"""
    else:
        inactive_rows = "<tr><td colspan='5' class='text-center text-muted' style='padding: 15px;'>No dormant schema misconfigurations detected.</td></tr>"

    # 3. Build Users Recon Rows
    user_rows = ""
    for adm in admins:
        desc = adm['description'] if adm['description'] else "—"
        user_rows += f"""
        <tr class="row-highlight">
            <td><strong class="text-danger">👑 {adm['username']}</strong></td>
            <td>{adm['displayName']}</td>
            <td><span class="badge badge-admin">Domain Admin (adminCount=1)</span></td>
            <td><span class="desc-text">{desc}</span></td>
        </tr>"""

    for reg in regular_users:
        if reg['description']:  # highlight accounts with leaked passwords or notes
            user_rows += f"""
            <tr>
                <td><strong>{reg['username']}</strong></td>
                <td>{reg['displayName']}</td>
                <td><span class="badge badge-user">Standard User</span></td>
                <td><span class="desc-leaked">⚠️ {reg['description']}</span></td>
            </tr>"""

    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AD CS ESC1 Security Audit Report - {{DOMAIN}}</title>
    <style>
        :root {
            --bg: #0b0f19;
            --surface: #111827;
            --surface-card: #1f2937;
            --border: #374151;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --danger: #ef4444;
            --danger-bg: rgba(239, 68, 68, 0.12);
            --warning: #f59e0b;
            --warning-bg: rgba(245, 158, 11, 0.12);
            --success: #10b981;
            --cyan: #06b6d4;
            --purple: #a855f7;
            --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg);
            color: var(--text-primary);
            font-family: var(--font);
            line-height: 1.6;
            padding: 30px 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%);
            border: 1px solid #4338ca;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 25px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
        }
        .header-top { display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 15px; }
        .header h1 { font-size: 26px; font-weight: 700; color: #fff; margin-bottom: 8px; }
        .header p { color: var(--text-secondary); font-size: 14px; }
        .badges { display: flex; gap: 10px; margin-top: 15px; flex-wrap: wrap; }
        .badge {
            padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
        }
        .badge-crit { background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger); }
        .badge-warn { background: var(--warning-bg); color: var(--warning); border: 1px solid var(--warning); }
        .badge-mitre { background: rgba(168, 85, 247, 0.15); color: var(--purple); border: 1px solid var(--purple); }
        .badge-admin { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
        .badge-user { background: rgba(156, 163, 175, 0.15); color: #cbd5e1; }
        .badge-ca { background: rgba(6, 182, 212, 0.15); color: var(--cyan); border: 1px solid var(--cyan); margin-right: 5px; }
        .badge-dormant { background: rgba(100, 116, 139, 0.2); color: #94a3b8; border: 1px solid #475569; }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }
        .metric-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
        }
        .metric-card .title { font-size: 13px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }
        .metric-card .value { font-size: 30px; font-weight: 800; margin: 5px 0; }
        .metric-card .subtitle { font-size: 12px; color: var(--text-secondary); }

        .section {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
        }
        .section-title {
            font-size: 18px; font-weight: 700; margin-bottom: 15px; display: flex; align-items: center; gap: 10px;
            border-bottom: 1px solid var(--border); padding-bottom: 10px;
        }
        
        .attack-flow {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            overflow-x: auto;
            padding: 15px 5px;
        }
        .flow-step {
            background: var(--surface-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 15px;
            min-width: 170px;
            flex: 1;
            text-align: center;
        }
        .flow-step.crit { border-color: var(--danger); background: var(--danger-bg); }
        .flow-arrow { font-size: 20px; color: var(--cyan); font-weight: bold; }
        .flow-num { font-size: 11px; font-weight: 700; color: var(--cyan); text-transform: uppercase; }
        .flow-title { font-size: 13px; font-weight: 700; margin: 4px 0; }
        .flow-desc { font-size: 11px; color: var(--text-secondary); }

        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }
        th { text-align: left; padding: 12px; background: var(--surface-card); color: var(--text-secondary); font-size: 12px; text-transform: uppercase; }
        td { padding: 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }
        tr:hover { background: rgba(255, 255, 255, 0.02); }
        code { background: #000; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: #38bdf8; font-size: 12px; }
        
        .text-danger { color: var(--danger); }
        .text-warning { color: var(--warning); }
        .text-success { color: var(--success); }
        .text-muted { color: var(--text-secondary); }
        .desc-leaked { color: #facc15; font-weight: 600; background: rgba(250, 204, 21, 0.1); padding: 2px 6px; border-radius: 4px; }

        .remediation-box {
            background: #022c22;
            border: 1px solid #059669;
            border-radius: 8px;
            padding: 20px;
            margin-top: 15px;
        }
        .remediation-box h4 { color: #34d399; margin-bottom: 8px; }
        .code-block {
            background: #030712;
            border: 1px solid #1f2937;
            padding: 12px;
            border-radius: 6px;
            font-family: Consolas, monospace;
            font-size: 12px;
            color: #a7f3d0;
            overflow-x: auto;
            margin-top: 8px;
        }

        .footer {
            text-align: center;
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-top">
                <div>
                    <h1>🛡️ Active Directory Certificate Services (AD CS) Security Audit</h1>
                    <p>Enterprise Vulnerability Assessment & Privilege Escalation Analysis (ESC1)</p>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 12px; color: var(--text-secondary);">Target Domain Controller</div>
                    <div style="font-size: 16px; font-weight: bold; color: var(--cyan);">{{DC_IP}} ({{DOMAIN}})</div>
                </div>
            </div>
            <div class="badges">
                <span class="badge badge-crit" style="background: {{RISK_BG}}; color: {{RISK_COLOR}}; border-color: {{RISK_COLOR}};">Risk Posture: {{RISK_LEVEL}}</span>
                <span class="badge badge-mitre">MITRE ATT&CK: T1649 (Forged PKI Certificates)</span>
                <span class="badge badge-warn">Audit Scope: Active Directory Forest Root</span>
            </div>
        </div>

        <!-- Metrics Grid -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="title">Active ESC1 Exploits</div>
                <div class="value text-danger">{{ACTIVE_COUNT}}</div>
                <div class="subtitle">Enrollee Supplies SAN & Client Auth</div>
            </div>
            <div class="metric-card">
                <div class="title">Total Evaluated Templates</div>
                <div class="value" style="color: var(--cyan);">{{TOTAL_TEMPLATES}}</div>
                <div class="subtitle">Discovered in AD Configuration Schema</div>
            </div>
            <div class="metric-card">
                <div class="title">Admin Accounts (Targets)</div>
                <div class="value" style="color: #f87171;">{{ADMIN_COUNT}}</div>
                <div class="subtitle">adminCount = 1 (Impersonation targets)</div>
            </div>
            <div class="metric-card">
                <div class="title">Audit Timestamp</div>
                <div class="value" style="font-size: 16px; margin: 12px 0; color: #cbd5e1;">{{TIMESTAMP}}</div>
                <div class="subtitle">Auditor: Oussama Belhane</div>
            </div>
        </div>

        <!-- Attack Chain Flowchart -->
        <div class="section">
            <div class="section-title">⚡ Attack Narrative: ESC1 Privilege Escalation Chain</div>
            <div class="attack-flow">
                <div class="flow-step">
                    <div class="flow-num">Step 1</div>
                    <div class="flow-title">Low-Priv Access</div>
                    <div class="flow-desc">Standard domain user (e.g. <code>john</code>) with no special rights.</div>
                </div>
                <div class="flow-arrow">➔</div>
                <div class="flow-step crit">
                    <div class="flow-num">Step 2</div>
                    <div class="flow-title">Enroll in ESC1</div>
                    <div class="flow-desc">Requests cert specifying <code>SAN: Administrator</code>.</div>
                </div>
                <div class="flow-arrow">➔</div>
                <div class="flow-step">
                    <div class="flow-num">Step 3</div>
                    <div class="flow-title">CA Issues Cert</div>
                    <div class="flow-desc">Enterprise CA signs cert with requested Administrator identity.</div>
                </div>
                <div class="flow-arrow">➔</div>
                <div class="flow-step">
                    <div class="flow-num">Step 4</div>
                    <div class="flow-title">PKINIT Kerberos</div>
                    <div class="flow-desc">Authenticate to KDC via certificate to obtain Admin TGT.</div>
                </div>
                <div class="flow-arrow">➔</div>
                <div class="flow-step crit">
                    <div class="flow-num">Step 5</div>
                    <div class="flow-title">Domain Takeover</div>
                    <div class="flow-desc">Full Domain Administrator access (Pass-The-Ticket / DCSync).</div>
                </div>
            </div>
        </div>

        <!-- Vulnerability Table -->
        <div class="section">
            <div class="section-title">🚨 Active Exploitable Templates (ESC1)</div>
            <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">
                These templates are published by an active Enterprise CA, allow enrollees to supply an arbitrary Subject Alternative Name (SAN), permit Client Authentication, and require no manager approval.
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Certificate Template</th>
                        <th>Published On CA</th>
                        <th>Misconfiguration Flag</th>
                        <th>EKU Purposes</th>
                        <th>DACL Enrollees (Permissions)</th>
                        <th>Severity / Impact</th>
                    </tr>
                </thead>
                <tbody>
                    {{VULN_ROWS}}
                </tbody>
            </table>
        </div>

        <!-- Inactive Misconfigurations -->
        <div class="section">
            <div class="section-title">⚠️ Inactive Schema Misconfigurations (Dormant Flaws)</div>
            <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">
                These templates have ESC1 configuration flaws in the Active Directory schema, but are currently <strong>not published</strong> on any active Certification Authority. If an administrator publishes them, they become immediately exploitable.
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Certificate Template</th>
                        <th>CA Publication Status</th>
                        <th>Schema Flags</th>
                        <th>EKU Purposes</th>
                        <th>Risk Assessment</th>
                    </tr>
                </thead>
                <tbody>
                    {{INACTIVE_ROWS}}
                </tbody>
            </table>
        </div>

        <!-- Directory Recon -->
        <div class="section">
            <div class="section-title">👥 Active Directory User Reconnaissance & Target Mapping</div>
            <table>
                <thead>
                    <tr>
                        <th>Account</th>
                        <th>Display Name</th>
                        <th>Privilege Tier</th>
                        <th>Description / Credentials Found</th>
                    </tr>
                </thead>
                <tbody>
                    {{USER_ROWS}}
                </tbody>
            </table>
        </div>

        <!-- BloodHound Graph & Cypher Queries -->
        <div class="section">
            <div class="section-title">🩸 BloodHound Attack Graph & Cypher Query Modeling</div>
            <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">
                Exported attack graph models connecting enrolled Active Directory principals, vulnerable templates (<code>CanEnroll</code>), and privilege escalation paths to Domain Admins.
            </p>
            <div style="background: #030712; border: 1px solid #1f2937; border-radius: 8px; padding: 15px; font-family: Consolas, monospace; font-size: 12px; color: #38bdf8;">
                <div style="color: #94a3b8; margin-bottom: 6px;">// BloodHound / Neo4j Cypher Query to find exploitable AD CS paths:</div>
                MATCH p=(g:Group)-[:CanEnroll]-&gt;(t:CertTemplate)-[:PublishedTo]-&gt;(ca:EnterpriseCA) WHERE t.enrolleesuppliessubject = true RETURN p;
            </div>
        </div>

        <!-- Remediation & Telemetry -->
        <div class="section">
            <div class="section-title">🛡️ Blue Team Hardening & Detection Telemetry</div>
            <div class="remediation-box">
                <h4>Option 1: Automated PowerShell Remediation (Recommended)</h4>
                <p style="font-size: 13px; color: #a7f3d0;">
                    Execute the automatically generated <code>remediate_esc1.ps1</code> script with Domain Administrator privileges to strip <code>CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT</code> (0x1) while creating safety backups.
                </p>
                <div class="code-block">
powershell.exe -ExecutionPolicy Bypass -File .\remediate_esc1.ps1
                </div>
            </div>

            <div style="margin-top: 20px;">
                <h4 style="font-size: 14px; margin-bottom: 8px;">Option 2: Manual Certificate Template Manager Hardening</h4>
                <p style="font-size: 13px; color: var(--text-secondary);">
                    Open <code>certtmpl.msc</code> on the CA ➔ Right click the vulnerable template ➔ <strong>Properties</strong> ➔ <strong>Subject Name</strong> tab ➔ Change from <em>"Supply in the request"</em> to <em>"Build from this Active Directory information"</em>.
                </p>
            </div>

            <div style="margin-top: 20px;">
                <h4 style="font-size: 14px; margin-bottom: 8px;">Detection Telemetry (SIEM & Windows Event IDs)</h4>
                <ul style="font-size: 13px; color: var(--text-secondary); margin-left: 20px;">
                    <li><strong>Event ID 4886 (CA):</strong> Certificate Services received a certificate request (monitor for unexpected SAN submissions).</li>
                    <li><strong>Event ID 4887 (CA):</strong> Certificate Services issued a certificate (monitor requests for Domain Admin SANs from standard user accounts).</li>
                    <li><strong>Event ID 4768 (DC):</strong> A Kerberos TGT ticket was requested using a certificate (pre-authentication type 16 / PKINIT).</li>
                </ul>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p><strong>AD CS ESC1 Vulnerability Scanner & Enterprise Auditor</strong></p>
            <p>Author: <strong>Oussama Belhane</strong> | Master's PFE Engineering Portfolio | MITRE ATT&CK T1649</p>
        </div>
    </div>
</body>
</html>"""

    html = html_template \
        .replace("{{DOMAIN}}", domain) \
        .replace("{{DC_IP}}", dc_ip) \
        .replace("{{TIMESTAMP}}", scan_time) \
        .replace("{{RISK_LEVEL}}", risk_level) \
        .replace("{{RISK_COLOR}}", risk_color) \
        .replace("{{RISK_BG}}", risk_bg) \
        .replace("{{ACTIVE_COUNT}}", str(len(active_vulns))) \
        .replace("{{TOTAL_TEMPLATES}}", str(total_templates)) \
        .replace("{{ADMIN_COUNT}}", str(len(admins))) \
        .replace("{{VULN_ROWS}}", vuln_rows) \
        .replace("{{INACTIVE_ROWS}}", inactive_rows) \
        .replace("{{USER_ROWS}}", user_rows)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    print(Fore.GREEN + Style.BRIGHT + f"[+] CISO Executive HTML audit report generated: {output_file}")
    return output_file


