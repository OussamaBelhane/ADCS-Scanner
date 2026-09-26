#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
   🛡️ ADCS ESC1 Vulnerability Scanner & PKI Auditor (v1.0.0)
   Author : Oussama Belhane (Cybersecurity Engineering Portfolio)
   License: MIT
   Purpose: Active Directory Certificate Services (ADCS) Misconfiguration Auditor
================================================================================
"""

import sys
import os
import argparse
import json
from datetime import datetime

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError:
    # Fallback if colorama is not yet installed
    class Fore:
        CYAN = '\033[96m'
        BLUE = '\033[94m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        MAGENTA = '\033[95m'
        WHITE = '\033[97m'
        RESET = '\033[0m'
    class Style:
        BRIGHT = '\033[1m'
        DIM = '\033[2m'
        RESET_ALL = '\033[0m'

# Check if ldap3 is installed
HAS_LDAP3 = False
try:
    from ldap3 import Server, Connection, NTLM, ALL, SUBTREE, ALL_ATTRIBUTES
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False


# ============================================================================
# 🎨 CONSOLE UI & STYLING ENGINE (Airgeddon / Cyberpunk Inspired)
# ============================================================================

class UI:
    C_MAIN = Fore.CYAN + Style.BRIGHT
    C_ACCENT = Fore.MAGENTA + Style.BRIGHT
    C_OK = Fore.GREEN + Style.BRIGHT
    C_WARN = Fore.YELLOW + Style.BRIGHT
    C_CRIT = Fore.RED + Style.BRIGHT
    C_DIM = Fore.WHITE + Style.DIM
    C_RESET = Style.RESET_ALL

    @staticmethod
    def banner():
        logo = f"""
{UI.C_MAIN}    ╔════════════════════════════════════════════════════════════════════════════╗
    ║   █████╗ ██████╗  ██████╗███████╗    ███████╗███████╗ ██████╗ ██╗        ║
    ║  ██╔══██╗██╔══██╗██╔════╝██╔════╝    ██╔════╝██╔════╝██╔════╝███║        ║
    ║  ███████║██║  ██║██║     ███████╗    █████╗  ███████╗██║     ╚██║        ║
    ║  ██╔══██║██║  ██║██║     ╚════██║    ██╔══╝  ╚════██║██║      ██║        ║
    ║  ██║  ██║██████╔╝╚██████╗███████║    ███████╗███████║╚██████╗ ██║        ║
    ║  ╚═╝  ╚═╝╚═════╝  ╚═════╝╚══════╝    ╚══════╝╚══════╝ ╚═════╝ ╚═╝        ║
    ║          Active Directory Certificate Services Vulnerability Scanner      ║
    ╚════════════════════════════════════════════════════════════════════════════╝{UI.C_RESET}
    {UI.C_ACCENT}► Developed by : Oussama Belhane (Cybersecurity Engineer){UI.C_RESET}
    {UI.C_DIM}► Focus Target : Misconfigured PKI Certificate Templates (ESC1 Abuse){UI.C_RESET}
    {UI.C_DIM}► Version      : 1.0.0-PROD | T1649 Defense & Audit{UI.C_RESET}
"""
        print(logo)

    @staticmethod
    def section(title):
        bar = "═" * (68 - len(title))
        print(f"\n{UI.C_MAIN}╔═[ {Style.BRIGHT}{title} ]{bar}╗{UI.C_RESET}")

    @staticmethod
    def subheader(title):
        print(f"\n{UI.C_ACCENT}──► {Style.BRIGHT}{title}{UI.C_RESET}")

    @staticmethod
    def info(msg):
        print(f"  {UI.C_MAIN}[*]{UI.C_RESET} {msg}")

    @staticmethod
    def success(msg):
        print(f"  {UI.C_OK}[+]{UI.C_RESET} {msg}")

    @staticmethod
    def warn(msg):
        print(f"  {UI.C_WARN}[!]{UI.C_RESET} {msg}")

    @staticmethod
    def alert(msg):
        print(f"  {UI.C_CRIT}[🚨 CRITICAL]{UI.C_RESET} {msg}")

    @staticmethod
    def card(title, key_values, is_vulnerable=False):
        c_border = UI.C_CRIT if is_vulnerable else UI.C_OK
        tag = f"{UI.C_CRIT} VULNERABLE: ESC1 {UI.C_RESET}" if is_vulnerable else f"{UI.C_OK} SAFE TEMPLATE {UI.C_RESET}"
        
        print(f"\n  {c_border}┌────────────────────────────────────────────────────────────────────────┐{UI.C_RESET}")
        print(f"  {c_border}│{UI.C_RESET} {Style.BRIGHT}{title:<56}{UI.C_RESET} [{tag}] {c_border}│{UI.C_RESET}")
        print(f"  {c_border}├────────────────────────────────────────────────────────────────────────┤{UI.C_RESET}")
        
        for k, v in key_values:
            print(f"  {c_border}│{UI.C_RESET}  {UI.C_DIM}• {k:<26}:{UI.C_RESET} {v:<40} {c_border}│{UI.C_RESET}")
            
        print(f"  {c_border}└────────────────────────────────────────────────────────────────────────┘{UI.C_RESET}")


# ============================================================================
# 🛡️ ADCS ESC1 LOGIC & BITWISE FLAGS ENGINE
# ============================================================================

# Flag definitions from Microsoft MS-CRTD specifications:
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS         = 0x00000002

# OIDs for Authentication Extended Key Usages (EKU):
AUTHENTICATION_EKUS = {
    "1.3.6.1.5.5.7.3.2":   "Client Authentication",
    "1.3.6.1.5.2.3.4":     "PKINIT Client Authentication",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "2.5.29.37.0":         "Any Purpose (Wildcard)",
    "1.3.6.1.4.1.311.10.3.11": "Key Recovery Agent"
}


class ADCSAuditor:
    def __init__(self, target_dc, domain, username, password, use_ssl=False):
        self.dc = target_dc
        self.domain = domain
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.base_dn = ""
        self.config_dn = ""
        self.conn = None
        self.templates = []
        self.vulnerable_count = 0
        self.safe_count = 0

    def calculate_dns(self):
        parts = self.domain.split(".")
        self.base_dn = ",".join([f"DC={p}" for p in parts])
        self.config_dn = f"CN=Configuration,{self.base_dn}"

    def connect(self):
        if not HAS_LDAP3:
            UI.alert("Error: 'ldap3' library is not installed! Run: pip install ldap3")
            return False

        UI.info(f"Targeting Domain Controller : {UI.C_MAIN}{self.dc}{UI.C_RESET}")
        UI.info(f"Connecting to Active Directory : {UI.C_MAIN}{self.domain}{UI.C_RESET}")
        self.calculate_dns()

        port = 636 if self.use_ssl else 389
        proto = "LDAPS" if self.use_ssl else "LDAP"
        UI.info(f"Establishing {proto} session on port {port}...")

        try:
            server = Server(self.dc, port=port, use_ssl=self.use_ssl, get_info=ALL)
            user_auth = f"{self.domain}\\{self.username}"
            self.conn = Connection(server, user=user_auth, password=self.password, authentication=NTLM)

            if not self.conn.bind():
                UI.alert(f"Authentication Failed for user: {user_auth}")
                UI.warn(f"LDAP Response: {self.conn.result.get('description', 'Unknown Error')}")
                return False

            UI.success(f"Authenticated successfully as: {Style.BRIGHT}{user_auth}{UI.C_RESET}")
            return True

        except Exception as e:
            UI.alert(f"Connection Exception: {str(e)}")
            return False

    def query_templates(self):
        templates_container = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{self.config_dn}"
        UI.info(f"Querying PKI Certificate Container in AD Configuration partition...")
        UI.info(f"Search Base: {UI.C_DIM}{templates_container}{UI.C_RESET}")

        try:
            attributes = [
                'cn', 'displayName', 'name', 'msPKI-Certificate-Name-Flag',
                'msPKI-Enrollment-Flag', 'pKIExtendedKeyUsage', 'nTSecurityDescriptor'
            ]
            self.conn.search(
                search_base=templates_container,
                search_filter="(objectClass=pKICertificateTemplate)",
                search_scope=SUBTREE,
                attributes=attributes
            )

            raw_entries = self.conn.entries
            UI.success(f"Retrieved {Style.BRIGHT}{len(raw_entries)}{UI.C_RESET} Active Directory Certificate Templates.")
            return raw_entries

        except Exception as e:
            UI.alert(f"Failed to query certificate templates: {str(e)}")
            return []

    def analyze_template(self, name, display_name, name_flag, enroll_flag, ekus):
        """
        Analyzes ESC1 Vulnerability criteria:
        1. Enrollee Supplies Subject: msPKI-Certificate-Name-Flag & 0x1 != 0
        2. Client Authentication EKU present (or Any Purpose)
        3. Manager Approval NOT required: msPKI-Enrollment-Flag & 0x2 == 0
        """
        enrollee_supplies_subject = bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
        manager_approval_required = bool(enroll_flag & CT_FLAG_PEND_ALL_REQUESTS)

        # Check for authentication EKUs
        auth_eku_found = []
        if isinstance(ekus, list):
            for eku in ekus:
                if eku in AUTHENTICATION_EKUS:
                    auth_eku_found.append(AUTHENTICATION_EKUS[eku])
        elif ekus in AUTHENTICATION_EKUS:
            auth_eku_found.append(AUTHENTICATION_EKUS[ekus])

        # A template with no EKU specified allows all purposes (SubCA)
        if not ekus:
            auth_eku_found.append("All Purposes (Wildcard/SubCA)")

        # ESC1 Verdict
        is_esc1 = False
        reasons = []

        if enrollee_supplies_subject:
            reasons.append("ENROLLEE_SUPPLIES_SUBJECT flag is ENABLED (0x00000001)")
            if auth_eku_found:
                reasons.append(f"Allows Authentication EKU: {', '.join(auth_eku_found)}")
                if not manager_approval_required:
                    reasons.append("No Manager Approval required (Auto-Approval)")
                    is_esc1 = True
                else:
                    reasons.append("Mitigated: Manager Approval is enforced")
            else:
                reasons.append("Safe: No Client Authentication EKU present")
        else:
            reasons.append("Safe: Subject is generated from Active Directory identity")

        return {
            "name": name,
            "display_name": display_name,
            "name_flag": hex(name_flag),
            "enrollee_supplies_subject": enrollee_supplies_subject,
            "manager_approval": manager_approval_required,
            "ekus": auth_eku_found,
            "is_vulnerable": is_esc1,
            "reasons": reasons
        }


# ============================================================================
# 🧪 DEMO MODE SIMULATOR (Test look without live DC)
# ============================================================================

def run_demo():
    UI.section("SYSTEM INITIALIZATION & DEMO ENVIRONMENT")
    UI.info("Starting in DEMO / SIMULATION mode (Simulating Live Active Directory DC)")
    UI.info("Targeting virtual Domain Controller : DC01.CORP.LOCAL (192.168.10.10)")
    UI.success("Authenticated successfully as: CORP\\jdoe (Standard Domain User)")

    mock_templates = [
        {
            "name": "User",
            "display_name": "Standard Domain User",
            "name_flag": 0x00000000,
            "enroll_flag": 0x00000000,
            "ekus": ["1.3.6.1.5.5.7.3.2"]
        },
        {
            "name": "Machine",
            "display_name": "Computer Identity",
            "name_flag": 0x00000000,
            "enroll_flag": 0x00000000,
            "ekus": ["1.3.6.1.5.5.7.3.2"]
        },
        {
            "name": "WebServer",
            "display_name": "Internal Web Server",
            "name_flag": 0x00000001,
            "enroll_flag": 0x00000000,
            "ekus": ["1.3.6.1.5.5.7.3.1"] # Server Auth only, safe from ESC1
        },
        {
            "name": "Corp-VPN-Certificate",
            "display_name": "Corporate Remote Access VPN",
            "name_flag": 0x00000001,      # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
            "enroll_flag": 0x00000000,    # No Manager Approval!
            "ekus": ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.2.3.4"] # Client Auth + PKINIT!
        },
        {
            "name": "SmartCard-Enrollment",
            "display_name": "Executive SmartCard Logon",
            "name_flag": 0x00000001,
            "enroll_flag": 0x00000002,    # Requires Manager Approval! (Mitigated)
            "ekus": ["1.3.6.1.4.1.311.20.2.2"]
        }
    ]

    UI.section("ACTIVE DIRECTORY CERTIFICATE TEMPLATES AUDIT")
    UI.info(f"Analyzing {len(mock_templates)} retrieved certificate templates...\n")

    auditor = ADCSAuditor("DC01.CORP.LOCAL", "corp.local", "jdoe", "demo")
    findings = []

    for t in mock_templates:
        result = auditor.analyze_template(
            t["name"], t["display_name"], t["name_flag"], t["enroll_flag"], t["ekus"]
        )
        findings.append(result)

        if result["is_vulnerable"]:
            auditor.vulnerable_count += 1
            UI.card(
                f"Template: {result['name']} ({result['display_name']})",
                [
                    ("Vulnerability Class", "ADCS ESC1 (Critical Privilege Escalation)"),
                    ("Subject Flag", f"{result['name_flag']} (ENROLLEE_SUPPLIES_SUBJECT)"),
                    ("Manager Approval", "FALSE (Immediate issuance without approval)"),
                    ("Extended Key Usage", ", ".join(result['ekus'])),
                    ("Privilege Escalation", "Standard User ──► DOMAIN ADMINISTRATOR"),
                    ("Attack Method", "Request cert with SAN: Administrator ➔ PKINIT TGT"),
                    ("Remediation", "Uncheck 'Supply in the request' in CA Template console")
                ],
                is_vulnerable=True
            )
        else:
            auditor.safe_count += 1
            print(f"  {UI.C_OK}[✔ SAFE]{UI.C_RESET} {result['name']:<24} {UI.C_DIM}│ Flag: {result['name_flag']:<10} │ EKUs: {', '.join(result['ekus']) or 'None'}{UI.C_RESET}")

    display_summary(auditor.vulnerable_count, auditor.safe_count, findings, "demo_adcs_audit_report.json")


# ============================================================================
# 📊 EXECUTIVE SUMMARY & REPORT GENERATOR
# ============================================================================

def display_summary(vuln_count, safe_count, findings, output_file=None):
    total = vuln_count + safe_count
    UI.section("EXECUTIVE AUDIT SUMMARY & RISK RATING")

    print(f"""
  {UI.C_MAIN}┌─────────────────────────────────┬─────────────────────────────────┐{UI.C_RESET}
  {UI.C_MAIN}│{UI.C_RESET} {Style.BRIGHT}METRIC SUMMARY                  {UI.C_RESET}{UI.C_MAIN}│{UI.C_RESET} {Style.BRIGHT}VALUE                           {UI.C_RESET}{UI.C_MAIN}│{UI.C_RESET}
  {UI.C_MAIN}├─────────────────────────────────┼─────────────────────────────────┤{UI.C_RESET}
  {UI.C_MAIN}│{UI.C_RESET} Total Templates Analyzed        {UI.C_MAIN}│{UI.C_RESET} {total:<31} {UI.C_MAIN}│{UI.C_RESET}
  {UI.C_MAIN}│{UI.C_RESET} Safe / Non-Vulnerable Templates  {UI.C_MAIN}│{UI.C_RESET} {UI.C_OK}{safe_count:<31}{UI.C_RESET} {UI.C_MAIN}│{UI.C_RESET}
  {UI.C_MAIN}│{UI.C_RESET} Critical Vulnerabilities (ESC1)  {UI.C_MAIN}│{UI.C_RESET} {UI.C_CRIT}{vuln_count:<31}{UI.C_RESET} {UI.C_MAIN}│{UI.C_RESET}
  {UI.C_MAIN}│{UI.C_RESET} Overall Domain Risk Level        {UI.C_MAIN}│{UI.C_RESET} {UI.C_CRIT if vuln_count > 0 else UI.C_OK}{'🚨 CRITICAL RISK (P1)' if vuln_count > 0 else '🟢 LOW RISK'}{UI.C_RESET} {UI.C_MAIN}│{UI.C_RESET}
  {UI.C_MAIN}└─────────────────────────────────┴─────────────────────────────────┘{UI.C_RESET}
""")

    if vuln_count > 0:
        UI.alert("ACTION REQUIRED: High-risk misconfiguration allows unauthorized Domain Admin takeover!")
        UI.warn("Blue Team Remediation: Edit vulnerable template in `certtmpl.msc` and select 'Build from this Active Directory information'.")
    else:
        UI.success("All Active Directory Certificate Templates are correctly enforcing subject identity.")

    if output_file:
        try:
            report_data = {
                "audit_timestamp": datetime.utcnow().isoformat() + "Z",
                "scanner_version": "1.0.0",
                "summary": {
                    "total_templates": total,
                    "vulnerable_esc1": vuln_count,
                    "safe": safe_count,
                    "domain_risk": "CRITICAL" if vuln_count > 0 else "LOW"
                },
                "findings": findings
            }
            with open(output_file, "w") as f:
                json.dump(report_data, f, indent=4)
            UI.success(f"Full audit report exported to JSON: {Style.BRIGHT}{output_file}{UI.C_RESET}")
        except Exception as e:
            UI.warn(f"Failed to export report: {str(e)}")

    print(f"\n{UI.C_DIM}Audit completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}. End of report.\n{UI.C_RESET}")


# ============================================================================
# 🚀 MAIN ENTRYPOINT
# ============================================================================

def main():
    UI.banner()

    parser = argparse.ArgumentParser(
        description="ADCS ESC1 Vulnerability Scanner — Active Directory PKI Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run in instant demonstration mode (no lab required):
  python adcs_esc1_scanner.py --demo

  # Scan a live Domain Controller over LDAP:
  python adcs_esc1_scanner.py -dc 192.168.1.10 -d corporate.local -u jdoe -p 'Winter2026!'

  # Scan using LDAPS (port 636) and export JSON report:
  python adcs_esc1_scanner.py -dc 192.168.1.10 -d corporate.local -u jdoe -p 'Winter2026!' --ssl -o report.json
"""
    )

    parser.add_argument("-dc", "--dc-ip", help="IP address or FQDN of the Domain Controller")
    parser.add_argument("-d", "--domain", help="Active Directory domain FQDN (e.g. corp.local)")
    parser.add_argument("-u", "--user", help="Username for authentication")
    parser.add_argument("-p", "--password", help="Password for authentication")
    parser.add_argument("--ssl", action="store_true", help="Use secure LDAPS (Port 636) instead of LDAP (Port 389)")
    parser.add_argument("-o", "--output", default="adcs_esc1_audit.json", help="Path to export JSON audit report (default: adcs_esc1_audit.json)")
    parser.add_argument("--demo", action="store_true", help="Run interactive demonstration mode with simulated ADCS templates")

    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    if not args.dc_ip or not args.domain or not args.user or not args.password:
        UI.warn("Missing connection parameters! Provide -dc, -d, -u, -p OR run with --demo.")
        parser.print_help()
        sys.exit(1)

    auditor = ADCSAuditor(args.dc_ip, args.domain, args.user, args.password, args.ssl)

    UI.section("AUTHENTICATION & LDAP HANDSHAKE")
    if not auditor.connect():
        sys.exit(1)

    UI.section("CERTIFICATE TEMPLATE DISCOVERY")
    raw_templates = auditor.query_templates()
    if not raw_templates:
        UI.warn("No certificate templates found or insufficient query permissions.")
        sys.exit(0)

    findings = []
    UI.section("SECURITY ANALYSIS & BITWISE CHECKS")

    for entry in raw_templates:
        try:
            name = str(entry.cn.value)
            display = str(entry.displayName.value) if 'displayName' in entry else name
            name_flag = int(entry['msPKI-Certificate-Name-Flag'].value) if 'msPKI-Certificate-Name-Flag' in entry and entry['msPKI-Certificate-Name-Flag'].value else 0
            enroll_flag = int(entry['msPKI-Enrollment-Flag'].value) if 'msPKI-Enrollment-Flag' in entry and entry['msPKI-Enrollment-Flag'].value else 0
            ekus = entry['pKIExtendedKeyUsage'].value if 'pKIExtendedKeyUsage' in entry else []

            res = auditor.analyze_template(name, display, name_flag, enroll_flag, ekus)
            findings.append(res)

            if res["is_vulnerable"]:
                auditor.vulnerable_count += 1
                UI.card(
                    f"Template: {res['name']} ({res['display_name']})",
                    [
                        ("Vulnerability Class", "ADCS ESC1 (Critical Privilege Escalation)"),
                        ("Subject Flag", f"{res['name_flag']} (ENROLLEE_SUPPLIES_SUBJECT)"),
                        ("Manager Approval", "FALSE (Immediate issuance without approval)"),
                        ("Extended Key Usage", ", ".join(res['ekus'])),
                        ("Privilege Escalation", "Standard User ──► DOMAIN ADMINISTRATOR"),
                        ("Remediation", "Uncheck 'Supply in the request' in CA Template console")
                    ],
                    is_vulnerable=True
                )
            else:
                auditor.safe_count += 1
                print(f"  {UI.C_OK}[✔ SAFE]{UI.C_RESET} {res['name']:<24} {UI.C_DIM}│ Flag: {res['name_flag']:<10} │ EKUs: {', '.join(res['ekus']) or 'None'}{UI.C_RESET}")

        except Exception as e:
            UI.warn(f"Failed to parse template: {str(e)}")

    display_summary(auditor.vulnerable_count, auditor.safe_count, findings, args.output)


if __name__ == "__main__":
    main()
