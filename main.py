#!/usr/bin/env python3
"""
ADCS ESC1 Vulnerability Scanner & Active Directory Auditor
Modular Architecture Entry Point
Author: Oussama Belhane | PFE Engineering Portfolio
"""

import sys
import argparse
import json
from datetime import datetime
from colorama import init, Fore, Style

# Core modules
from core.ldap_client import connect_ldap
from ui.console import (
    print_banner,
    select_target_menu,
    action_list_users,
    action_audit_esc1
)
from reports.html_reporter import generate_html_report
from reports.bloodhound_exporter import export_bloodhound_graph
from reports.remediator import generate_remediation_script

# Ensure UTF-8 output on Windows terminals
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

init(autoreset=True)


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Audit ADCS Certificate Templates for ESC1 Vulnerabilities")
    parser.add_argument("-dc", "--dc-ip", help="Domain Controller IP or hostname")
    parser.add_argument("-d", "--domain", help="Domain FQDN (e.g. invictus.local)")
    parser.add_argument("-u", "--user", help="Username")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument("--ssl", action="store_true", help="Use LDAPS (Port 636)")
    parser.add_argument("--list-users", action="store_true", help="Enumerate domain users and highlight Admin targets")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print all safe templates")
    parser.add_argument("-o", "--output", default="adcs_esc1_report.json", help="JSON report output file")
    parser.add_argument("--html", default="adcs_esc1_report.html", help="HTML executive report output file")
    parser.add_argument("--fix", "--generate-fix", dest="fix", action="store_true", help="Generate PowerShell remediation script")
    parser.add_argument("--fix-file", default="remediate_esc1.ps1", help="PowerShell remediation script filename")
    parser.add_argument("--bloodhound", default="adcs_bloodhound.json", help="Export BloodHound graph JSON")
    parser.add_argument("--cypher", default="adcs_attack_path.cypher", help="Export Neo4j Cypher queries")

    args = parser.parse_args()

    # CLI mode (if parameters supplied)
    if args.dc_ip and args.domain and args.user and args.password:
        conn = connect_ldap(args.dc_ip, args.domain, args.user, args.password, args.ssl)
        admins, regulars = [], []
        if args.list_users:
            admins, regulars = action_list_users(conn, args.domain)
        active, inactive, safe = action_audit_esc1(conn, args.domain, args.verbose, args.output)

        if args.html:
            generate_html_report(args.domain, args.dc_ip, admins, regulars, active, inactive, safe, args.html)
        if args.fix:
            generate_remediation_script(active, args.domain, args.fix_file)
        if args.bloodhound:
            export_bloodhound_graph(active, args.domain, args.dc_ip, args.bloodhound, args.cypher)
        return

    # Interactive Mode
    target = select_target_menu()
    dc_ip = target["dc_ip"]
    domain = target["domain"]
    user = target["user"]
    password = target["password"]
    use_ssl = target.get("ssl", False)

    conn = connect_ldap(dc_ip, domain, user, password, use_ssl)

    last_admins = []
    last_regulars = []
    last_active = []
    last_inactive = []
    last_safe = []

    while True:
        print(Fore.CYAN + Style.BRIGHT + "\n[📋 ACTION MENU] - Connected as: " + Fore.WHITE + f"{domain}\\{user}")
        print(f"  [{Fore.GREEN}1{Style.RESET_ALL}] List Domain Users (Admin Targets & Passwords in Descriptions)")
        print(f"  [{Fore.GREEN}2{Style.RESET_ALL}] Audit Certificate Templates (ESC1 with DACL Enrollment Rights)")
        print(f"  [{Fore.GREEN}3{Style.RESET_ALL}] Full Comprehensive Audit (Users + Templates + HTML + BloodHound)")
        print(f"  [{Fore.YELLOW}4{Style.RESET_ALL}] Generate Hardened PowerShell Remediation Script (remediate_esc1.ps1)")
        print(f"  [{Fore.CYAN}5{Style.RESET_ALL}] Export BloodHound Graph & Cypher Queries (adcs_bloodhound.json)")
        print(f"  [{Fore.MAGENTA}6{Style.RESET_ALL}] Switch Target / Connect to Another Machine")
        print(f"  [{Fore.RED}0{Style.RESET_ALL}] Exit Console\n")

        choice = input(Fore.WHITE + Style.BRIGHT + "Select an action [0-6]: ").strip()

        if choice == "1":
            last_admins, last_regulars = action_list_users(conn, domain)
        elif choice == "2":
            last_active, last_inactive, last_safe = action_audit_esc1(conn, domain, args.verbose, args.output)
        elif choice == "3":
            last_admins, last_regulars = action_list_users(conn, domain)
            last_active, last_inactive, last_safe = action_audit_esc1(conn, domain, args.verbose, args.output)

            report_data = {
                "timestamp": datetime.now().isoformat(),
                "target_dc": dc_ip,
                "domain": domain,
                "total_users": len(last_admins) + len(last_regulars),
                "admin_users": last_admins,
                "active_esc1_count": len(last_active),
                "active_vulnerabilities": last_active,
                "inactive_vulnerabilities": last_inactive
            }
            with open(args.output, "w") as f:
                json.dump(report_data, f, indent=4)
            print(Fore.GREEN + f"[+] Comprehensive JSON report saved to: {args.output}")

            generate_html_report(domain, dc_ip, last_admins, last_regulars, last_active, last_inactive, last_safe, args.html)
            export_bloodhound_graph(last_active, domain, dc_ip, args.bloodhound, args.cypher)
            if last_active:
                generate_remediation_script(last_active, domain, args.fix_file)
            print("")
        elif choice == "4":
            if not last_active:
                print(Fore.YELLOW + "[*] Running ESC1 audit first to detect vulnerable templates...")
                last_active, last_inactive, last_safe = action_audit_esc1(conn, domain, args.verbose, args.output)
            generate_remediation_script(last_active, domain, args.fix_file)
        elif choice == "5":
            if not last_active:
                print(Fore.YELLOW + "[*] Running ESC1 audit first to detect vulnerable templates...")
                last_active, last_inactive, last_safe = action_audit_esc1(conn, domain, args.verbose, args.output)
            export_bloodhound_graph(last_active, domain, dc_ip, args.bloodhound, args.cypher)
        elif choice == "6":
            target = select_target_menu()
            dc_ip, domain, user, password = target["dc_ip"], target["domain"], target["user"], target["password"]
            use_ssl = target.get("ssl", False)
            conn = connect_ldap(dc_ip, domain, user, password, use_ssl)
            last_admins, last_regulars, last_active, last_inactive, last_safe = [], [], [], [], []
        elif choice in ["0", "q", "exit"]:
            print(Fore.CYAN + "\n[*] Exiting ADCS Scanner. Goodbye!\n")
            break
        else:
            print(Fore.RED + "[-] Invalid selection. Choose 0, 1, 2, 3, 4, 5, or 6.")


if __name__ == "__main__":
    main()
