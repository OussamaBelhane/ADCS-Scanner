"""
Interactive Terminal UI & Console Formatter
Handles banners, target profile management, and formatted result tables.
"""

import os
import json
from colorama import Fore, Style
from core.constants import CONFIG_FILE
from core.ldap_client import get_domain_users, get_published_templates, get_certificate_templates
from core.engine import check_esc1


def print_banner():
    """Prints the formatted ASCII banner."""
    print(Fore.CYAN + Style.BRIGHT + """
╔═════════════════════════════════════════════════════════════════════╗
║     🛡️  ADCS ESC1 Vulnerability Scanner & Directory Auditor         ║
║     Author: Oussama Belhane | PFE Engineering Portfolio             ║
╚═════════════════════════════════════════════════════════════════════╝""" + Style.RESET_ALL)


def load_saved_targets():
    """Loads saved targets from targets.json."""
    if not os.path.exists(CONFIG_FILE):
        return []
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_target(target):
    """Saves or updates a target in targets.json."""
    targets = load_saved_targets()
    for existing in targets:
        if existing["dc_ip"] == target["dc_ip"] and existing["user"] == target["user"]:
            existing.update(target)
            break
    else:
        targets.append(target)

    with open(CONFIG_FILE, "w") as f:
        json.dump(targets, f, indent=4)
    print(Fore.GREEN + f"[+] Profile saved to {CONFIG_FILE}\n")


def select_target_menu():
    """Interactive CLI menu to select or create target profiles."""
    saved_targets = load_saved_targets()

    if saved_targets:
        print(Fore.YELLOW + "\n[*] Saved Targets Detected:")
        for idx, t in enumerate(saved_targets, 1):
            print(f"    [{idx}] {Fore.CYAN}{t['domain']}{Style.RESET_ALL} (DC: {t['dc_ip']} | User: {t['user']})")
        print(f"    [{Fore.MAGENTA}N{Style.RESET_ALL}] Add a New Target Profile\n")

        choice = input(Fore.WHITE + Style.BRIGHT + f"Select target [1-{len(saved_targets)} or N]: ").strip()

        if choice.isdigit() and 1 <= int(choice) <= len(saved_targets):
            selected = saved_targets[int(choice) - 1]
            print(Fore.GREEN + f"[+] Loaded profile for {selected['domain']}!\n")
            return selected

    print(Fore.MAGENTA + Style.BRIGHT + "\n[*] Configure Target Connection:")
    dc_ip = input("  ├── Domain Controller IP / Hostname : ").strip()
    domain = input("  ├── Domain Name (e.g. invictus.local): ").strip()
    user = input("  ├── Username (e.g. john)            : ").strip()
    password = input("  ├── Password                        : ").strip()
    ssl_choice = input("  ├── Use LDAPS (Port 636)? [y/N]     : ").strip().lower()

    new_target = {
        "dc_ip": dc_ip,
        "domain": domain,
        "user": user,
        "password": password,
        "ssl": ssl_choice in ["y", "yes"]
    }

    save_target(new_target)
    return new_target


def action_list_users(conn, domain):
    """Module: Enumerate Domain Users & Privileged Targets"""
    print(Fore.CYAN + "\n" + "═" * 70)
    print(Fore.CYAN + f" 👥 ACTIVE DIRECTORY USER ENUMERATION ({domain})")
    print(Fore.CYAN + "═" * 70)

    admins, regulars = get_domain_users(conn, domain)

    print(Fore.RED + Style.BRIGHT + f"\n[👑 High-Privilege Admin Accounts ({len(admins)})] - Primary Impersonation Targets:")
    for adm in admins:
        desc_str = f" | Desc: {adm['description']}" if adm['description'] else ""
        print(Fore.RED + f"  • {adm['username']:<22} ({adm['displayName']}){desc_str}")

    print(Fore.WHITE + Style.BRIGHT + f"\n[👤 Standard Domain Users ({len(regulars)})] - Low-Privilege Enrollees:")
    for reg in regulars:
        desc_str = f" | {Fore.YELLOW}Desc: {reg['description']}{Fore.WHITE}" if reg['description'] else ""
        print(f"  • {reg['username']:<22} ({reg['displayName']}){desc_str}")

    print(Fore.GREEN + f"\n[+] Total Accounts Found: {len(admins) + len(regulars)} ({len(admins)} Admins, {len(regulars)} Standard)\n")
    return admins, regulars


def action_audit_esc1(conn, domain, verbose=False, output_file="adcs_esc1_report.json"):
    """Module: Audit Certificate Templates for ESC1"""
    print(f"\n[*] Querying active Certification Authorities and schema templates...")
    published_map, ca_count = get_published_templates(conn, domain)
    templates = get_certificate_templates(conn, domain)

    print(f"[+] Found {ca_count} active CA(s) publishing {len(published_map)} enabled templates.")
    print(f"[+] Found {len(templates)} total schema templates.\n")

    active_vulns = []
    inactive_vulns = []
    safe_templates = []

    for entry in templates:
        result = check_esc1(entry)
        t_name = result["name"]
        is_published = t_name in published_map

        if result["is_vulnerable"]:
            result["is_published"] = is_published
            result["published_cas"] = published_map.get(t_name, [])
            if is_published:
                active_vulns.append(result)
            else:
                inactive_vulns.append(result)
        else:
            safe_templates.append(result)

    # 1. Critical Findings
    print(Fore.RED + Style.BRIGHT + "═" * 70)
    print(Fore.RED + Style.BRIGHT + f" 🚨 ACTIVE EXPLOITABLE VULNERABILITIES (ESC1): {len(active_vulns)}")
    print(Fore.RED + Style.BRIGHT + "═" * 70 + Style.RESET_ALL)

    if active_vulns:
        for v in active_vulns:
            enrollees_str = ", ".join(v.get("enrollees", [])) if v.get("enrollees") else "No enrollment rights detected"
            is_unpriv = v.get("has_unprivileged_enroll", False)

            if is_unpriv:
                dacl_perm_str = Fore.RED + Style.BRIGHT + f"{enrollees_str} (UNPRIVILEGED ENROLLEES)"
                impact_str = Fore.YELLOW + Style.BRIGHT + "Standard User ──► DOMAIN ADMINISTRATOR via PKINIT"
                badge = Fore.RED + Style.BRIGHT + "[CRITICAL ESC1 EXPLOIT]"
            else:
                dacl_perm_str = Fore.YELLOW + f"{enrollees_str} (ADMINS ONLY)"
                impact_str = Fore.WHITE + "Administrative template (Low escalation risk, but misconfigured SAN)"
                badge = Fore.YELLOW + "[HIGH / ELEVATED (Admin Restricted)]"

            print(f"\n  {Fore.RED}┌── Template : {Style.BRIGHT}{v['name']}{Style.RESET_ALL} ({v['display_name']}) {badge}")
            print(f"  {Fore.RED}├── Published: {Fore.WHITE}{', '.join(v['published_cas'])}")
            print(f"  {Fore.RED}├── Flaw     : {Fore.WHITE}Enrollee Supplies SAN ({v['name_flag']}) | Approval: False")
            print(f"  {Fore.RED}├── EKU Auth : {Fore.WHITE}{', '.join(v['auth_ekus'])}")
            print(f"  {Fore.RED}├── DACL Perm: {dacl_perm_str}")
            print(f"  {Fore.RED}└── Impact   : {impact_str}")
    else:
        print(Fore.GREEN + "  [✔] No active published templates are vulnerable to ESC1.")

    # 2. Inactive Schema Warnings
    if inactive_vulns:
        print(Fore.YELLOW + "\n" + "-" * 70)
        print(Fore.YELLOW + f" ⚠️  INACTIVE SCHEMA TEMPLATES ({len(inactive_vulns)}) - Not Published on Any CA:")
        print(Fore.YELLOW + "-" * 70)
        for iv in inactive_vulns:
            print(f"  • {iv['name']:<25} (Misconfigured in schema, but dormant / not issued)")

    # 3. Safe Templates
    print(Fore.GREEN + "\n" + "-" * 70)
    print(Fore.GREEN + f" ✔  VERIFIED SAFE TEMPLATES: {len(safe_templates)}")
    print(Fore.GREEN + "-" * 70)
    if verbose:
        for s in safe_templates:
            print(f"  [✔] {s['name']:<30} (Flag: {s['name_flag']})")
    else:
        print(f"  [✔] {len(safe_templates)} templates verified safe. (Run with -v for verbose details).")

    # 4. Summary Card
    print("\n" + Fore.CYAN + Style.BRIGHT + "╔═════════════════════════════════════════════════════════════════════╗")
    print(f"║                     EXECUTIVE AUDIT SUMMARY                         ║")
    print("╠═════════════════════════════════════════════════════════════════════╣")
    print(f"║  Target Domain         : {domain:<42} ║")
    print(f"║  Total Schema Templates: {len(templates):<42} ║")
    print(f"║  Safe Templates        : {Fore.GREEN}{len(safe_templates):<42}{Fore.CYAN} ║")
    print(f"║  Inactive Schema Flaws : {Fore.YELLOW}{len(inactive_vulns):<42}{Fore.CYAN} ║")
    print(f"║  Active ESC1 Exploits  : {Fore.RED}{Style.BRIGHT}{len(active_vulns):<42}{Style.RESET_ALL}{Fore.CYAN} ║")
    risk_text = "🚨 CRITICAL RISK (P1)" if active_vulns else "🟢 LOW RISK"
    risk_color = Fore.RED if active_vulns else Fore.GREEN
    print(f"║  Domain Risk Level     : {risk_color}{Style.BRIGHT}{risk_text:<42}{Style.RESET_ALL}{Fore.CYAN} ║")
    print("╚═════════════════════════════════════════════════════════════════════╝" + Style.RESET_ALL)

    return active_vulns, inactive_vulns, safe_templates
