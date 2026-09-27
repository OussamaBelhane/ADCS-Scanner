#!/usr/bin/env python3
"""
ADCS ESC1 Vulnerability Scanner & Active Directory Auditor
Author: Oussama Belhane
Description: Interactive Active Directory & ADCS security audit console.
             Allows security engineers to audit certificate templates (ESC1),
             enumerate domain accounts, and map privilege escalation paths.
"""

import sys
import os
import argparse
import json
import struct
import uuid
from datetime import datetime
from ldap3 import Server, Connection, NTLM, SUBTREE
from ldap3.protocol.microsoft import security_descriptor_control
from colorama import init, Fore, Style

# Ensure UTF-8 output on Windows terminals
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

init(autoreset=True)

CONFIG_FILE = "targets.json"

# -------------------------------------------------------------------------
# ADCS ESC1 & Windows Security Constants (MS-CRTD & MS-DTYP specifications)
# -------------------------------------------------------------------------
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002

# Extended Right GUID for Certificate-Enrollment in Active Directory
CERT_ENROLLMENT_EXTENDED_RIGHT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
CERT_AUTOENROLLMENT_EXTENDED_RIGHT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

WELL_KNOWN_SIDS = {
    "S-1-5-11": "Authenticated Users",
    "S-1-1-0": "Everyone",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-18": "Local System",
}

UNPRIVILEGED_SIDS = ["S-1-5-11", "S-1-1-0", "S-1-5-32-545"]

CLIENT_AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "2.5.29.37.0": "Any Purpose (Wildcard)",
}


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + """
╔═════════════════════════════════════════════════════════════════════╗
║     🛡️  ADCS ESC1 Vulnerability Scanner & Directory Auditor         ║
║     Author: Oussama Belhane | PFE Engineering Portfolio             ║
╚═════════════════════════════════════════════════════════════════════╝""" + Style.RESET_ALL)


def get_base_dn(domain):
    return ",".join([f"DC={part}" for part in domain.split(".")])


# -------------------------------------------------------------------------
# 💾 Target Profile Management
# -------------------------------------------------------------------------

def load_saved_targets():
    if not os.path.exists(CONFIG_FILE):
        return []
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_target(target):
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


# -------------------------------------------------------------------------
# 🔍 Active Directory LDAP Operations
# -------------------------------------------------------------------------

def connect_ldap(dc_ip, domain, username, password, use_ssl=False):
    port = 636 if use_ssl else 389
    user_principal = f"{domain}\\{username}"

    print(f"[*] Connecting to {dc_ip}:{port} as {user_principal}...")
    server = Server(dc_ip, port=port, use_ssl=use_ssl)
    conn = Connection(server, user=user_principal, password=password, authentication=NTLM)

    if not conn.bind():
        print(Fore.RED + f"[-] Authentication failed: {conn.result.get('description', 'Unknown error')}")
        sys.exit(1)

    print(Fore.GREEN + f"[+] Authentication successful!\n")
    return conn


def get_published_templates(conn, domain):
    base_dn = get_base_dn(domain)
    ca_dn = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}"

    conn.search(
        search_base=ca_dn,
        search_filter="(objectClass=pKIEnrollmentService)",
        search_scope=SUBTREE,
        attributes=['cn', 'certificateTemplates']
    )

    published = {}
    for ca_entry in conn.entries:
        ca_name = str(ca_entry.cn.value)
        templates_on_ca = ca_entry.certificateTemplates.values if 'certificateTemplates' in ca_entry else []
        for t in templates_on_ca:
            template_name = str(t)
            if template_name not in published:
                published[template_name] = []
            published[template_name].append(ca_name)

    return published, len(conn.entries)


# -------------------------------------------------------------------------
# 🛡️ Low-Level Windows DACL & Security Descriptor Engine (MS-DTYP)
# -------------------------------------------------------------------------

def parse_sid(data, offset):
    """Parses binary Windows SID structure into standard S-R-I-S-S string format."""
    rev, sub_count = struct.unpack_from('<BB', data, offset)
    id_auth = int.from_bytes(data[offset+2:offset+8], byteorder='big')
    sub_auths = [struct.unpack_from('<I', data, offset+8+i*4)[0] for i in range(sub_count)]
    sid_str = f"S-{rev}-{id_auth}" + "".join(f"-{sa}" for sa in sub_auths)
    sid_len = 8 + sub_count * 4
    return sid_str, sid_len


def resolve_sid_name(sid_str):
    """Maps well-known and domain-relative SIDs to human-readable security principal names."""
    if sid_str in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid_str]
    parts = sid_str.split("-")
    if len(parts) >= 8:
        rid = parts[-1]
        rid_map = {
            "513": "Domain Users",
            "515": "Domain Computers",
            "512": "Domain Admins",
            "519": "Enterprise Admins",
            "500": "Administrator",
            "518": "Schema Admins"
        }
        if rid in rid_map:
            return rid_map[rid]
    return sid_str


def is_unprivileged_principal(sid_str):
    """Returns True if the SID represents an unprivileged identity (Domain Users, Authenticated Users, Everyone)."""
    if sid_str in UNPRIVILEGED_SIDS:
        return True
    parts = sid_str.split("-")
    if len(parts) >= 8 and parts[-1] in ["513", "515"]:
        return True
    return False


def parse_dacl_enrollees(sd_bytes):
    """
    Parses raw binary Security Descriptor (MS-DTYP specifications).
    Inspects Access Control Entries (ACEs) to identify principals granted
    Certificate-Enrollment extended right (0e10c968-78fb-11d2-90d4-00c04f79dc55)
    or Full Control on the Certificate Template object.
    """
    if not sd_bytes:
        return {"enrollees": [], "has_unprivileged": False}
    try:
        rev, sbz1, control, off_owner, off_group, off_sacl, off_dacl = struct.unpack_from('<BBHIIII', sd_bytes, 0)
        if off_dacl == 0 or off_dacl >= len(sd_bytes):
            return {"enrollees": [], "has_unprivileged": False}

        acl_rev, acl_sbz1, acl_size, ace_count, acl_sbz2 = struct.unpack_from('<BBHHH', sd_bytes, off_dacl)
        curr_offset = off_dacl + 8
        enrollees = []
        has_unprivileged = False
        seen_sids = set()

        for _ in range(ace_count):
            if curr_offset + 4 > len(sd_bytes):
                break
            ace_type, ace_flags, ace_size = struct.unpack_from('<BBH', sd_bytes, curr_offset)
            ace_data = sd_bytes[curr_offset:curr_offset+ace_size]

            can_enroll = False
            sid = None

            if ace_type == 0x05:  # ACCESS_ALLOWED_OBJECT_ACE
                mask, flags = struct.unpack_from('<II', ace_data, 4)
                pos = 12
                obj_guid = None
                if flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                    raw_guid = ace_data[pos:pos+16]
                    obj_guid = str(uuid.UUID(bytes_le=raw_guid))
                    pos += 16
                if flags & 0x02:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                    pos += 16
                sid, _ = parse_sid(ace_data, pos)

                # Granted Certificate-Enrollment right or all extended control access
                if obj_guid == CERT_ENROLLMENT_EXTENDED_RIGHT or (mask & 0x100 and not (flags & 0x01)):
                    can_enroll = True

            elif ace_type == 0x00:  # ACCESS_ALLOWED_ACE
                mask = struct.unpack_from('<I', ace_data, 4)[0]
                # Standard enrollment access or Full Control
                if (mask & 0x100) or ((mask & 0xF00FF) == 0xF00FF) or (mask & 0x10000000):
                    sid, _ = parse_sid(ace_data, 8)
                    can_enroll = True

            if can_enroll and sid and sid not in seen_sids:
                seen_sids.add(sid)
                friendly = resolve_sid_name(sid)
                is_unpriv = is_unprivileged_principal(sid)
                if is_unpriv:
                    has_unprivileged = True
                enrollees.append({
                    "sid": sid,
                    "name": friendly,
                    "is_unprivileged": is_unpriv
                })

            curr_offset += ace_size

        return {
            "enrollees": enrollees,
            "has_unprivileged": has_unprivileged
        }
    except Exception:
        return {"enrollees": [], "has_unprivileged": False}


def get_certificate_templates(conn, domain):
    base_dn = get_base_dn(domain)
    templates_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}"

    attributes = [
        'cn', 'displayName', 'msPKI-Certificate-Name-Flag',
        'msPKI-Enrollment-Flag', 'pKIExtendedKeyUsage', 'nTSecurityDescriptor'
    ]

    # DACL_SECURITY_INFORMATION = 0x4
    controls = security_descriptor_control(sdflags=0x4)

    conn.search(
        search_base=templates_dn,
        search_filter="(objectClass=pKICertificateTemplate)",
        search_scope=SUBTREE,
        attributes=attributes,
        controls=controls
    )

    return conn.entries


def get_domain_users(conn, domain):
    base_dn = get_base_dn(domain)
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectCategory=person)(objectClass=user))",
        search_scope=SUBTREE,
        attributes=['sAMAccountName', 'displayName', 'description', 'adminCount']
    )

    admins = []
    regular_users = []

    for entry in conn.entries:
        u_name = str(entry.sAMAccountName.value)
        display = str(entry.displayName.value) if 'displayName' in entry else "N/A"
        desc = str(entry.description.value) if 'description' in entry else ""
        is_admin = bool(getattr(entry, 'adminCount', None) and entry.adminCount.value == 1)

        user_info = {
            "username": u_name,
            "displayName": display,
            "description": desc,
            "is_admin": is_admin
        }
        if is_admin:
            admins.append(user_info)
        else:
            regular_users.append(user_info)

    return admins, regular_users


def check_esc1(entry):
    name = str(entry.cn.value)
    display_name = str(entry.displayName.value) if 'displayName' in entry else name

    name_flag = int(entry['msPKI-Certificate-Name-Flag'].value or 0) if 'msPKI-Certificate-Name-Flag' in entry else 0
    enroll_flag = int(entry['msPKI-Enrollment-Flag'].value or 0) if 'msPKI-Enrollment-Flag' in entry else 0

    ekus = entry['pKIExtendedKeyUsage'].value if 'pKIExtendedKeyUsage' in entry else []
    if isinstance(ekus, str):
        ekus = [ekus]
    elif not ekus:
        ekus = []

    supplies_san = bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
    manager_approval = bool(enroll_flag & CT_FLAG_PEND_ALL_REQUESTS)
    auth_ekus = [CLIENT_AUTH_EKUS[oid] for oid in ekus if oid in CLIENT_AUTH_EKUS]

    if not ekus and supplies_san:
        auth_ekus.append("All Purposes (Wildcard/SubCA)")

    # Parse low-level DACL Security Descriptor
    raw_sd = entry['nTSecurityDescriptor'].raw_values[0] if ('nTSecurityDescriptor' in entry and entry['nTSecurityDescriptor'].raw_values) else None
    dacl_info = parse_dacl_enrollees(raw_sd)
    enrollees = [e['name'] for e in dacl_info['enrollees']]
    has_unprivileged_enroll = dacl_info['has_unprivileged']

    # Vulnerability definition:
    # 1. Enrollee Supplies SAN
    # 2. Client Authentication EKU present
    # 3. Manager approval false
    is_vulnerable = supplies_san and (len(auth_ekus) > 0) and (not manager_approval)
    is_unprivileged_exploitable = is_vulnerable and has_unprivileged_enroll

    return {
        "name": name,
        "display_name": display_name,
        "name_flag": hex(name_flag),
        "name_flag_raw": name_flag,
        "enroll_flag_raw": enroll_flag,
        "supplies_san": supplies_san,
        "manager_approval": manager_approval,
        "auth_ekus": auth_ekus,
        "enrollees": enrollees,
        "has_unprivileged_enroll": has_unprivileged_enroll,
        "is_vulnerable": is_vulnerable,
        "is_unprivileged_exploitable": is_unprivileged_exploitable
    }


# -------------------------------------------------------------------------
# 🎯 Action Modules
# -------------------------------------------------------------------------

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


# -------------------------------------------------------------------------
# 🛠️ Automated Remediation & Executive Reporting Engines
# -------------------------------------------------------------------------

def generate_remediation_script(active_vulns, domain, output_file="remediate_esc1.ps1"):
    """
    Generates a production-ready, safety-checked PowerShell script
    for Active Directory administrators to remediate detected ESC1 vulnerabilities.
    """
    if not active_vulns:
        print(Fore.YELLOW + "[*] No active ESC1 vulnerabilities to remediate.")
        return None

    lines = [
        "<#",
        "=" * 80,
        " Active Directory Certificate Services (AD CS) ESC1 Automated Remediation Script",
        f" Target Domain : {domain}",
        f" Generated On  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        " Generated By  : ADCS ESC1 Vulnerability Scanner (Author: Oussama Belhane)",
        " MITRE ATT&CK  : T1649 - Steal or Forge Authentication Certificates",
        "=" * 80,
        " INSTRUCTIONS:",
        " 1. Execute this script with Domain Admin privileges on a DC or host with RSAT.",
        " 2. Automatic XML backups are created before any changes are applied.",
        " 3. The script strips CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x1) to prevent SAN spoofing.",
        "=" * 80,
        "#>",
        "",
        "#Requires -RunAsAdministrator",
        "",
        "Import-Module ActiveDirectory -ErrorAction Stop",
        "",
        "$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'",
        "$backupDir = Join-Path $PWD \"ADCS_Remediation_Backup_$timestamp\"",
        "New-Item -ItemType Directory -Path $backupDir -Force | Out-Null",
        f"Write-Host \"[*] AD CS ESC1 Remediation started for: {domain}\" -ForegroundColor Cyan",
        "Write-Host \"[*] Automated backups will be saved to: $backupDir`n\" -ForegroundColor Yellow",
        "",
        "$configDN = (Get-ADRootDSE).configurationNamingContext",
        "$templatesBase = \"CN=Certificate Templates,CN=Public Key Services,CN=Services,$configDN\"",
        ""
    ]

    for vuln in active_vulns:
        name = vuln["name"]
        display = vuln.get("display_name", name)
        lines.extend([
            f"# -------------------------------------------------------------------------",
            f"# Remediation for Vulnerable Template: {name} ('{display}')",
            f"# -------------------------------------------------------------------------",
            f"Write-Host \"[*] Hardening template: {name}...\" -ForegroundColor Cyan",
            f"$targetDN = \"CN={name},$templatesBase\"",
            f"$obj = Get-ADObject -Identity $targetDN -Properties 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag'",
            f"if ($obj) {{",
            f"    # Step 1: Export backup prior to modification",
            f"    $backupFile = Join-Path $backupDir \"{name}_backup.clixml\"",
            f"    $obj | Export-Clixml -Path $backupFile",
            f"    Write-Host \"  ├── [BACKUP] Saved existing object to $backupFile\" -ForegroundColor Gray",
            f"",
            f"    # Step 2: Clear CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x00000001)",
            f"    $curFlag = [int]($obj.'msPKI-Certificate-Name-Flag')",
            f"    $newFlag = $curFlag -band (-bnot 0x1)",
            f"    Set-ADObject -Identity $targetDN -Replace @{{'msPKI-Certificate-Name-Flag' = $newFlag}}",
            f"    Write-Host \"  ├── [REMEDIATED] Removed Enrollee Supplies SAN flag.\" -ForegroundColor Green",
            f"    Write-Host \"  │   Flag Transition: 0x$($curFlag.ToString('X8')) -> 0x$($newFlag.ToString('X8'))\" -ForegroundColor DarkGreen",
            f"",
            f"    # Step 3: Verification",
            f"    $verifiedObj = Get-ADObject -Identity $targetDN -Properties 'msPKI-Certificate-Name-Flag'",
            f"    $verifiedFlag = [int]($verifiedObj.'msPKI-Certificate-Name-Flag')",
            f"    if (($verifiedFlag -band 0x1) -eq 0) {{",
            f"        Write-Host \"  └── [VERIFIED] Template {name} is now secure against ESC1!\" -ForegroundColor Green",
            f"    }} else {{",
            f"        Write-Host \"  └── [WARNING] Verification failed for {name}. Check permissions!\" -ForegroundColor Red",
            f"    }}",
            f"}}",
            ""
        ])

    lines.extend([
        "Write-Host \"[✔] All remediation actions applied. Active Directory replication initiated.\" -ForegroundColor Green",
        "Write-Host \"[*] To apply immediately on CA hosts, optionally run: Restart-Service CertSvc`n\" -ForegroundColor Yellow"
    ])

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(Fore.GREEN + Style.BRIGHT + f"[+] Hardened PowerShell remediation script generated: {output_file}")
    return output_file


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


def export_bloodhound_graph(active_vulns, domain, dc_ip, output_json="adcs_bloodhound.json", output_cypher="adcs_attack_path.cypher"):
    """
    Exports BloodHound-compatible JSON graph data and Neo4j Cypher queries.
    Maps relationship edges: (Group) -[CanEnroll]-> (Template) -[PublishedTo]-> (CA)
    and (Template) -[Abuse_ESC1_PKINIT]-> (Domain Admins).
    """
    domain_upper = domain.upper()
    nodes = []
    edges = []
    seen_nodes = set()

    def add_node(node_id, label, props):
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({"id": node_id, "label": label, "properties": props})

    # High-value Target Node
    da_id = f"DOMAIN ADMINS@{domain_upper}"
    add_node(da_id, "Group", {"name": "Domain Admins", "highvalue": True, "domain": domain_upper})

    # DC Node
    dc_node_id = f"DC@{domain_upper}"
    add_node(dc_node_id, "Computer", {"name": f"DC ({dc_ip})", "domain": domain_upper})

    for v in active_vulns:
        t_name = v["name"]
        t_id = f"{t_name.upper()}@{domain_upper}"
        add_node(t_id, "CertTemplate", {
            "name": t_name,
            "displayname": v.get("display_name", t_name),
            "enrolleesuppliessubject": v.get("supplies_san", True),
            "requiresmanagerapproval": v.get("manager_approval", False),
            "domain": domain_upper,
            "published": True
        })

        # CA publication edges
        for ca in v.get("published_cas", []):
            ca_id = f"{ca.upper()}@{domain_upper}"
            add_node(ca_id, "EnterpriseCA", {"name": ca, "domain": domain_upper})
            edges.append({
                "source": t_id,
                "target": ca_id,
                "relationship": "PublishedTo"
            })

        # Enrollment rights edges from DACL
        enrollees = v.get("enrollees", ["Domain Users"])
        for enrollee in enrollees:
            enrollee_id = f"{enrollee.upper()}@{domain_upper}"
            add_node(enrollee_id, "Group", {"name": enrollee, "domain": domain_upper})
            edges.append({
                "source": enrollee_id,
                "target": t_id,
                "relationship": "CanEnroll"
            })

        # Privilege escalation edge to Domain Admins
        if v.get("has_unprivileged_enroll", True):
            edges.append({
                "source": t_id,
                "target": da_id,
                "relationship": "Abuse_ESC1_PKINIT",
                "properties": {
                    "technique": "MITRE T1649",
                    "impact": "Domain Administrator Takeover",
                    "vector": "Kerberos PKINIT SAN Impersonation"
                }
            })

    bloodhound_data = {
        "meta": {
            "methods": 0,
            "type": "adcs",
            "count": len(active_vulns),
            "version": 5
        },
        "graph": {
            "nodes": nodes,
            "edges": edges
        }
    }

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(bloodhound_data, f, indent=4)
    print(Fore.GREEN + Style.BRIGHT + f"[+] BloodHound graph artifact exported: {output_json}")

    cypher_queries = [
        "// ===================================================================",
        "// BloodHound / Neo4j Cypher Queries for AD CS ESC1 Attack Paths",
        f"// Target Domain: {domain}",
        "// ===================================================================",
        "",
        "// Query 1: Find all unprivileged groups with CanEnroll permissions to ESC1 templates",
        "MATCH p=(g:Group)-[:CanEnroll]->(t:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)",
        "WHERE t.enrolleesuppliessubject = true AND t.requiresmanagerapproval = false",
        "RETURN p;",
        "",
        "// Query 2: Map the complete privilege escalation path from user to Domain Admin",
        f"MATCH (g:Group)-[:CanEnroll]->(t:CertTemplate)-[:Abuse_ESC1_PKINIT]->(da:Group {{name: 'Domain Admins'}})",
        "RETURN g, t, da;",
        ""
    ]

    with open(output_cypher, "w", encoding="utf-8") as f:
        f.write("\n".join(cypher_queries))
    print(Fore.GREEN + Style.BRIGHT + f"[+] BloodHound Cypher queries exported: {output_cypher}")

    return output_json, output_cypher


# -------------------------------------------------------------------------
# 🚀 Interactive Menu & Main Loop
# -------------------------------------------------------------------------

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

