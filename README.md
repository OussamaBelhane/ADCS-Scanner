# 🛡️ ADCS ESC1 Vulnerability Scanner & PKI Auditor

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI Pipeline](https://github.com/OussamaBelhane/ADCS-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/OussamaBelhane/ADCS-Scanner/actions)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](Dockerfile)
[![Tests](https://img.shields.io/badge/Tests-Pytest%20Passing-brightgreen.svg)](tests/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1649-red.svg)](https://attack.mitre.org/techniques/T1649/)
[![Focus](https://img.shields.io/badge/Focus-Active%20Directory%20PKI%20Audit-purple.svg)]()

> A sleek, high-visibility Python command-line security auditor designed to detect **ADCS ESC1 (Active Directory Certificate Services Privilege Escalation)** misconfigurations across enterprise domains.

---

## 📺 Terminal Preview

```text
    ╔════════════════════════════════════════════════════════════════════════════╗
    ║   █████╗ ██████╗  ██████╗███████╗    ███████╗███████╗ ██████╗ ██╗        ║
    ║  ██╔══██╗██╔══██╗██╔════╝██╔════╝    ██╔════╝██╔════╝██╔════╝███║        ║
    ║  ███████║██║  ██║██║     ███████╗    █████╗  ███████╗██║     ╚██║        ║
    ║  ██╔══██║██║  ██║██║     ╚════██║    ██╔══╝  ╚════██║██║      ██║        ║
    ║  ██║  ██║██████╔╝╚██████╗███████║    ███████╗███████╗╚██████╗ ██║        ║
    ║  ╚═╝  ╚═╝╚═════╝  ╚═════╝╚══════╝    ╚══════╝╚══════╝ ╚═════╝ ╚═╝        ║
    ║          Active Directory Certificate Services Vulnerability Scanner      ║
    ╚════════════════════════════════════════════════════════════════════════════╝
    ► Developed by : Oussama Belhane (Cybersecurity Engineer)
    ► Focus Target : Misconfigured PKI Certificate Templates (ESC1 Abuse)
    ► Version      : 1.0.0-PROD | T1649 Defense & Audit

╔═[ AUTHENTICATION & LDAP HANDSHAKE ]════════════════════════════════════╗
  [*] Targeting Domain Controller : 192.168.10.10
  [*] Connecting to Active Directory : corp.local
  [*] Establishing LDAP session on port 389...
  [+] Authenticated successfully as: corp.local\jdoe

╔═[ CERTIFICATE TEMPLATE DISCOVERY ]═════════════════════════════════════╗
  [*] Querying PKI Certificate Container in AD Configuration partition...
  [+] Retrieved 18 Active Directory Certificate Templates.

╔═[ SECURITY ANALYSIS & BITWISE CHECKS ]═════════════════════════════════╗
  [✔ SAFE] User                     │ Flag: 0x0        │ EKUs: Client Authentication
  [✔ SAFE] Machine                  │ Flag: 0x0        │ EKUs: Client Authentication

  ┌────────────────────────────────────────────────────────────────────────┐
  │ Template: Corp-VPN-Certificate (Corporate Remote Access VPN) [ VULNERABLE: ESC1 ] │
  ├────────────────────────────────────────────────────────────────────────┤
  │  • Vulnerability Class        : ADCS ESC1 (Critical Privilege Escalation) │
  │  • Subject Flag               : 0x1 (ENROLLEE_SUPPLIES_SUBJECT)         │
  │  • Manager Approval           : FALSE (Immediate issuance without approval)│
  │  • Extended Key Usage         : Client Authentication, PKINIT Client Auth│
  │  • Privilege Escalation       : Standard User ──► DOMAIN ADMINISTRATOR   │
  │  • Remediation                : Uncheck 'Supply in the request' in CA   │
  └────────────────────────────────────────────────────────────────────────┘

╔═[ EXECUTIVE AUDIT SUMMARY & RISK RATING ]══════════════════════════════╗
  ┌─────────────────────────────────┬─────────────────────────────────┐
  │ METRIC SUMMARY                  │ VALUE                           │
  ├─────────────────────────────────┼─────────────────────────────────┤
  │ Total Templates Analyzed        │ 18                              │
  │ Safe / Non-Vulnerable Templates │ 17                              │
  │ Critical Vulnerabilities (ESC1) │ 1                               │
  │ Overall Domain Risk Level       │ 🚨 CRITICAL RISK (P1)           │
  └─────────────────────────────────┴─────────────────────────────────┘

  [🚨 CRITICAL] ACTION REQUIRED: High-risk misconfiguration allows unauthorized Domain Admin takeover!
  [+] Full audit report exported to JSON: adcs_audit_report.json
```

---

## ⚡ What is the ESC1 Vulnerability?

**Active Directory Certificate Services (ADCS)** issues cryptographic identity certificates. When a certificate template is configured with the following conditions, any low-privileged domain user can take over the entire domain:

1. **`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (`0x00000001`)**: The template allows the requester to supply their own Subject Alternative Name (SAN).
2. **Client Authentication EKU**: The certificate allows authentication to Active Directory (`Client Authentication`, `PKINIT`, or `Smart Card Logon`).
3. **No Manager Approval**: Certificates are issued instantly without administrative sign-off (`CT_FLAG_PEND_ALL_REQUESTS` is missing).
4. **Broad Enrollment Rights**: Regular `Domain Users` or `Authenticated Users` have enrollment permissions.

### The Attack Path (MITRE T1649):
```text
Low-Privilege User ──► Requests Cert (SAN: Administrator) ──► Obtains Valid Admin Cert ──► Requests Kerberos TGT (PKINIT) ──► FULL DOMAIN ADMIN
```

---

## ✨ Enterprise Engineering Features

- 🎮 **Interactive Security Console**: Menu-driven audit suite with persistent target profile management (`targets.json`).
- 🔍 **Zero-False-Positive CA Verification**: Cross-references schema templates (`CN=Certificate Templates`) against active Enterprise CAs (`CN=Enrollment Services`), completely eliminating false alarms on dormant templates.
- 🔐 **Low-Level Binary DACL Parsing (MS-DTYP)**: Directly unpacks raw Windows Security Descriptors (`nTSecurityDescriptor`) in pure Python. Inspects Access Control Entries (ACEs) for the **Certificate-Enrollment Extended Right GUID** (`0e10c968-78fb-11d2-90d4-00c04f79dc55`) to confirm whether unprivileged identities (`Domain Users`, `Authenticated Users`) actually have enrollment permissions.
- 🩸 **BloodHound & Neo4j Integration**: Exports attack graph models (`adcs_bloodhound.json`) and executable Cypher queries (`adcs_attack_path.cypher`) mapping `(Group) -[CanEnroll]-> (Template) -[Abuse_ESC1_PKINIT]-> (Domain Admins)`.
- 👥 **Domain Account Reconnaissance**: Enumerates directory accounts, flags high-value Domain Admin targets (`adminCount=1`), and highlights credential exposures in account descriptions.
- 🧮 **Bitwise MS-CRTD Flag Analysis**: Evaluates `msPKI-Certificate-Name-Flag` (`0x1`) and `msPKI-Enrollment-Flag` (`0x2`) against Microsoft specifications.
- 📊 **CISO Executive HTML Report**: Generates an executive-ready, modern dark-mode HTML assessment deliverable complete with attack chain visualization, risk scoring, and MITRE ATT&CK T1649 mapping.
- 🛡️ **Automated PowerShell Remediation Engine**: Generates a safety-checked, rollback-ready PowerShell script (`remediate_esc1.ps1`) with automatic `.clixml` backups that administrators can run to strip vulnerable flags.
- 📋 **Structured JSON Artifacts**: Exports complete machine-readable audit data (`adcs_esc1_report.json`) for SIEM, Splunk, or compliance ingestion.

---

## 🚀 Installation & Usage

### 1. Clone the Repository & Install Dependencies
```bash
git clone https://github.com/OussamaBelhane/ADCS-Scanner.git
cd ADCS-Scanner
pip install -r requirements.txt
```

### 2. Interactive Console Mode (Recommended)
Simply run the script with no arguments to launch the interactive audit console:
```bash
python adcs_esc1_scanner.py
```
From the interactive menu:
- `[1]` List Domain Users & Identify Admin Targets
- `[2]` Audit Certificate Templates (ESC1 with DACL Enrollment Rights)
- `[3]` Full Comprehensive Audit (Users + Templates + HTML + BloodHound)
- `[4]` Generate Hardened PowerShell Remediation Script (`remediate_esc1.ps1`)
- `[5]` Export BloodHound Graph & Cypher Queries (`adcs_bloodhound.json`)
- `[6]` Switch Target / Connect to Another Domain Controller

### 3. CLI Mode (Automation / CI/CD)
```bash
# Full audit with HTML report, BloodHound export, and automated remediation script generation
python adcs_esc1_scanner.py -dc 192.168.181.129 -d invictus.local -u john -p 'Password123!' --list-users --fix --html adcs_report.html --bloodhound adcs_bloodhound.json

# Secure LDAPS scan (Port 636)
python adcs_esc1_scanner.py -dc 192.168.181.129 -d invictus.local -u john -p 'Password123!' --ssl
```

### 4. Dockerized Execution
Run in an isolated container without local environment configuration:
```bash
# Build the container
docker build -t adcs-esc1-scanner .

# Run the audit
docker run --rm -it adcs-esc1-scanner -dc 192.168.181.129 -d invictus.local -u john -p 'Password123!'
```

### 5. Automated Unit Tests (QA Suite)
Run the built-in test suite to verify MS-CRTD bitwise logic and MS-DTYP DACL parsing:
```bash
pytest -v tests/
```

---

## 🛡️ Automated Remediation & Hardening

When vulnerable ESC1 templates are detected, the tool automatically generates a hardened PowerShell script:
```powershell
# Run with Domain Admin rights to automatically strip CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
powershell.exe -ExecutionPolicy Bypass -File .\remediate_esc1.ps1
```
* **Safety First**: Creates timestamped `.clixml` backups of all modified Active Directory objects before applying changes.
* **Verification**: Re-reads directory attributes post-change to confirm bitwise flags have been cleared.

---

## 📜 Author
* **Oussama Belhane** — Cybersecurity Engineer
* Focus: Active Directory Security, Red/Blue Team Operations & Digital Forensics
