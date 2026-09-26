# 🛡️ ADCS ESC1 Vulnerability Scanner & PKI Auditor

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
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

## ✨ Features

- 🎨 **Airgeddon-Inspired Terminal UI**: Sleek ANSI colored panels, progress indicators, and visual risk cards.
- 🔍 **Automated LDAP/LDAPS Audit**: Queries the Active Directory `Configuration` naming context (`CN=Certificate Templates,CN=Public Key Services...`).
- 🧮 **Bitwise Security Math**: Evaluates `msPKI-Certificate-Name-Flag` and `msPKI-Enrollment-Flag` against official Microsoft MS-CRTD specifications.
- 📋 **Automated JSON Export**: Saves standardized audit artifacts for compliance reports and SIEM ingest.
- 🧪 **Offline Demo Mode**: Test and showcase the scanner console interface anywhere with `--demo` (no live lab required!).

---

## 🚀 Installation & Usage

### 1. Clone the Repository & Install Dependencies
```bash
git clone https://github.com/OussamaBelhane/ADCS-ESC1-Scanner.git
cd ADCS-ESC1-Scanner
pip install -r requirements.txt
```

### 2. Instant Demo Mode (Showcase / Testing)
Test the console interface and risk cards without needing an active Domain Controller:
```bash
python adcs_esc1_scanner.py --demo
```

### 3. Scan a Live Domain Controller (LDAP / LDAPS)
```bash
# Standard LDAP scan (Port 389)
python adcs_esc1_scanner.py -dc 192.168.1.10 -d corporate.local -u jdoe -p 'Winter2026!'

# Secure LDAPS scan (Port 636) with JSON report export
python adcs_esc1_scanner.py -dc 192.168.1.10 -d corporate.local -u jdoe -p 'Winter2026!' --ssl -o corporate_adcs_audit.json
```

---

## 🛡️ Blue Team Remediation (How to Fix ESC1)

To remediate vulnerable templates found by this tool:
1. Open the **Certificate Templates Console** (`certtmpl.msc`) on the Certification Authority server.
2. Right-click the vulnerable template and click **Properties**.
3. Navigate to the **Subject Name** tab.
4. Select **"Build from this Active Directory information"** instead of *"Supply in the request"*.
5. Under the **Issuance Requirements** tab, consider checking **"CA certificate manager approval"** for high-privilege templates.

---

## 📜 Author
* **Oussama Belhane** — Cybersecurity Engineer
* Focus: Active Directory Security, Red/Blue Team Operations & Digital Forensics
