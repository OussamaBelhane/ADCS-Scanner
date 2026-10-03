"""
ADCS ESC1 Vulnerability Evaluation Engine
Evaluates the 4 golden conditions required for Domain Escalation via ESC1.
"""

from core.constants import (
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
    CT_FLAG_PEND_ALL_REQUESTS,
    CLIENT_AUTH_EKUS
)
from core.dacl_parser import parse_dacl_enrollees


def check_esc1(entry):
    """
    Evaluates whether an Active Directory Certificate Template satisfies
    the 4 Golden Conditions for ESC1 Privilege Escalation:
    1. Enrollee supplies Subject Alternative Name (SAN).
    2. Template has Client Authentication EKU.
    3. CA does not enforce Manager Approval.
    4. Unprivileged users (Domain Users / Authenticated Users) have enrollment rights.
    """
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
