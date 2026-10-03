"""
ADCS ESC1 & Windows Security Constants (MS-CRTD & MS-DTYP specifications)
"""

# Template Bitmask Flags
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002

# Extended Right GUID for Certificate-Enrollment in Active Directory
CERT_ENROLLMENT_EXTENDED_RIGHT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
CERT_AUTOENROLLMENT_EXTENDED_RIGHT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

# Security Identifiers (SIDs)
WELL_KNOWN_SIDS = {
    "S-1-5-11": "Authenticated Users",
    "S-1-1-0": "Everyone",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-18": "Local System",
}

UNPRIVILEGED_SIDS = ["S-1-5-11", "S-1-1-0", "S-1-5-32-545"]

# Extended Key Usage (EKU) OIDs for Authentication
CLIENT_AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "2.5.29.37.0": "Any Purpose (Wildcard)",
}

CONFIG_FILE = "targets.json"
