import struct
import uuid
import pytest
from core import (
    check_esc1,
    parse_sid,
    resolve_sid_name,
    is_unprivileged_principal,
    parse_dacl_enrollees,
    CERT_ENROLLMENT_EXTENDED_RIGHT,
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
    CT_FLAG_PEND_ALL_REQUESTS
)


class MockAttribute:
    def __init__(self, value, raw_values=None):
        self.value = value
        self.raw_values = raw_values or [b""]


class MockEntry:
    def __init__(self, cn, name_flag=0, enroll_flag=0, ekus=None, display_name=None, raw_sd=None):
        self.cn = MockAttribute(cn)
        self.displayName = MockAttribute(display_name or cn)
        self.attrs = {
            'msPKI-Certificate-Name-Flag': MockAttribute(name_flag),
            'msPKI-Enrollment-Flag': MockAttribute(enroll_flag),
            'pKIExtendedKeyUsage': MockAttribute(ekus or []),
        }
        if raw_sd is not None:
            self.attrs['nTSecurityDescriptor'] = MockAttribute(raw_sd, raw_values=[raw_sd])

    def __contains__(self, item):
        return item in self.attrs

    def __getitem__(self, item):
        return self.attrs[item]


# -------------------------------------------------------------------------
# 1. Bitwise Flag & ESC1 Detection Tests
# -------------------------------------------------------------------------

def test_esc1_vulnerable_when_san_allowed_and_client_auth():
    """Verify template is flagged vulnerable when ENROLLEE_SUPPLIES_SUBJECT (0x1) and Client Auth are present."""
    entry = MockEntry(
        cn="ESC1-Test",
        name_flag=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
        enroll_flag=0,
        ekus=["1.3.6.1.5.5.7.3.2"]  # Client Authentication
    )
    result = check_esc1(entry)
    assert result["is_vulnerable"] is True
    assert result["supplies_san"] is True
    assert result["manager_approval"] is False
    assert "Client Authentication" in result["auth_ekus"]


def test_esc1_safe_when_manager_approval_required():
    """Verify template is NOT vulnerable if CA manager approval (0x2) is enforced."""
    entry = MockEntry(
        cn="ESC1-Approved",
        name_flag=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
        enroll_flag=CT_FLAG_PEND_ALL_REQUESTS,  # Manager Approval
        ekus=["1.3.6.1.5.5.7.3.2"]
    )
    result = check_esc1(entry)
    assert result["is_vulnerable"] is False
    assert result["manager_approval"] is True


def test_esc1_safe_when_server_auth_only():
    """Verify template is NOT vulnerable if EKU does not allow client authentication."""
    entry = MockEntry(
        cn="WebServer-Only",
        name_flag=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
        enroll_flag=0,
        ekus=["1.3.6.1.5.5.7.3.1"]  # Server Authentication only
    )
    result = check_esc1(entry)
    assert result["is_vulnerable"] is False
    assert len(result["auth_ekus"]) == 0


def test_esc1_safe_when_no_san_supply():
    """Verify template is NOT vulnerable if ENROLLEE_SUPPLIES_SUBJECT flag is 0."""
    entry = MockEntry(
        cn="User-Standard",
        name_flag=0,
        enroll_flag=0,
        ekus=["1.3.6.1.5.5.7.3.2"]
    )
    result = check_esc1(entry)
    assert result["is_vulnerable"] is False
    assert result["supplies_san"] is False


def test_subca_wildcard_eku_flagged():
    """Verify template with no EKUs and SAN supply is flagged as Wildcard/All Purposes."""
    entry = MockEntry(
        cn="SubCA-Mock",
        name_flag=CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
        enroll_flag=0,
        ekus=[]
    )
    result = check_esc1(entry)
    assert result["is_vulnerable"] is True
    assert "All Purposes (Wildcard/SubCA)" in result["auth_ekus"]


# -------------------------------------------------------------------------
# 2. Windows SID & Security Principal Resolution Tests
# -------------------------------------------------------------------------

def test_well_known_sid_resolution():
    """Verify resolution of standard well-known Windows SIDs."""
    assert resolve_sid_name("S-1-5-11") == "Authenticated Users"
    assert resolve_sid_name("S-1-1-0") == "Everyone"
    assert is_unprivileged_principal("S-1-5-11") is True
    assert is_unprivileged_principal("S-1-1-0") is True


def test_domain_sid_rid_resolution():
    """Verify mapping of domain RIDs (Domain Users vs Domain Admins)."""
    domain_users_sid = "S-1-5-21-966532304-2497176652-369248004-513"
    domain_admins_sid = "S-1-5-21-966532304-2497176652-369248004-512"

    assert resolve_sid_name(domain_users_sid) == "Domain Users"
    assert resolve_sid_name(domain_admins_sid) == "Domain Admins"

    assert is_unprivileged_principal(domain_users_sid) is True
    assert is_unprivileged_principal(domain_admins_sid) is False


# -------------------------------------------------------------------------
# 3. Binary Windows Security Descriptor & DACL Parsing Tests
# -------------------------------------------------------------------------

def build_mock_security_descriptor(grant_unprivileged=True):
    """
    Constructs a syntactically valid binary Windows Security Descriptor (MS-DTYP)
    containing an ACCESS_ALLOWED_OBJECT_ACE for Certificate-Enrollment extended right.
    """
    # 1. Build SID for Authenticated Users (S-1-5-11) or Domain Admins
    if grant_unprivileged:
        # S-1-5-11: rev=1, sub_count=1, auth=5, subauth=11
        sid_bytes = struct.pack('<BB', 1, 1) + int(5).to_bytes(6, 'big') + struct.pack('<I', 11)
    else:
        # S-1-5-21-...-512: rev=1, sub_count=5, auth=5, subauths...
        sid_bytes = struct.pack('<BB', 1, 5) + int(5).to_bytes(6, 'big') + struct.pack('<IIIII', 21, 1, 2, 3, 512)

    # 2. Build ACCESS_ALLOWED_OBJECT_ACE (Type 0x05)
    # Mask = 0x100 (RIGHT_DS_CONTROL_ACCESS)
    # Flags = 0x01 (ACE_OBJECT_TYPE_PRESENT)
    guid_bytes = uuid.UUID(CERT_ENROLLMENT_EXTENDED_RIGHT).bytes_le
    ace_header = struct.pack('<BBH', 0x05, 0x00, 4 + 4 + 4 + 16 + len(sid_bytes))
    ace_body = struct.pack('<II', 0x00000100, 0x00000001) + guid_bytes + sid_bytes
    ace_data = ace_header + ace_body

    # 3. Build ACL Header
    acl_header = struct.pack('<BBHHH', 0x04, 0x00, 8 + len(ace_data), 1, 0x00)
    acl_data = acl_header + ace_data

    # 4. Build SECURITY_DESCRIPTOR Header (20 bytes)
    # Revision=1, Control=0x0004 (SE_DACL_PRESENT), OffsetDacl=20
    sd_header = struct.pack('<BBHIIII', 1, 0, 0x0004, 0, 0, 0, 20)
    return sd_header + acl_data


def test_dacl_parsing_unprivileged_enrollment():
    """Verify binary DACL parser correctly extracts Authenticated Users Certificate-Enrollment right."""
    sd_bytes = build_mock_security_descriptor(grant_unprivileged=True)
    dacl_info = parse_dacl_enrollees(sd_bytes)

    assert dacl_info["has_unprivileged"] is True
    enrollee_names = [e["name"] for e in dacl_info["enrollees"]]
    assert "Authenticated Users" in enrollee_names


def test_dacl_parsing_admin_only_enrollment():
    """Verify binary DACL parser correctly marks admin-only enrollees as NOT unprivileged."""
    sd_bytes = build_mock_security_descriptor(grant_unprivileged=False)
    dacl_info = parse_dacl_enrollees(sd_bytes)

    assert dacl_info["has_unprivileged"] is False
    enrollee_names = [e["name"] for e in dacl_info["enrollees"]]
    assert "Domain Admins" in enrollee_names
