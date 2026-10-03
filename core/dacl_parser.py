"""
Binary Security Descriptor & DACL Parser (MS-DTYP specifications)
Handles parsing binary Windows SIDs and Access Control Entries (ACEs) to identify
which security principals have enrollment or Full Control permissions on templates.
"""

import struct
import uuid
from core.constants import (
    CERT_ENROLLMENT_EXTENDED_RIGHT,
    WELL_KNOWN_SIDS,
    UNPRIVILEGED_SIDS
)


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
