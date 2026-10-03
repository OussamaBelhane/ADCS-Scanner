"""
Active Directory LDAP Client & Enumeration Engine
Handles connecting to the Domain Controller and querying ADCS Certificate Templates,
Enrollment Services (Enterprise CAs), and Domain User Accounts.
"""

import sys
from ldap3 import Server, Connection, NTLM, SUBTREE
from ldap3.protocol.microsoft import security_descriptor_control
from colorama import Fore


def get_base_dn(domain):
    """Converts a DNS domain name (e.g. corp.local) to standard LDAP Base DN (DC=corp,DC=local)."""
    return ",".join([f"DC={part}" for part in domain.split(".")])


def connect_ldap(dc_ip, domain, username, password, use_ssl=False):
    """Authenticates to the Domain Controller via NTLM over LDAP (Port 389) or LDAPS (Port 636)."""
    port = 636 if use_ssl else 389
    user_principal = f"{domain}\\{username}"

    print(f"[*] Connecting to {dc_ip}:{port} as {user_principal}...")
    server = Server(dc_ip, port=port, use_ssl=use_ssl, get_info='ALL')
    conn = Connection(server, user=user_principal, password=password, authentication=NTLM)

    if not conn.bind():
        print(Fore.RED + f"[-] Authentication failed: {conn.result.get('description', 'Unknown error')}")
        sys.exit(1)

    print(Fore.GREEN + f"[+] Authentication successful!\n")
    return conn


def get_published_templates(conn, domain):
    """
    Queries Enrollment Services in the Configuration partition to determine
    which certificate templates are actively published by Enterprise CAs.
    Returns:
        published: dict mapping template_name -> list of publishing CA names
        ca_count: total number of enterprise CAs discovered
    """
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


def get_certificate_templates(conn, domain):
    """
    Queries the Certificate Templates container in the Configuration partition.
    Requests binary nTSecurityDescriptor DACL using LDAP control flags (0x4).
    """
    base_dn = get_base_dn(domain)
    templates_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}"

    controls = security_descriptor_control(sdflags=0x4)
    conn.search(
        search_base=templates_dn,
        search_filter="(objectClass=pKICertificateTemplate)",
        search_scope=SUBTREE,
        attributes=[
            'cn', 'displayName', 'msPKI-Certificate-Name-Flag',
            'msPKI-Enrollment-Flag', 'pKIExtendedKeyUsage',
            'msPKI-RA-Signature', 'nTSecurityDescriptor'
        ],
        controls=controls
    )
    return conn.entries


def get_domain_users(conn, domain):
    """Enumerates all domain users and groups to distinguish Privileged vs Standard accounts."""
    base_dn = get_base_dn(domain)
    conn.search(
        search_base=base_dn,
        search_filter="(&(objectClass=user)(objectCategory=person))",
        search_scope=SUBTREE,
        attributes=['sAMAccountName', 'displayName', 'adminCount', 'description', 'memberOf']
    )

    admins = []
    regular_users = []

    for entry in conn.entries:
        user_name = str(entry.sAMAccountName.value)
        display_name = str(entry.displayName.value) if 'displayName' in entry else user_name
        description = str(entry.description.value) if 'description' in entry else ""
        admin_count = entry.adminCount.value if 'adminCount' in entry else 0

        user_obj = {
            "username": user_name,
            "displayName": display_name,
            "description": description,
            "adminCount": admin_count
        }

        # Check admin indicators (adminCount=1 or Domain Admins group membership)
        is_admin = admin_count == 1
        if not is_admin and 'memberOf' in entry:
            for group in entry.memberOf.values:
                if "Domain Admins" in str(group) or "Enterprise Admins" in str(group) or "Administrators" in str(group):
                    is_admin = True
                    break

        if is_admin:
            admins.append(user_obj)
        else:
            regular_users.append(user_obj)

    return admins, regular_users
