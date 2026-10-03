"""
BloodHound Graph & Neo4j Cypher Export Engine
Maps ADCS attack path relationships for BloodHound ingestion.
"""

import json
from colorama import Fore, Style


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
