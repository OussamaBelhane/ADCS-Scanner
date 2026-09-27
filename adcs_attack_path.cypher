// ===================================================================
// BloodHound / Neo4j Cypher Queries for AD CS ESC1 Attack Paths
// Target Domain: invictus.local
// ===================================================================

// Query 1: Find all unprivileged groups with CanEnroll permissions to ESC1 templates
MATCH p=(g:Group)-[:CanEnroll]->(t:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
WHERE t.enrolleesuppliessubject = true AND t.requiresmanagerapproval = false
RETURN p;

// Query 2: Map the complete privilege escalation path from user to Domain Admin
MATCH (g:Group)-[:CanEnroll]->(t:CertTemplate)-[:Abuse_ESC1_PKINIT]->(da:Group {name: 'Domain Admins'})
RETURN g, t, da;
