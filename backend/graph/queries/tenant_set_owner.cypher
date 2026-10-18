// tenant_set_owner (graph `tenants`): record that a tenant owns a graph: (Tenant)-[:OWNS]->(GraphRef).
MERGE (t:Tenant {id: $tenant})
MERGE (g:GraphRef {name: $graph})
SET g.owner = $tenant
MERGE (t)-[:OWNS]->(g)
