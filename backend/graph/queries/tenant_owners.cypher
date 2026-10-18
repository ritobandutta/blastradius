// tenant_owners (graph `tenants`): every graph and its owner, used to list a tenant's stacks.
MATCH (g:GraphRef)
RETURN g.name AS name, g.owner AS owner
