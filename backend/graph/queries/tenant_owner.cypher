// tenant_owner (graph `tenants`): which tenant owns a named stack graph?
MATCH (g:GraphRef {name: $graph})
RETURN g.owner AS owner
