// tenant_release (graph `tenants`): forget a graph's owner when the graph is deleted.
MATCH (g:GraphRef {name: $graph})
DETACH DELETE g
