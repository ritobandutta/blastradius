// precedent_rules (graph `precedent`): every learned rule with the findings it came from.
MATCH (r:Rule)
OPTIONAL MATCH (r)-[:DERIVED_FROM]->(f:Finding)
RETURN r.id AS id, r.status AS status, r.owner AS owner, r.ingest_tool AS ingest_tool,
       r.act_tool AS act_tool, r.sink_kind AS sink_kind, r.critic AS critic, r.exploit AS exploit,
       collect(DISTINCT f.id) AS findings
ORDER BY status, id
