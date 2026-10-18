// guard_tool_facts (stack graph): everything the Guard needs to know about one tool call.
// untrusted_sources: untrusted DataSources this tool reads (so a successful call taints the session)
// sinks:             sinks the tool can still reach (scoped REACHES edges are ignored)
// gated:             the Agent's CAN_INVOKE edge needs a human click
MATCH (t:Tool {id: $tool})
OPTIONAL MATCH (a:Agent)-[i:CAN_INVOKE]->(t)
OPTIONAL MATCH (d:DataSource)-[:READ_BY]->(t)
WHERE d.trust = 'untrusted'
WITH t, a, i, collect(DISTINCT d.id) AS untrusted_sources
OPTIONAL MATCH (t)-[r:REACHES]->(s:Sink)
WHERE NOT coalesce(r.scoped, false)
RETURN t.id AS tool, t.side_effect AS side_effect, a.id AS agent,
       coalesce(i.gated, false) AS gated, untrusted_sources,
       collect(DISTINCT {sink: s.id, kind: s.kind}) AS sinks
