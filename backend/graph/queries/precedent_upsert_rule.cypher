// precedent_upsert_rule (graph `precedent`): a learned Guard rule, derived from confirmed findings.
// (Rule)-[:DERIVED_FROM]->(Finding). A new rule starts as `proposed`; only the critic arms it.
// Re-deriving an existing rule keeps its status until the critic runs again.
MERGE (r:Rule {id: $id})
ON CREATE SET r.status = 'proposed', r.created = $ts
SET r.owner = $owner, r.ingest_tool = $ingest_tool, r.act_tool = $act_tool,
    r.sink_kind = $sink_kind, r.sink = $sink, r.representative = $representative,
    r.exploit = $exploit
WITH r
UNWIND $findings AS fid
MATCH (f:Finding {id: fid})
MERGE (r)-[:DERIVED_FROM]->(f)
