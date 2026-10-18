// precedent_rules_matching (graph `precedent`): which learned rules fire for this call?
// A rule fires when the pending tool is the rule's act tool AND the rule's ingest tool has
// already run in this session (so untrusted data from it is in context). The Guard passes
// statuses = ['armed']; the critic passes the rule's own id to test it before arming.
// Rules are private to their owner tenant, except the shared 'seed' corpus.
MATCH (r:Rule)
WHERE r.status IN $statuses AND r.act_tool = $tool AND r.ingest_tool IN $tainted
  AND r.owner IN $owners AND ($rid = '' OR r.id = $rid)
OPTIONAL MATCH (r)-[:DERIVED_FROM]->(f:Finding)
RETURN r.id AS rule, r.status AS status, r.sink_kind AS sink_kind, collect(DISTINCT f.id) AS findings
ORDER BY rule
