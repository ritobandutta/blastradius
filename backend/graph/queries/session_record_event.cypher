// session_record_event (session graph): write one step of the session, with its edges, in one query.
//   (prev)-[:NEXT]->(this)                        order of calls
//   (this)-[:DERIVED_FROM]->(each tainted event)  only when the context was tainted ($derived):
//                                                 every executed, tainted, earlier event
// A first event has no previous one (OPTIONAL MATCH finds nothing), so no NEXT edge is made.
CREATE (e:Event {
  seq: $seq, tool: $tool, args_hash: $args_hash, tainted: $tainted,
  decision: $decision, executed: $executed, status: $status,
  reasons: $reasons, dlp: $dlp, ts: $ts
})
WITH e
OPTIONAL MATCH (p:Event {seq: $prev})
WITH e, collect(p) AS prevs
OPTIONAL MATCH (t:Event)
WHERE $derived AND t.executed = true AND t.tainted = true AND t.seq < $seq
WITH e, prevs, collect(t) AS tainted_events
FOREACH (p IN prevs | CREATE (p)-[:NEXT]->(e))
FOREACH (t IN tainted_events | CREATE (e)-[:DERIVED_FROM]->(t))
