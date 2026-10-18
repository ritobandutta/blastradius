// paths_to_sinks: every attack path  untrusted DataSource -> Tool -> Agent -> Tool -> Sink.
// A path is open only if the Agent's CAN_INVOKE edge is not gated and the REACHES edge is not
// scoped. t1 and t2 may be the same tool (fetch a poisoned page, then call fetch again to leak).
// Secret/Permission sensitivity is the highest held by either tool on the path.
MATCH (ds:DataSource)-[:READ_BY]->(t1:Tool)-[:RETURNS_TO]->(a:Agent)-[i:CAN_INVOKE]->(t2:Tool)-[r:REACHES]->(s:Sink)
WHERE ds.trust = 'untrusted'
  AND NOT coalesce(i.gated, false)
  AND NOT coalesce(r.scoped, false)
OPTIONAL MATCH (x:Tool)-[:HOLDS]->(h)
WHERE x.id IN [t1.id, t2.id]
WITH ds, t1, a, t2, s, coalesce(max(h.sensitivity), 0) AS secret_sensitivity
RETURN ds.id AS source, ds.label AS source_label,
       t1.id AS ingest_tool, a.id AS agent, t2.id AS act_tool,
       s.id AS sink, s.kind AS sink_kind, s.label AS sink_label,
       secret_sensitivity
ORDER BY sink_kind, source, ingest_tool, act_tool, sink
