// choke_points (exact part): for every tool, how many open attack paths run through it, either
// as the ingesting tool (t1) or the acting tool (t2). Removing/gating a tool with a high share
// severs that share of paths. The Agent is the hub of every path, so it is not a candidate.
MATCH (ds:DataSource)-[:READ_BY]->(t1:Tool)-[:RETURNS_TO]->(a:Agent)-[i:CAN_INVOKE]->(t2:Tool)-[r:REACHES]->(s:Sink)
WHERE ds.trust = 'untrusted'
  AND NOT coalesce(i.gated, false)
  AND NOT coalesce(r.scoped, false)
WITH ds.id + '>' + t1.id + '>' + t2.id + '>' + s.id AS pid, [t1.id, t2.id] AS tools
UNWIND tools AS tool
RETURN tool, count(DISTINCT pid) AS paths
ORDER BY paths DESC, tool
