// toxic_combinations: an agent that can (1) ingest untrusted content, (2) read private data or
// hold a secret, and (3) reach an outbound exfil channel, all through un-gated, un-scoped edges.
// Any one of the three is survivable; all three together is the "lethal trifecta".
MATCH (a:Agent)
OPTIONAL MATCH (a)-[i1:CAN_INVOKE]->(tu:Tool)<-[:READ_BY]-(du:DataSource)
WHERE du.trust = 'untrusted' AND NOT coalesce(i1.gated, false)
WITH a, [x IN collect(DISTINCT {tool: tu.id, via: du.id}) WHERE x.tool IS NOT NULL] AS ingest
OPTIONAL MATCH (a)-[i2:CAN_INVOKE]->(tp:Tool)<-[:READ_BY]-(dp:DataSource)
WHERE dp.trust = 'internal' AND NOT coalesce(i2.gated, false)
WITH a, ingest, [x IN collect(DISTINCT {tool: tp.id, via: dp.id}) WHERE x.tool IS NOT NULL] AS private_data
OPTIONAL MATCH (a)-[i3:CAN_INVOKE]->(ts:Tool)-[:HOLDS]->(sec)
WHERE NOT coalesce(i3.gated, false)
WITH a, ingest, private_data, [x IN collect(DISTINCT {tool: ts.id, via: sec.id}) WHERE x.tool IS NOT NULL] AS secrets
OPTIONAL MATCH (a)-[i4:CAN_INVOKE]->(te:Tool)-[r:REACHES]->(s:Sink)
WHERE s.kind = 'exfil' AND NOT coalesce(i4.gated, false) AND NOT coalesce(r.scoped, false)
WITH a, ingest, private_data, secrets, [x IN collect(DISTINCT {tool: te.id, via: s.id}) WHERE x.tool IS NOT NULL] AS egress
RETURN a.id AS agent, ingest, private_data, secrets, egress,
       size(ingest) > 0 AND (size(private_data) > 0 OR size(secrets) > 0) AND size(egress) > 0 AS toxic
