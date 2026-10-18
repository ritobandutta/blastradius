// precedent_upsert_findings (graph `precedent`): one Finding per attack path.
// (Stack)-[:HAS]->(Finding)-[:INSTANCE_OF]->(Pattern). `combo` is the stack-independent tool
// combination (source>ingest tool>act tool>sink), which is what makes a finding comparable
// across stacks. `exploit` is the recorded canary replay used by the rule critic.
MATCH (s:Stack {id: $stack})
UNWIND $findings AS f
MERGE (x:Finding {id: f.id})
SET x.combo = f.combo, x.source = f.source, x.ingest_tool = f.ingest_tool,
    x.act_tool = f.act_tool, x.sink = f.sink, x.sink_kind = f.sink_kind, x.score = f.score,
    x.confirmed = f.confirmed, x.variants = f.variants, x.exploit = f.exploit, x.open = true
MERGE (s)-[:HAS]->(x)
WITH x, f
UNWIND f.patterns AS pid
MATCH (p:Pattern {id: pid})
MERGE (x)-[:INSTANCE_OF]->(p)
