// precedent_stack_findings (graph `precedent`): a stack's findings with their patterns and fixes.
MATCH (s:Stack {id: $stack})-[:HAS]->(f:Finding)
OPTIONAL MATCH (f)-[:INSTANCE_OF]->(p:Pattern)
WITH f, collect(DISTINCT p.id) AS patterns
OPTIONAL MATCH (f)-[fb:FIXED_BY]->(fx:Fix)
RETURN f.id AS id, f.combo AS combo, f.source AS source, f.ingest_tool AS ingest_tool,
       f.act_tool AS act_tool, f.sink AS sink, f.sink_kind AS sink_kind, f.score AS score,
       f.confirmed AS confirmed, f.variants AS variants, f.exploit AS exploit, f.open AS open,
       patterns, collect(DISTINCT {fix: fx.id, describe: fx.describe, held: fb.held}) AS fixes
ORDER BY score DESC, id
