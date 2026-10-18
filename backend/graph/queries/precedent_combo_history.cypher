// precedent_combo_history (graph `precedent`): for each of this stack's findings, the earlier
// stacks that had the very same tool combination (same `combo`), reached through the shared
// Pattern, and the fixes that held there. One row per (finding, earlier finding, fix).
MATCH (me:Stack {id: $stack})-[:HAS]->(f:Finding)
OPTIONAL MATCH (f)-[:INSTANCE_OF]->(:Pattern)<-[:INSTANCE_OF]-(g:Finding)<-[:HAS]-(s:Stack)
WHERE s.id <> me.id AND g.combo = f.combo
OPTIONAL MATCH (g)-[fb:FIXED_BY]->(fx:Fix)
WHERE fb.held = true
RETURN DISTINCT f.id AS finding, f.combo AS combo, f.act_tool AS act_tool,
       g.id AS earlier_finding, g.confirmed AS earlier_confirmed,
       s.id AS earlier_stack, s.owner AS earlier_owner, s.seeded AS earlier_seeded,
       fx.id AS fix, fx.describe AS fix_describe
