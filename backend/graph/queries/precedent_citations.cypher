// precedent_citations (graph `precedent`): the two-hop traversal from the brief,
//   Stack -> Finding -> Pattern <- Finding <- Stack
// grouped per Pattern, with the Fixes that held on the earlier stacks' findings.
MATCH (me:Stack {id: $stack})-[:HAS]->(:Finding)-[:INSTANCE_OF]->(p:Pattern)<-[:INSTANCE_OF]-(g:Finding)<-[:HAS]-(s:Stack)
WHERE s.id <> me.id
WITH p, s, g
OPTIONAL MATCH (g)-[fb:FIXED_BY]->(fx:Fix)
WHERE fb.held = true
WITH p, collect(DISTINCT {id: s.id, owner: s.owner, seeded: s.seeded}) AS stacks,
     collect(DISTINCT g) AS gs, collect(DISTINCT fx.id) AS fixes
RETURN p.id AS pattern, p.name AS name, p.owasp AS owasp,
       size(stacks) AS other_stacks, stacks,
       size(gs) AS findings, size([x IN gs WHERE x.confirmed = true]) AS confirmed,
       [x IN gs | x.id] AS finding_ids, fixes
ORDER BY other_stacks DESC, confirmed DESC, name
