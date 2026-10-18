// precedent_patterns (graph `precedent`): the pattern catalog with how often each was seen.
MATCH (p:Pattern)
OPTIONAL MATCH (p)<-[:INSTANCE_OF]-(f:Finding)<-[:HAS]-(s:Stack)
RETURN p.id AS id, p.name AS name, p.description AS description, p.owasp AS owasp,
       count(DISTINCT f) AS findings, count(DISTINCT s) AS stacks
ORDER BY stacks DESC, name
