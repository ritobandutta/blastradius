// precedent_upsert_stack (graph `precedent`): remember that a stack was scanned.
// Findings of a previous scan of the same stack are marked closed first; the upsert reopens the
// ones that still exist, so a re-scan never leaves stale open findings behind.
MERGE (s:Stack {id: $id})
SET s.owner = $owner, s.seeded = $seeded, s.name = $name, s.scanned = $ts,
    s.open_risk = $open_risk, s.path_count = $path_count
WITH s
OPTIONAL MATCH (s)-[:HAS]->(old:Finding)
SET old.open = false
RETURN s.id AS id
