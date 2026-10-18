// precedent_upsert_patterns (graph `precedent`): the named steering techniques, one node each,
// tagged with OWASP LLM Top 10 categories.
UNWIND $patterns AS p
MERGE (x:Pattern {id: p.id})
SET x.name = p.name, x.description = p.description, x.owasp = p.owasp
