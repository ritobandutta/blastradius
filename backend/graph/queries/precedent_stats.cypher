// precedent_stats (graph `precedent`): size of the shared memory.
MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY label
