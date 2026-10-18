// precedent_rulings_for_tool (graph `precedent`): earlier rulings about the same tool, newest first.
MATCH (r:Ruling {tool: $tool})
RETURN r.id AS id, r.verdict AS verdict, r.summary AS summary, r.stack AS stack, r.ts AS ts
ORDER BY ts DESC
LIMIT $limit
