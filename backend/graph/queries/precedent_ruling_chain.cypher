// precedent_ruling_chain (graph `precedent`): a ruling and the rulings it cites (one hop back).
MATCH (r:Ruling {id: $id})
OPTIONAL MATCH (r)-[:CITES]->(c:Ruling)
RETURN r.id AS id, r.verdict AS verdict, r.summary AS summary, r.mock AS mock,
       collect(DISTINCT {id: c.id, verdict: c.verdict, tool: c.tool, stack: c.stack}) AS cites
