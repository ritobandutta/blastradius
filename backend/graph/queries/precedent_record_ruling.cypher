// precedent_record_ruling (graph `precedent`): an advisory Tribunal ruling, linked to the earlier
// rulings it cites: (Ruling)-[:CITES]->(Ruling). Rulings never change a Guard decision.
CREATE (r:Ruling {id: $id, tool: $tool, stack: $stack, session: $session, seq: $seq,
                  verdict: $verdict, summary: $summary, mock: $mock, model: $model, ts: $ts,
                  advisory: true})
WITH r
UNWIND $cites AS cid
MATCH (c:Ruling {id: cid})
MERGE (r)-[:CITES]->(c)
