// precedent_record_fix (graph `precedent`): a Fix and the Findings it severed.
// `held` is true only when the proof of absence re-ran paths_to_sinks on the patched graph and
// got zero paths, so a fix that did not work is remembered as one that did not hold.
MERGE (fx:Fix {id: $fix})
SET fx.action = $action, fx.tool = $tool, fx.sink = $sink, fx.cost = $cost, fx.describe = $describe
WITH fx
UNWIND $findings AS fid
MATCH (f:Finding {id: fid})
MERGE (f)-[e:FIXED_BY]->(fx)
SET e.held = $held, e.stack = $stack, e.ts = $ts
SET f.open = CASE WHEN $held THEN false ELSE f.open END
