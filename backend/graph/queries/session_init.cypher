// session_init (session graph): open the session and take the next event number, in one query.
// MERGE creates the Session the first time (score 100). The counter only advances when the
// session really belongs to $stack, so a caller naming the wrong stack cannot burn event
// numbers; the Guard compares the returned `stack` and refuses on a mismatch.
// Atomic, so event numbers stay unique under concurrent calls.
MERGE (s:Session {id: $id})
ON CREATE SET s.stack = $stack, s.score = 100, s.next_seq = 0, s.lockdown = false, s.created = $ts
WITH s, s.stack AS owner_stack
SET s.next_seq = CASE WHEN owner_stack = $stack THEN s.next_seq + 1 ELSE s.next_seq END
RETURN owner_stack AS stack, s.score AS score, s.lockdown AS lockdown, s.next_seq AS seq
