// session_init (session graph): create the Session node the first time a session is seen.
// The trust score starts at 100 and next_seq hands out event numbers atomically.
MERGE (s:Session {id: $id})
ON CREATE SET s.stack = $stack, s.score = 100, s.next_seq = 0, s.lockdown = false, s.created = $ts
RETURN s.stack AS stack, s.score AS score, s.lockdown AS lockdown
