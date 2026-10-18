// session_next_seq (session graph): atomic event counter, safe under concurrent calls.
MATCH (s:Session {id: $id})
SET s.next_seq = s.next_seq + 1
RETURN s.next_seq AS seq
