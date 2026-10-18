// housekeeping_session_age (session graph): when was this session opened? Used by the public
// demo janitor to delete stale session graphs.
MATCH (s:Session)
RETURN s.created AS created
LIMIT 1
