// session_penalize (session graph): lower the trust score atomically, never below zero.
// Lockdown is sticky: once the score drops under the threshold it stays on for the session.
MATCH (s:Session {id: $id})
WITH s, CASE WHEN s.score - $penalty < 0 THEN 0 ELSE s.score - $penalty END AS new_score
SET s.score = new_score, s.lockdown = (s.lockdown = true OR new_score < $threshold)
RETURN s.score AS score, s.lockdown AS lockdown
