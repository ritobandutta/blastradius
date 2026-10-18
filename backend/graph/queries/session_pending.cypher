// session_pending (session graph): ESCALATE calls still waiting for a human.
MATCH (s:Session), (e:Event)
WHERE e.decision = 'ESCALATE' AND e.status = 'pending'
RETURN s.id AS session, s.stack AS stack, e.seq AS seq, e.tool AS tool,
       e.reasons AS reasons, e.tainted AS tainted, e.ts AS ts
ORDER BY ts
