// session_events (session graph): the full step list for the live panel.
MATCH (s:Session)
OPTIONAL MATCH (e:Event)
RETURN s.id AS session, s.stack AS stack, s.score AS score, s.lockdown AS lockdown,
       e.seq AS seq, e.tool AS tool, e.decision AS decision, e.status AS status,
       e.tainted AS tainted, e.executed AS executed, e.reasons AS reasons, e.dlp AS dlp, e.ts AS ts
ORDER BY seq
