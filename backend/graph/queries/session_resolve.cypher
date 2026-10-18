// session_resolve (session graph): a human approves or denies a pending ESCALATE.
// The WHERE clause is the whole safety argument: only an event whose decision is ESCALATE and
// which is still pending can change. A DENY event never matches, so nothing can turn it into ALLOW.
MATCH (e:Event {seq: $seq})
WHERE e.decision = 'ESCALATE' AND e.status = 'pending'
SET e.status = $status, e.executed = $executed, e.resolved_ts = $ts, e.resolved_by = 'human'
RETURN e.seq AS seq, e.tool AS tool, e.status AS status, e.tainted AS tainted
