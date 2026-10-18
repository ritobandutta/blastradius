// session_taint (session graph): is untrusted data in the agent's context right now?
// An event taints the context only if it actually ran (executed) and its tool reads an
// untrusted source. Denied or still-pending calls never returned data, so they do not count.
MATCH (e:Event)
WHERE e.executed = true AND e.tainted = true
RETURN e.seq AS seq, e.tool AS tool
ORDER BY seq
