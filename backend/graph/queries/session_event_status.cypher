// session_event_status (session graph): poll the outcome of one event (used while a call waits
// for a human to approve or deny an ESCALATE).
MATCH (e:Event {seq: $seq})
RETURN e.decision AS decision, e.status AS status, e.executed AS executed
