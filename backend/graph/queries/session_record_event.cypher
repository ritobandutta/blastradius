// session_record_event (session graph): write one step of the session as an Event node.
CREATE (e:Event {
  seq: $seq, tool: $tool, args_hash: $args_hash, tainted: $tainted,
  decision: $decision, executed: $executed, status: $status,
  reasons: $reasons, dlp: $dlp, ts: $ts
})
RETURN e.seq AS seq
