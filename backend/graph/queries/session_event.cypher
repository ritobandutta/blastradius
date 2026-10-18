// session_event (session graph): one event with everything the Tribunal may read.
MATCH (s:Session), (e:Event {seq: $seq})
RETURN s.stack AS stack, e.seq AS seq, e.tool AS tool, e.decision AS decision, e.status AS status,
       e.tainted AS tainted, e.reasons AS reasons, e.dlp AS dlp
