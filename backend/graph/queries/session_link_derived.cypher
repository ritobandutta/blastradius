// session_link_derived (session graph): when the context was tainted, this call is
// (this)-[:DERIVED_FROM]->(each executed tainted event). That is the taint provenance.
MATCH (e:Event {seq: $seq}), (t:Event)
WHERE t.executed = true AND t.tainted = true AND t.seq < $seq
CREATE (e)-[:DERIVED_FROM]->(t)
