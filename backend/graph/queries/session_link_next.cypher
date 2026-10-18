// session_link_next (session graph): chain events in order, (prev)-[:NEXT]->(this).
MATCH (p:Event {seq: $prev}), (e:Event {seq: $seq})
CREATE (p)-[:NEXT]->(e)
