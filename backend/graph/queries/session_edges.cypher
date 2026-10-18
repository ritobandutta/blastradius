// session_edges (session graph): NEXT and DERIVED_FROM edges for drawing the taint graph.
MATCH (a:Event)-[r]->(b:Event)
RETURN a.seq AS source, b.seq AS target, type(r) AS type
ORDER BY type, source, target
