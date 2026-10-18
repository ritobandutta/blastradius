// defense_flow_edges (scratch graph defense:<id>): FLOW edges of the path subgraph.
UNWIND $edges AS e
MATCH (a:N {id: e.f}), (b:N {id: e.t})
CREATE (a)-[:FLOW {capacity: e.c, fix: e.fix}]->(b)
