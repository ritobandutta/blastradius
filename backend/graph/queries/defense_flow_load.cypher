// defense_flow_load (scratch graph defense:<id>): copy the attack-path subgraph into a single
// FLOW edge type with integer capacities. algo.maxFlow accepts exactly one relationship type,
// so the four capability edge types are folded into FLOW here. Capacity = cost of cutting that
// edge (gate / scope / remove-tool); edges with no fix lever get a huge capacity.
UNWIND $nodes AS n
CREATE (:N {id: n})
