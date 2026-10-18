// defense_maxflow (scratch graph defense:<id>): FalkorDB's own max-flow from the super source to
// the super sink. By the max-flow/min-cut theorem its value equals the cost of the cheapest set
// of fixes that severs every attack path, which we compare with the networkx cut we report.
MATCH (s:N {id: 'SRC'}), (t:N {id: 'SNK'})
CALL algo.maxFlow({
  sourceNodes: [s],
  targetNodes: [t],
  relationshipTypes: ['FLOW'],
  capacityProperty: 'capacity'
}) YIELD maxFlow, edges, edgeFlows
RETURN maxFlow, size(edges) AS edges_used
