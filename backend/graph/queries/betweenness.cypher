// betweenness: FalkorDB's own centrality over the capability edges. Fixed seed + a sample size
// above the node count means every node is a source, so the result is exact and repeatable.
CALL algo.betweenness({
  relationshipTypes: ['READ_BY', 'RETURNS_TO', 'CAN_INVOKE', 'REACHES'],
  samplingSize: 1000,
  samplingSeed: 42
}) YIELD node, score
RETURN node.id AS id, labels(node)[0] AS label, score
ORDER BY score DESC
