# Cypher and algorithms BlastRadius relies on

Every statement below was run against `falkordb/falkordb:latest` by
`scripts/spike_cypher.py` before we used it. Anything marked **not usable** failed on the
real server, so we do not depend on it.

## Verified syntax

| Need | Syntax that works | Notes |
|---|---|---|
| Parameters | `g.ro_query("... WHERE n.id = $id", {"id": x})` | Always parameterize. |
| Server-side time | `result.run_time_ms` | `internal_execution_time` does **not** exist on this client. |
| Bounded paths | `MATCH p=(d)-[:A\|B\|C*1..6]->(s) RETURN [n IN nodes(p) \| n.id]` | `relationships(p)` also works. |
| All paths from a source | `CALL algo.SSpaths({sourceNode:d, relTypes:[...], maxLen:6, relDirection:'outgoing', pathCount:100}) YIELD path` | Returns every prefix, so filter to paths ending at a Sink. |
| Paths between two nodes | `CALL algo.SPpaths({sourceNode:d, targetNode:s, relTypes:[...], maxLen:6, pathCount:0}) YIELD path` | `pathCount:0` returns all shortest paths. |
| Centrality | `CALL algo.betweenness({samplingSeed:42}) YIELD node, score` | Fixed seed for reproducible output. |
| Components | `CALL algo.WCC() YIELD node, componentId` | |
| PageRank | `CALL algo.pageRank('Tool','CAN_INVOKE') YIELD node, score` | |
| Max flow | `CALL algo.maxFlow({sourceNodes:[d], targetNodes:[s], relationshipTypes:['FLOW'], capacityProperty:'capacity'}) YIELD maxFlow` | `relationshipTypes` must hold **exactly one** string, so the path subgraph is copied onto a single `FLOW` edge type first (verified: yields `maxFlow`, `edges`, `edgeFlows`; `maxFlow` comes back as a float). |
| List graphs | `db.list_graphs()` | |

## Not usable (found by the spike)

- `shortestPath((a)-[*]->(b))` in `MATCH`: FalkorDB only allows it in `WITH`/`RETURN`.
- `allShortestPaths` unless both endpoints are already resolved.
- `algo.maxFlow` with several relationship types (see above).
- `algo.BFS(d, 6, 'CAN_INVOKE')` returned no rows for our graph. We do not use it.

## Known engine behaviour we design around

- An unreferenced relationship alias is only checked for existence, not enumerated. Queries
  that count or enumerate paths always reference the path (`nodes(p)` / `relationships(p)`).

## Queries the product relies on

This section is filled in as each phase lands; a test fails if a query listed here is
missing from `backend/graph/queries/`.
