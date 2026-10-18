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

## Also verified (second spike)

- Edge predicates inside a path filter: `WHERE all(r IN relationships(p) WHERE NOT coalesce(r.gated,false))`.
  This is how a confirmation gate (`gated`) or a scoped token (`scoped`) removes an edge from
  the attack graph without deleting it.
- Pattern predicate in WHERE: `WHERE (t)-[:REACHES]->(:Sink)` works. `exists((t)-[...]->())` does **not**.
- `UNWIND nodes(p) AS n RETURN n.id, count(DISTINCT p)` gives exact "paths through this node" counts.
- `UNION`, `labels(n)`, `type(r)`, `startNode(r)`, `endNode(r)` all work.

## Known engine behaviour we design around

- **Variable-length paths may revisit nodes** (`email -> fetch_url -> agent -> fetch_url -> http`).
  Without a filter the same tool appears twice, which inflates path counts. Every path query
  therefore keeps only simple paths:
  `size(ids) = size(reduce(acc=[], x IN ids | CASE WHEN x IN acc THEN acc ELSE acc+[x] END))`.

- An unreferenced relationship alias is only checked for existence, not enumerated. Queries
  that count or enumerate paths always reference the path (`nodes(p)` / `relationships(p)`).

## Queries the product relies on

Each query lives in `backend/graph/queries/<name>.cypher`. A test fails if a `.cypher` file is
not listed here, so this catalog cannot drift from the code. Run on the per-stack graph
`stack:<id>` unless noted.

| Query | What it answers | FalkorDB features used |
|---|---|---|
| `paths_to_sinks` | Every open path `untrusted DataSource -> Tool -> Agent -> Tool -> Sink`, with the highest secret sensitivity on the path | Pattern match, `OPTIONAL MATCH`, edge predicates (`gated`, `scoped`) |
| `toxic_combinations` | Does an agent hold the lethal trifecta (untrusted ingest + private data/secret + exfil egress)? | Chained `OPTIONAL MATCH`, `collect(DISTINCT ...)` |
| `choke_points` | How many open paths run through each tool | `UNWIND`, `count(DISTINCT ...)` |
| `betweenness` | Centrality of each node over the capability edges | `algo.betweenness` |

### Guard queries

`guard_tool_facts` runs on the stack graph. The `session_*` queries run on the per-session graph
`session:<id>`, which holds `Session` and `Event` nodes linked by `NEXT` and `DERIVED_FROM`.

| Query | What it answers |
|---|---|
| `guard_tool_facts` | What a tool reads (untrusted sources), which sinks it still reaches, and whether the agent's `CAN_INVOKE` edge is gated |
| `session_init` | Create the session (`MERGE`), score starts at 100 |
| `session_next_seq` | Atomic event counter, safe under concurrent calls |
| `session_taint` | Is untrusted data in the agent's context? (executed + tainted events) |
| `session_drift` | Counts behind the trust-score signals: burst, enumeration, new tool |
| `session_penalize` | Lower the trust score and set sticky lockdown, atomically |
| `session_record_event` | Write one step as an `Event` node |
| `session_link_next` | `(prev)-[:NEXT]->(event)` |
| `session_link_derived` | `(event)-[:DERIVED_FROM]->(tainted event)`, the taint provenance |
| `session_resolve` | Human approve/deny. Only matches `decision = 'ESCALATE' AND status = 'pending'`, so a DENY can never change |
| `session_event_status` | Poll the outcome of one event while it waits for a human |
| `session_pending` | ESCALATE calls awaiting a human |
| `session_events` | Full step list and trust score for the live panel |
| `session_edges` | `NEXT` and `DERIVED_FROM` edges for drawing the taint graph |

This list grows as later phases add defense and precedent queries.
