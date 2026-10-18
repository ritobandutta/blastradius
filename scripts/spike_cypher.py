"""Phase 0 spike: confirm FalkorDB syntax against the real container.

Run: uv run python scripts/spike_cypher.py
Every block prints OK/FAIL so docs/CYPHER.md only records syntax we verified.
"""
import time
import traceback

from falkordb import FalkorDB

db = FalkorDB(host="localhost", port=6390)
G = "spike_graph"
try:
    db.select_graph(G).delete()
except Exception:
    pass
g = db.select_graph(G)


def step(name, fn):
    try:
        out = fn()
        print(f"OK   {name}: {out}")
    except Exception as e:  # noqa: BLE001
        print(f"FAIL {name}: {type(e).__name__}: {e}")
        traceback.print_exc(limit=1)


# --- seed: untrusted -> tool -> agent -> tool -> sink, plus a diamond for cuts
g.query(
    """
CREATE (d:DataSource {id:'email', trust:'untrusted'}),
       (t1:Tool {id:'read_email', side_effect:'read'}),
       (a:Agent {id:'agent'}),
       (t2:Tool {id:'slack_post', side_effect:'network_out'}),
       (t3:Tool {id:'http_post', side_effect:'network_out'}),
       (s:Sink {id:'slack', kind:'exfil'}),
       (d)-[:READ_BY]->(t1), (t1)-[:RETURNS_TO]->(a),
       (a)-[:CAN_INVOKE]->(t2), (a)-[:CAN_INVOKE]->(t3),
       (t2)-[:REACHES]->(s), (t3)-[:REACHES]->(s)
"""
)

step("params + result_set + header", lambda: (
    lambda r: (r.result_set, r.header)
)(g.ro_query("MATCH (n:Tool) WHERE n.id = $id RETURN n.id, n.side_effect", {"id": "read_email"})))

step("run_time attrs", lambda: (
    lambda r: {k: getattr(r, k, 'MISSING') for k in
               ('run_time_ms', 'internal_execution_time', 'nodes_created')}
)(g.ro_query("MATCH (n) RETURN count(n)")))

step("var-length path, nodes(p) ids", lambda: g.ro_query(
    "MATCH p=(d:DataSource {trust:'untrusted'})-[*1..6]->(s:Sink) "
    "RETURN [n IN nodes(p) | n.id], length(p)").result_set)

step("var-length typed alternation", lambda: g.ro_query(
    "MATCH p=(d:DataSource)-[:READ_BY|RETURNS_TO|CAN_INVOKE|REACHES*1..6]->(s:Sink) "
    "RETURN [n IN nodes(p) | n.id]").result_set)

step("relationships(p) + edge alias reference (uniqueness limit)", lambda: g.ro_query(
    "MATCH p=(d:DataSource)-[*1..6]->(s:Sink) "
    "RETURN [r IN relationships(p) | type(r)]").result_set)

step("shortestPath", lambda: g.ro_query(
    "MATCH (d:DataSource {id:'email'}), (s:Sink {id:'slack'}) "
    "MATCH p=shortestPath((d)-[*]->(s)) RETURN [n IN nodes(p) | n.id]").result_set)

step("allShortestPaths", lambda: g.ro_query(
    "MATCH (d:DataSource {id:'email'}), (s:Sink {id:'slack'}) "
    "MATCH p=allShortestPaths((d)-[*]->(s)) RETURN [n IN nodes(p) | n.id]").result_set)

step("algo.SSpaths", lambda: g.ro_query(
    "MATCH (d:DataSource {id:'email'}) CALL algo.SSpaths({sourceNode:d, "
    "relTypes:['READ_BY','RETURNS_TO','CAN_INVOKE','REACHES'], maxLen:6, "
    "relDirection:'outgoing', pathCount:100}) YIELD path "
    "RETURN [n IN nodes(path) | n.id]").result_set)

step("algo.SPpaths", lambda: g.ro_query(
    "MATCH (d:DataSource {id:'email'}), (s:Sink {id:'slack'}) CALL algo.SPpaths({sourceNode:d, "
    "targetNode:s, relTypes:['READ_BY','RETURNS_TO','CAN_INVOKE','REACHES'], maxLen:6, "
    "pathCount:0}) YIELD path RETURN [n IN nodes(path) | n.id]").result_set)

step("algo.betweenness", lambda: g.ro_query(
    "CALL algo.betweenness({samplingSeed:42}) YIELD node, score "
    "RETURN node.id, score ORDER BY score DESC").result_set)

step("algo.WCC", lambda: g.ro_query(
    "CALL algo.WCC() YIELD node, componentId RETURN node.id, componentId").result_set)

step("algo.pageRank", lambda: g.ro_query(
    "CALL algo.pageRank('Tool','CAN_INVOKE') YIELD node, score RETURN node.id, score").result_set)

step("algo.BFS", lambda: g.ro_query(
    "MATCH (d:DataSource {id:'email'}) CALL algo.BFS(d, 6, 'CAN_INVOKE') "
    "YIELD nodes, edges RETURN size(nodes)").result_set)

# maxFlow needs a capacity property on edges
g.query("MATCH ()-[r]->() SET r.capacity = 1")
step("algo.maxFlow", lambda: g.ro_query(
    "MATCH (d:DataSource {id:'email'}), (s:Sink {id:'slack'}) "
    "CALL algo.maxFlow({sourceNodes:[d], targetNodes:[s], "
    "relationshipTypes:['READ_BY','RETURNS_TO','CAN_INVOKE','REACHES'], "
    "capacityProperty:'capacity'}) YIELD maxFlow RETURN maxFlow").result_set)

step("list_graphs", lambda: db.list_graphs())

step("latency of var-length query (ms wall)", lambda: (
    lambda t0, _r, t1: round((t1 - t0) * 1000, 2)
)(time.perf_counter(), g.ro_query(
    "MATCH p=(d:DataSource)-[*1..6]->(s:Sink) RETURN count(p)"), time.perf_counter()))

g.delete()
