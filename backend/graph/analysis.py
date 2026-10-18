"""Attack-surface analysis. Every answer is a FalkorDB query result, returned with its path.

paths_to_sinks      exact attack paths (Cypher pattern match)
toxic_combinations  agents holding the lethal trifecta
choke_points        paths-through-tool counts (Cypher) + betweenness (algo.betweenness)
blast_radius        weighted score per path and a total "open risk"

Score of one path = sink_weight * (1 + secret_sensitivity/5) * hop_factor
  sink_weight   exec 10, mutate 7, exfil 8   (code execution is worst, then data loss)
  secret factor a tool on the path holding a 5/5 secret doubles the score
  hop_factor    1.0 if one tool does both ingest and act (the attacker needs one capability),
                0.85 if two different tools are needed
"""
from dataclasses import dataclass, field

from backend.graph.client import Graph, stack_graph_name

SINK_WEIGHT = {"exec": 10.0, "mutate": 7.0, "exfil": 8.0}


@dataclass
class AttackPath:
    source: str
    source_label: str
    ingest_tool: str
    agent: str
    act_tool: str
    sink: str
    sink_kind: str
    sink_label: str
    secret_sensitivity: int
    score: float = 0.0

    @property
    def nodes(self) -> list[str]:
        return [self.source, self.ingest_tool, self.agent, self.act_tool, self.sink]

    @property
    def id(self) -> str:
        return ">".join(self.nodes)

    def edges(self) -> list[tuple[str, str, str]]:
        return [
            (self.source, self.ingest_tool, "READ_BY"),
            (self.ingest_tool, self.agent, "RETURNS_TO"),
            (self.agent, self.act_tool, "CAN_INVOKE"),
            (self.act_tool, self.sink, "REACHES"),
        ]

    def to_dict(self) -> dict:
        return {
            "id": self.id, "nodes": self.nodes, "source": self.source,
            "source_label": self.source_label, "ingest_tool": self.ingest_tool,
            "agent": self.agent, "act_tool": self.act_tool, "sink": self.sink,
            "sink_kind": self.sink_kind, "sink_label": self.sink_label,
            "secret_sensitivity": self.secret_sensitivity, "score": self.score,
            "edges": [{"from": a, "to": b, "type": t} for a, b, t in self.edges()],
        }


def score_path(p: AttackPath) -> float:
    hop = 1.0 if p.ingest_tool == p.act_tool else 0.85
    return round(SINK_WEIGHT[p.sink_kind] * (1 + p.secret_sensitivity / 5.0) * hop, 2)


@dataclass
class PathReport:
    stack: str
    paths: list[AttackPath] = field(default_factory=list)
    run_time_ms: float = 0.0  # time FalkorDB spent on the query
    wall_ms: float = 0.0

    @property
    def open_risk(self) -> float:
        return round(sum(p.score for p in self.paths), 2)

    def to_dict(self) -> dict:
        return {
            "stack": self.stack,
            "path_count": len(self.paths),
            "open_risk": self.open_risk,
            "paths": [p.to_dict() for p in self.paths],
            "query": "paths_to_sinks",
            "run_time_ms": self.run_time_ms,
            "wall_ms": self.wall_ms,
        }


def paths_to_sinks(stack_id: str) -> PathReport:
    res = Graph(stack_graph_name(stack_id)).named("paths_to_sinks")
    paths = []
    for row in res.dicts():
        p = AttackPath(**row)
        p.score = score_path(p)
        paths.append(p)
    paths.sort(key=lambda p: (-p.score, p.id))
    return PathReport(stack_id, paths, res.run_time_ms, res.wall_ms)


def toxic_combinations(stack_id: str) -> dict:
    res = Graph(stack_graph_name(stack_id)).named("toxic_combinations")
    agents = res.dicts()
    return {
        "stack": stack_id,
        "toxic": any(a["toxic"] for a in agents),
        "agents": agents,
        "query": "toxic_combinations",
        "run_time_ms": res.run_time_ms,
        "wall_ms": res.wall_ms,
    }


def choke_points(stack_id: str) -> dict:
    g = Graph(stack_graph_name(stack_id))
    counts = g.named("choke_points")
    centrality = g.named("betweenness")
    on_paths = {r["tool"]: r["paths"] for r in counts.dicts()}
    tools = {r[0] for r in g.ro_query("MATCH (t:Tool) RETURN t.id").rows}
    ranked = [
        {"id": r["id"], "score": r["score"], "paths_through": on_paths.get(r["id"], 0)}
        for r in centrality.dicts()
        if r["id"] in tools
    ]
    ranked.sort(key=lambda r: (-r["paths_through"], -r["score"], r["id"]))
    return {
        "stack": stack_id,
        "choke_points": ranked,
        "queries": ["choke_points", "betweenness"],
        "run_time_ms": round(counts.run_time_ms + centrality.run_time_ms, 3),
    }


def tool_facts(stack_id: str, node_id: str) -> dict:
    """Why is this node on the graph? Used by the UI's click-a-node panel."""
    g = Graph(stack_graph_name(stack_id))
    node = g.ro_query(
        "MATCH (n {id:$id}) RETURN labels(n)[0] AS label, properties(n) AS props LIMIT 1",
        {"id": node_id},
    ).dicts()
    if not node:
        raise KeyError(node_id)
    props = {k: v for k, v in node[0]["props"].items() if k not in ("spec_json",)}
    edges = g.ro_query(
        "MATCH (n {id:$id})-[r]-(m) RETURN type(r) AS type, startNode(r).id = $id AS outgoing, "
        "m.id AS other, labels(m)[0] AS other_label, properties(r) AS props "
        "ORDER BY type, other",
        {"id": node_id},
    ).dicts()
    paths = [p for p in paths_to_sinks(stack_id).paths if node_id in p.nodes]
    return {"id": node_id, "label": node[0]["label"], "props": props, "edges": edges,
            "on_paths": [p.id for p in paths], "open_risk_through": round(sum(p.score for p in paths), 2)}


def graph_elements(stack_id: str) -> dict:
    """Full node/edge list for the visualizer (also straight from FalkorDB)."""
    g = Graph(stack_graph_name(stack_id))
    nodes = g.ro_query(
        "MATCH (n) RETURN n.id AS id, labels(n)[0] AS label, n.trust AS trust, n.kind AS kind, "
        "n.side_effect AS side_effect, n.sensitivity AS sensitivity, n.label AS name, "
        "n.confirmed AS confirmed"
    )
    edges = g.ro_query(
        "MATCH (a)-[r]->(b) RETURN a.id AS source, b.id AS target, type(r) AS type, "
        "coalesce(r.gated,false) AS gated, coalesce(r.scoped,false) AS scoped"
    )
    return {
        "stack": stack_id,
        "nodes": nodes.dicts(),
        "edges": edges.dicts(),
        "run_time_ms": round(nodes.run_time_ms + edges.run_time_ms, 3),
    }
