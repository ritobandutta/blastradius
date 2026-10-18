"""Defense graph: the cheapest set of changes that severs every untrusted -> sink path.

Step 1  paths come from FalkorDB (analysis.paths_to_sinks, a Cypher query).
Step 2  those paths are folded into a flow network. Each tool is split into two roles so a tool
        that both ingests and acts (fetch_url) cannot create a shortcut that skips the agent:

            SRC -> source -> in:T -> agent -> act:U -> sink -> SNK

        edge                 fix that severs it                       cost
        in:T  -> agent       remove tool T  (the only way to stop     10   (high)
                             T's output from reaching the agent)
        agent -> act:U       put a confirmation gate on U              1   (low)
        act:U -> sink        scope U's token away from that sink       3   (medium)
        everything else      no lever                                 INF

Step 3  min-cut over that network picks the cheapest fixes (networkx). The same network is also
        loaded into a FalkorDB scratch graph and algo.maxFlow is run on it: by the max-flow/
        min-cut theorem the two numbers must agree, and we report both.

Constraints let the user say "this tool must stay ungated" (`keep_ungated`) or "this tool must
not be removed" (`keep_tools`); those edges become INF and the cut routes around them.
"""
import uuid
from dataclasses import dataclass, field

import networkx as nx

from backend.graph import analysis
from backend.graph.client import Graph

COST = {"gate": 1, "scope": 3, "remove_tool": 10}
INF = 1000


@dataclass
class Fix:
    action: str  # gate | scope | remove_tool
    tool: str
    sink: str | None
    cost: int
    paths_severed: int = 0

    def to_dict(self) -> dict:
        return {"action": self.action, "tool": self.tool, "sink": self.sink, "cost": self.cost,
                "paths_severed": self.paths_severed, "describe": self.describe()}

    def describe(self) -> str:
        if self.action == "gate":
            return f"Require human confirmation before the agent calls {self.tool}"
        if self.action == "scope":
            return f"Scope {self.tool}'s token so it can no longer reach {self.sink}"
        return f"Remove {self.tool} from the agent"


@dataclass
class FixPlan:
    stack: str
    paths_before: int
    open_risk_before: float
    fixes: list[Fix] = field(default_factory=list)
    cut_value: float = 0.0  # networkx min-cut value
    maxflow_falkordb: float | None = None  # FalkorDB algo.maxFlow on the same network
    maxflow_ms: float | None = None
    plan_cost: int = 0  # after de-duplicating fixes on removed tools
    constraints: dict = field(default_factory=dict)
    query_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "stack": self.stack, "paths_before": self.paths_before,
            "open_risk_before": self.open_risk_before,
            "fixes": [f.to_dict() for f in self.fixes],
            "cut_value_networkx": self.cut_value,
            "maxflow_falkordb": self.maxflow_falkordb,
            "maxflow_ms": self.maxflow_ms,
            "maxflow_agrees": self.maxflow_falkordb is not None
            and abs(self.maxflow_falkordb - self.cut_value) < 1e-6,
            "plan_cost": self.plan_cost, "constraints": self.constraints,
            "path_query_ms": self.query_ms,
        }


def _role(prefix: str, tool: str) -> str:
    return f"{prefix}:{tool}"


def build_network(paths: list[analysis.AttackPath], keep_ungated: set[str],
                  keep_tools: set[str]) -> nx.DiGraph:
    g = nx.DiGraph()

    def add(u, v, cap, fix=None):
        if g.has_edge(u, v):
            return
        g.add_edge(u, v, capacity=cap, fix=fix)

    for p in paths:
        i, a = _role("in", p.ingest_tool), p.agent
        act = _role("act", p.act_tool)
        add("SRC", p.source, INF)
        add(p.source, i, INF)
        add(i, a, INF if p.ingest_tool in keep_tools else COST["remove_tool"],
            ("remove_tool", p.ingest_tool, None))
        add(a, act, INF if p.act_tool in keep_ungated else COST["gate"],
            ("gate", p.act_tool, None))
        add(act, p.sink, COST["scope"], ("scope", p.act_tool, p.sink))
        add(p.sink, "SNK", INF)
    return g


def _cut_edges(g: nx.DiGraph) -> tuple[float, list[tuple]]:
    value, (reach, rest) = nx.minimum_cut(g, "SRC", "SNK")
    cut = [(u, v) for u in reach for v in g[u] if v in rest]
    return value, cut


def _falkordb_maxflow(g: nx.DiGraph) -> tuple[float, float]:
    """Load the flow network into a scratch FalkorDB graph and run algo.maxFlow on it."""
    name = f"defense:{uuid.uuid4().hex[:10]}"
    scratch = Graph(name)
    try:
        scratch.named("defense_flow_load", {"nodes": list(g.nodes)}, write=True)
        scratch.named("defense_flow_edges", {"edges": [
            {"f": u, "t": v, "c": int(d["capacity"]), "fix": (d["fix"][0] if d["fix"] else "")}
            for u, v, d in g.edges(data=True)
        ]}, write=True)
        res = scratch.named("defense_maxflow")
        return float(res.rows[0][0]), res.run_time_ms
    finally:
        scratch.delete()


def plan(stack_id: str, keep_ungated: set[str] | None = None,
         keep_tools: set[str] | None = None) -> FixPlan:
    keep_ungated, keep_tools = keep_ungated or set(), keep_tools or set()
    report = analysis.paths_to_sinks(stack_id)
    out = FixPlan(stack_id, len(report.paths), report.open_risk,
                  constraints={"keep_ungated": sorted(keep_ungated),
                               "keep_tools": sorted(keep_tools)},
                  query_ms=report.run_time_ms)
    if not report.paths:
        out.maxflow_falkordb = 0.0
        return out

    g = build_network(report.paths, keep_ungated, keep_tools)
    value, cut = _cut_edges(g)
    if value >= INF:
        raise ValueError(
            "no fix severs every path under these constraints "
            f"(keep_ungated={sorted(keep_ungated)}, keep_tools={sorted(keep_tools)}); "
            "relax one of them"
        )
    out.cut_value = value
    out.maxflow_falkordb, out.maxflow_ms = _falkordb_maxflow(g)

    fixes: dict[tuple, Fix] = {}
    for u, v in cut:
        action, tool, sink = g[u][v]["fix"]
        fixes[(action, tool, sink)] = Fix(action, tool, sink, COST[action])
    # A removed tool needs no gate or scope of its own: count it once.
    removed = {f.tool for f in fixes.values() if f.action == "remove_tool"}
    kept = [f for f in fixes.values() if f.action == "remove_tool" or f.tool not in removed]
    for f in kept:
        f.paths_severed = sum(1 for p in report.paths if _severs(f, p))
    out.fixes = sorted(kept, key=lambda f: (-f.paths_severed, f.action, f.tool))
    out.plan_cost = sum(f.cost for f in out.fixes)
    return out


def _severs(f: Fix, p: analysis.AttackPath) -> bool:
    if f.action == "remove_tool":
        return f.tool in (p.ingest_tool, p.act_tool)
    if f.action == "gate":
        return f.tool == p.act_tool
    return f.tool == p.act_tool and f.sink == p.sink
