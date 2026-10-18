"""Stack graph schema and loader.

Nodes : Agent, MCPServer, Tool, DataSource, Secret, Permission, Sink
Edges : (MCPServer)-[:EXPOSES]->(Tool)
        (DataSource)-[:READ_BY]->(Tool)
        (Tool)-[:RETURNS_TO]->(Agent)
        (Agent)-[:CAN_INVOKE {gated}]->(Tool)
        (Tool)-[:REACHES {scoped}]->(Sink)
        (Tool)-[:HOLDS]->(Secret|Permission)

`gated` and `scoped` are the two soft fix levers: a gated CAN_INVOKE needs a human click, and a
scoped REACHES means the tool's token can no longer touch that sink. Path queries skip both.
The original spec is stored on the Agent node as `spec_json` so a patched config can be
derived from the graph alone.
"""
import json
import time

from backend.graph import client
from backend.graph.client import Graph, stack_graph_name
from backend.parser.models import StackSpec

TRUST_RANK = {"untrusted": 0, "internal": 1, "trusted": 2}

INDEXES = [
    "CREATE INDEX FOR (n:Tool) ON (n.id)",
    "CREATE INDEX FOR (n:DataSource) ON (n.id)",
    "CREATE INDEX FOR (n:Sink) ON (n.id)",
    "CREATE INDEX FOR (n:Agent) ON (n.id)",
]


def _collect(spec: StackSpec) -> dict[str, list[dict]]:
    """Flatten the spec into node/edge rows, de-duplicating shared sources, sinks and secrets."""
    rows: dict[str, list[dict]] = {
        k: []
        for k in ("servers", "tools", "sources", "sinks", "secrets", "perms",
                  "exposes", "reads", "invokes", "returns", "reaches", "holds_s", "holds_p")
    }
    seen_tools: set[str] = set()
    sources: dict[str, dict] = {}
    sinks: dict[str, dict] = {}
    secrets: dict[str, dict] = {}
    perms: dict[str, dict] = {}
    agent = spec.agent.id

    for server in spec.servers:
        rows["servers"].append({"id": server.id, "command": server.command,
                                "description_trust": server.description_trust})
        for tool in server.tools:
            if tool.name in seen_tools:
                raise ValueError(
                    f"tool name {tool.name!r} appears twice in stack {spec.id!r}; "
                    "tool names must be unique so the Guard can identify calls"
                )
            seen_tools.add(tool.name)
            rows["tools"].append({
                "id": tool.name, "server": server.id, "description": tool.description,
                "side_effect": tool.side_effect, "confirmed": tool.confirmed,
                "annotation": json.dumps(tool.annotation),
            })
            rows["exposes"].append({"server": server.id, "tool": tool.name})
            rows["returns"].append({"tool": tool.name, "agent": agent})
            rows["invokes"].append({"agent": agent, "tool": tool.name, "gated": tool.gated})

            for d in tool.reads or []:
                prev = sources.get(d.id)
                trust = d.trust if not prev or TRUST_RANK[d.trust] < TRUST_RANK[prev["trust"]] \
                    else prev["trust"]
                sources[d.id] = {"id": d.id, "label": d.label or d.id, "trust": trust}
                rows["reads"].append({"source": d.id, "tool": tool.name})
            for r in tool.reaches or []:
                prev = sinks.get(r.id)
                if prev and prev["kind"] != r.kind:
                    raise ValueError(
                        f"sink {r.id!r} declared as both {prev['kind']} and {r.kind}"
                    )
                sinks[r.id] = {"id": r.id, "label": r.label or r.id, "kind": r.kind}
                rows["reaches"].append({"tool": tool.name, "sink": r.id, "scoped": r.scoped})
            for h in tool.holds or []:
                target, edge = (secrets, "holds_s") if h.type == "secret" else (perms, "holds_p")
                target[h.id] = {"id": h.id, "label": h.label or h.id, "sensitivity": h.sensitivity}
                rows[edge].append({"tool": tool.name, "target": h.id})

        if server.description_trust == "untrusted":
            # Poisoned tool descriptions are attacker-influenced text that reaches the agent
            # whenever it lists the server's tools, so model them as an untrusted data source.
            ds_id = f"{server.id}-tool-descriptions"
            sources[ds_id] = {"id": ds_id, "label": f"{server.id} tool descriptions",
                              "trust": "untrusted"}
            for tool in server.tools:
                rows["reads"].append({"source": ds_id, "tool": tool.name})

    rows["sources"] = list(sources.values())
    rows["sinks"] = list(sinks.values())
    rows["secrets"] = list(secrets.values())
    rows["perms"] = list(perms.values())
    return rows


def load_stack(spec: StackSpec) -> dict:
    """(Re)create the graph `stack:<id>` from a spec. Returns a summary with timings."""
    t0 = time.perf_counter()
    g = Graph(stack_graph_name(spec.id))
    g.delete()
    g = Graph(stack_graph_name(spec.id))
    rows = _collect(spec)
    agent = spec.agent

    for stmt in INDEXES:
        g.query(stmt)
    g.query(
        "CREATE (:Agent {id:$id, name:$name, stack:$stack, spec_json:$spec})",
        {"id": agent.id, "name": agent.name or agent.id, "stack": spec.id,
         "spec": spec.model_dump_json()},
    )
    g.query("UNWIND $rows AS r CREATE (:MCPServer {id:r.id, command:r.command, "
            "description_trust:r.description_trust})", {"rows": rows["servers"]})
    g.query("UNWIND $rows AS r CREATE (:Tool {id:r.id, server:r.server, description:r.description, "
            "side_effect:r.side_effect, confirmed:r.confirmed, annotation:r.annotation})",
            {"rows": rows["tools"]})
    g.query("UNWIND $rows AS r CREATE (:DataSource {id:r.id, label:r.label, trust:r.trust})",
            {"rows": rows["sources"]})
    g.query("UNWIND $rows AS r CREATE (:Sink {id:r.id, label:r.label, kind:r.kind})",
            {"rows": rows["sinks"]})
    g.query("UNWIND $rows AS r CREATE (:Secret {id:r.id, label:r.label, sensitivity:r.sensitivity})",
            {"rows": rows["secrets"]})
    g.query("UNWIND $rows AS r CREATE (:Permission {id:r.id, label:r.label, "
            "sensitivity:r.sensitivity})", {"rows": rows["perms"]})

    g.query("UNWIND $rows AS r MATCH (s:MCPServer {id:r.server}), (t:Tool {id:r.tool}) "
            "CREATE (s)-[:EXPOSES]->(t)", {"rows": rows["exposes"]})
    g.query("UNWIND $rows AS r MATCH (d:DataSource {id:r.source}), (t:Tool {id:r.tool}) "
            "CREATE (d)-[:READ_BY]->(t)", {"rows": rows["reads"]})
    g.query("UNWIND $rows AS r MATCH (t:Tool {id:r.tool}), (a:Agent {id:r.agent}) "
            "CREATE (t)-[:RETURNS_TO]->(a)", {"rows": rows["returns"]})
    g.query("UNWIND $rows AS r MATCH (a:Agent {id:r.agent}), (t:Tool {id:r.tool}) "
            "CREATE (a)-[:CAN_INVOKE {gated:r.gated}]->(t)", {"rows": rows["invokes"]})
    g.query("UNWIND $rows AS r MATCH (t:Tool {id:r.tool}), (s:Sink {id:r.sink}) "
            "CREATE (t)-[:REACHES {scoped:r.scoped}]->(s)", {"rows": rows["reaches"]})
    g.query("UNWIND $rows AS r MATCH (t:Tool {id:r.tool}), (s:Secret {id:r.target}) "
            "CREATE (t)-[:HOLDS]->(s)", {"rows": rows["holds_s"]})
    g.query("UNWIND $rows AS r MATCH (t:Tool {id:r.tool}), (s:Permission {id:r.target}) "
            "CREATE (t)-[:HOLDS]->(s)", {"rows": rows["holds_p"]})

    counts = g.ro_query(
        "MATCH (n) WITH count(n) AS nodes MATCH ()-[r]->() RETURN nodes, count(r) AS edges"
    ).dicts()[0]
    return {
        "stack": spec.id,
        "graph": g.name,
        "nodes": counts["nodes"],
        "edges": counts["edges"],
        "load_ms": round((time.perf_counter() - t0) * 1000, 1),
    }


def stack_ids() -> list[str]:
    return sorted(n.removeprefix("stack:") for n in client.list_graphs() if n.startswith("stack:"))


def delete_stack(stack_id: str) -> None:
    Graph(stack_graph_name(stack_id)).delete()


def stored_spec(stack_id: str) -> StackSpec:
    g = Graph(stack_graph_name(stack_id))
    if not g.exists():
        raise KeyError(stack_id)
    row = g.ro_query("MATCH (a:Agent) RETURN a.spec_json LIMIT 1").rows
    return StackSpec.model_validate_json(row[0][0])
