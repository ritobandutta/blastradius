"""The per-session taint graph, written to FalkorDB on every step.

Graph `session:<id>`:
  (Session {id, stack, score, lockdown, next_seq})
  (Event {seq, tool, args_hash, tainted, decision, executed, status, reasons, dlp, ts})
  (Event)-[:NEXT]->(Event)            order of calls
  (Event)-[:DERIVED_FROM]->(Event)    this call ran while that tainted event was in context

`tainted` means "this tool reads an untrusted source". `executed` means the call really ran
(ALLOW, or an ESCALATE a human approved), so only executed tainted events put attacker-
influenced data into the agent's context.
"""
import json

from backend.graph.client import Graph, GraphQueryError, session_graph_name


def session_graph(session_id: str) -> Graph:
    return Graph(session_graph_name(session_id))


def init_session(g: Graph, session_id: str, stack_id: str, ts: float) -> dict:
    row = g.named("session_init", {"id": session_id, "stack": stack_id, "ts": ts}, write=True)
    return row.dicts()[0]


def next_seq(g: Graph, session_id: str) -> int:
    return g.named("session_next_seq", {"id": session_id}, write=True).rows[0][0]


def tainted_events(g: Graph) -> list[dict]:
    return g.named("session_taint").dicts()


def drift(g: Graph, tool: str, args_hash: str, ts: float) -> dict:
    from backend.guard import trust

    return g.named(
        "session_drift",
        {"tool": tool, "args_hash": args_hash, "burst_since": ts - trust.BURST_WINDOW,
         "enum_since": ts - trust.ENUM_WINDOW},
    ).dicts()[0]


def penalize(g: Graph, session_id: str, points: int, threshold: int) -> dict:
    return g.named(
        "session_penalize", {"id": session_id, "penalty": points, "threshold": threshold},
        write=True,
    ).dicts()[0]


def record_event(
    g: Graph, seq: int, tool: str, args_hash: str, tainted: bool, decision: str, executed: bool,
    status: str, reasons: list[str], dlp: list[str], ts: float, derived: bool,
) -> None:
    g.named(
        "session_record_event",
        {"seq": seq, "tool": tool, "args_hash": args_hash, "tainted": tainted,
         "decision": decision, "executed": executed, "status": status,
         "reasons": json.dumps(reasons), "dlp": json.dumps(dlp), "ts": ts},
        write=True,
    )
    if seq > 1:
        g.named("session_link_next", {"prev": seq - 1, "seq": seq}, write=True)
    if derived:
        g.named("session_link_derived", {"seq": seq}, write=True)


def event_status(g: Graph, seq: int) -> dict | None:
    rows = g.named("session_event_status", {"seq": seq}).dicts()
    return rows[0] if rows else None


def session_view(session_id: str) -> dict:
    g = session_graph(session_id)
    try:
        rows = g.named("session_events").dicts()
    except GraphQueryError as e:
        # FalkorDB reports a graph that was never created as "empty key". That is simply
        # an unknown session (404), not a failed query (500).
        if "empty key" in e.message:
            raise KeyError(session_id) from e
        raise
    if not rows:
        raise KeyError(session_id)
    head = rows[0]
    events = []
    for r in rows:
        if r["seq"] is None:
            continue
        events.append({
            "seq": r["seq"], "tool": r["tool"], "decision": r["decision"], "status": r["status"],
            "tainted": r["tainted"], "executed": r["executed"],
            "reasons": json.loads(r["reasons"] or "[]"), "dlp": json.loads(r["dlp"] or "[]"),
            "ts": r["ts"],
        })
    edges = g.named("session_edges").dicts()
    return {"session": session_id, "stack": head["stack"], "score": head["score"],
            "lockdown": bool(head["lockdown"]), "events": events, "edges": edges}
