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
import threading

from backend.graph.client import Graph, GraphQueryError, session_graph_name


def session_graph(session_id: str) -> Graph:
    return Graph(session_graph_name(session_id))


_OPEN_LOCKS: dict[str, threading.Lock] = {}
_OPEN_LOCKS_GUARD = threading.Lock()


def _open_lock(session_id: str) -> threading.Lock:
    with _OPEN_LOCKS_GUARD:
        return _OPEN_LOCKS.setdefault(session_id, threading.Lock())


def open_session(g: Graph, session_id: str, stack_id: str, ts: float) -> dict:
    """Create the session if new and take the next event number (one query).

    Returns {stack, score, lockdown, seq}. If `stack` is not `stack_id` the session belongs to
    another stack: the counter did not advance and the caller must refuse.

    Why the lock: measured against FalkorDB, concurrent MERGEs of the same brand-new Session
    node can each create one, leaving duplicates and repeated event numbers (12 threads opening
    one new session produced up to 9 copies). The lock serializes opening within this process,
    which is where one session's calls arrive (the API server, or one proxy per session). It
    does NOT protect two separate processes opening the same new session at the same instant;
    that would need a database-level unique constraint.
    """
    with _open_lock(session_id):
        return g.named("session_init", {"id": session_id, "stack": stack_id, "ts": ts},
                       write=True).dicts()[0]


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
    """Write the event and its NEXT / DERIVED_FROM edges in a single query."""
    g.named(
        "session_record_event",
        {"seq": seq, "prev": seq - 1, "tool": tool, "args_hash": args_hash, "tainted": tainted,
         "decision": decision, "executed": executed, "status": status,
         "reasons": json.dumps(reasons), "dlp": json.dumps(dlp), "ts": ts, "derived": derived},
        write=True,
    )


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
