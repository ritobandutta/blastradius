"""The human approval gate.

Only a person can turn an ESCALATE into an ALLOW, and nothing can touch a DENY. The second
guarantee is enforced inside the database: `session_resolve.cypher` only matches an event whose
decision is ESCALATE and whose status is still pending. A DENY event never matches, so no
caller (the UI, the CLI, the Tribunal, a bug) can flip it.
"""
import time

from backend.graph import client
from backend.graph.client import Graph, session_graph_name
from backend.guard import taint


class ApprovalError(ValueError):
    """The event is not a pending ESCALATE (it does not exist, was a DENY, or was resolved)."""


def resolve(session_id: str, seq: int, approve: bool) -> dict:
    g = taint.session_graph(session_id)
    status, executed = ("approved", True) if approve else ("rejected", False)
    rows = g.named(
        "session_resolve",
        {"seq": seq, "status": status, "executed": executed, "ts": time.time()},
        write=True,
    ).dicts()
    if not rows:
        raise ApprovalError(
            f"event {seq} in session {session_id!r} is not a pending ESCALATE; "
            "DENY decisions can never be changed and resolved ESCALATEs are final"
        )
    return {**rows[0], "resolved_by": "human"}


def wait_for_resolution(session_id: str, seq: int, timeout: float, poll: float = 0.25) -> str:
    """Block until a human resolves the event. Returns 'approved', 'rejected' or 'pending'."""
    g = taint.session_graph(session_id)
    deadline = time.monotonic() + timeout
    while True:
        st = taint.event_status(g, seq)
        if st is None:
            return "rejected"
        if st["status"] != "pending":
            return st["status"]
        if time.monotonic() >= deadline:
            return "pending"
        time.sleep(poll)


def session_ids() -> list[str]:
    return sorted(n.removeprefix("session:") for n in client.list_graphs()
                  if n.startswith("session:"))


def pending() -> list[dict]:
    out = []
    for sid in session_ids():
        out += Graph(session_graph_name(sid)).named("session_pending").dicts()
    return sorted(out, key=lambda r: r["ts"])
