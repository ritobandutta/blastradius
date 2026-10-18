"""Replay recorded benign sessions to measure false positives.

A defence that blocks everything would score 100% in the attack table, so every comparison also
reports what each defence does to legitimate work. The Guard is replayed through the real
decide.check (FalkorDB); the naive filter is replayed over the text the session reads.
"""
import json
import uuid
from pathlib import Path

from backend.graph.client import Graph, session_graph_name
from backend.guard import decide
from backend.redteam import naive_filter
from demo.toy_agent.tools import BENIGN_EMAIL, BENIGN_NOTES, BENIGN_PAGE

BENIGN_DIR = Path(__file__).resolve().parent.parent.parent / "demo" / "benign_sessions"
_BENIGN_TEXT = [BENIGN_EMAIL, BENIGN_PAGE, BENIGN_NOTES]


def load_sessions(name: str = "vulnerable") -> list[dict]:
    return json.loads((BENIGN_DIR / f"{name}.json").read_text())["sessions"]


def replay_guard(stack_id: str, session: dict) -> dict:
    """Run one recorded session through the Guard. Returns per-call decisions."""
    sid = f"benign-{uuid.uuid4().hex[:8]}"
    steps = []
    try:
        for call in session["calls"]:
            d = decide.check(sid, stack_id, call["tool"], call.get("args"))
            steps.append({"tool": call["tool"], "decision": d.decision, "reasons": d.reasons})
    finally:
        Graph(session_graph_name(sid)).delete()
    blocked = [s for s in steps if s["decision"] != decide.ALLOW]
    return {"name": session["name"], "description": session.get("description", ""),
            "steps": steps, "blocked": bool(blocked),
            "first_block": blocked[0] if blocked else None}


def replay_naive(session: dict) -> dict:
    hits = [naive_filter.scan(t) for t in _BENIGN_TEXT]
    return {"name": session["name"], "blocked": any(hits)}


def false_positive_report(stack_id: str, name: str = "vulnerable") -> dict:
    sessions = load_sessions(name)
    guard = [replay_guard(stack_id, s) for s in sessions]
    naive = [replay_naive(s) for s in sessions]
    return {
        "sessions": len(sessions),
        "guard_blocked": sum(g["blocked"] for g in guard),
        "naive_blocked": sum(n["blocked"] for n in naive),
        "guard": guard,
        "naive": naive,
    }
