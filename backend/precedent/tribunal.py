"""Tribunal: Prosecutor, Defense and Judge argue a pending ESCALATE, for the human's benefit.

This is advisory text. It has no authority, and the code makes that structural:

  * It only accepts an event whose decision is ESCALATE and whose status is still pending.
    A DENY (or an already-resolved event) is refused before any LLM is called.
  * It never imports or calls approvals.resolve or decide.check, and it writes nothing to the
    session graph. Its only write is a `Ruling` node in the precedent graph. A test asserts the
    event is byte-for-byte unchanged afterwards, and that this module cannot reach approvals.
  * The Judge cites earlier Rulings about the same tool (precedent_rulings_for_tool), linked
    with (Ruling)-[:CITES]->(Ruling).

In MOCK MODE the three roles are produced by a deterministic template from the same graph facts
and every response carries mock=true, so the UI shows the MOCK MODE badge.
"""
import json
import uuid

from backend.graph.client import Graph, session_graph_name
from backend.llm import base as llm
from backend.precedent import store

ADVISORY = "Advisory only. The deterministic Guard keeps final authority; only a human can approve."


class NotEscalated(ValueError):
    """The event is not a pending ESCALATE, so the Tribunal has nothing to argue."""


def _event(session_id: str, seq: int) -> dict:
    rows = Graph(session_graph_name(session_id)).named("session_event", {"seq": seq}).dicts()
    if not rows:
        raise KeyError(f"event {seq} in session {session_id!r}")
    return rows[0]


def _facts(ev: dict) -> str:
    reasons = json.loads(ev["reasons"] or "[]")
    return (f"tool={ev['tool']}; decision={ev['decision']}; context_tainted={bool(ev['tainted'])}; "
            f"reasons={'; '.join(reasons)}")


def _mock_role(role: str, ev: dict, past: list[dict]) -> str:
    reasons = "; ".join(json.loads(ev["reasons"] or "[]")) or "no reason recorded"
    if role == "prosecutor":
        return (f"The call to {ev['tool']} was escalated because: {reasons}. If the content the "
                "agent read was attacker-influenced, this call is how it would act on it.")
    if role == "defense":
        return (f"{ev['tool']} may be exactly what the user asked for. The Guard escalated on the "
                "structure of the path, not on any sign that the content was malicious, so a "
                "legitimate workflow looks identical.")
    n = len(past)
    cited = (f" Earlier rulings on {ev['tool']}: " +
             "; ".join(f"{p['id']} ({p['verdict']})" for p in past) + ".") if n else \
        f" No earlier rulings on {ev['tool']}."
    return ("Verdict: HOLD. Treat this as unapproved until a human confirms the destination and "
            "payload are what they intended." + cited)


def _ask(role: str, system: str, prompt: str, ev: dict, past: list[dict]) -> llm.LLMResult:
    return llm.run(system, prompt, fallback=lambda: _mock_role(role, ev, past), max_tokens=350)


def _verdict(text: str) -> str:
    low = text.lower()
    if "verdict: allow" in low or "verdict: approve" in low:
        return "ALLOW"
    return "HOLD"


def hear(session_id: str, seq: int) -> dict:
    ev = _event(session_id, seq)
    if ev["decision"] != "ESCALATE" or ev["status"] != "pending":
        raise NotEscalated(
            f"event {seq} is {ev['decision']}/{ev['status']}: the Tribunal only hears pending "
            "ESCALATE calls. A DENY is final and is never reopened."
        )
    stack = ev["stack"]
    past = store.read("precedent_rulings_for_tool", {"tool": ev["tool"], "limit": 3})
    facts = _facts(ev)
    history = "\n".join(f"- {p['id']}: {p['verdict']} ({p['summary'][:120]})" for p in past) \
        or "(none)"
    sys_p = "You are a security prosecutor in a hearing about a pending AI-agent tool call."
    sys_d = "You are the defense in a hearing about a pending AI-agent tool call."
    sys_j = ("You are the judge. Reply with 'Verdict: HOLD' or 'Verdict: ALLOW' and two sentences. "
             "Your ruling is advisory and a human decides.")

    pros = _ask("prosecutor", sys_p, f"Argue why this call is dangerous in 3 sentences.\n{facts}",
                ev, past)
    defn = _ask("defense", sys_d, f"Argue why this call is legitimate in 3 sentences.\n{facts}",
                ev, past)
    judge = _ask("judge", sys_j,
                 f"{facts}\nProsecutor: {pros.text}\nDefense: {defn.text}\n"
                 f"Earlier rulings on this tool:\n{history}", ev, past)

    mock = pros.mock or defn.mock or judge.mock
    error = next((r.error for r in (pros, defn, judge) if r.error), None)
    ruling_id = f"ruling-{uuid.uuid4().hex[:10]}"
    verdict = _verdict(judge.text)
    # The only write the Tribunal performs: a Ruling in the precedent graph.
    store.ensure().named("precedent_record_ruling", {
        "id": ruling_id, "tool": ev["tool"], "stack": stack, "session": session_id, "seq": seq,
        "verdict": verdict, "summary": judge.text[:600], "mock": mock,
        "model": judge.model, "ts": store.now(), "cites": [p["id"] for p in past],
    }, write=True)
    return {
        "ruling": ruling_id, "advisory": True, "notice": ADVISORY,
        "mock_mode": mock, "model": judge.model, "llm_error": error,
        "event": {"session": session_id, "seq": seq, "tool": ev["tool"],
                  "decision": ev["decision"], "status": ev["status"]},
        "prosecutor": pros.text, "defense": defn.text, "judge": judge.text,
        "suggested_verdict": verdict, "cites": past,
    }


def chain(ruling_id: str) -> dict:
    rows = store.read("precedent_ruling_chain", {"id": ruling_id})
    if not rows:
        raise KeyError(ruling_id)
    row = rows[0]
    row["cites"] = [c for c in row["cites"] if c.get("id")]
    return row
