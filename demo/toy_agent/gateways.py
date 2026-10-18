"""The three things that can sit between the toy agent and its tools.

  unprotected  `Passthrough` (in agent.py)
  naive        keyword/regex filter on everything the agent reads
  guard        the real BlastRadius Guard, i.e. FalkorDB queries via decide.check()
"""
import uuid
from dataclasses import dataclass, field

from backend.graph.client import Graph, session_graph_name, stack_graph_name
from backend.guard import decide
from backend.redteam import naive_filter

REMOVED = "[content removed by keyword filter]"


@dataclass
class NaiveGateway:
    name: str = "naive-filter"
    hits: list[dict] = field(default_factory=list)

    def filter_content(self, source: str, text: str):
        hit = naive_filter.scan(text)
        if hit:
            self.hits.append({"source": source, **hit})
            return REMOVED, hit
        return text, None

    def before_call(self, tool: str, args: dict) -> dict:
        return {"allowed": True, "decision": "ALLOW", "note": "keyword filter does not gate calls"}


@dataclass
class ConfigGateway:
    """Enforces only what the (patched) stack config says, read from the stack graph.

    No taint tracking and no Guard: this isolates the patch. A gated tool needs a human, which a
    headless run never has, so the call does not happen. A sink whose token was scoped away is
    unreachable. `sink` is the sink the attack is trying to reach.
    """
    stack: str
    sink: str
    name: str = "config-only"

    def filter_content(self, source: str, text: str):
        return text, None

    def before_call(self, tool: str, args: dict) -> dict:
        rows = Graph(stack_graph_name(self.stack)).named("config_tool_state", {"tool": tool}).dicts()
        st = rows[0] if rows else {"gated": False, "scoped_sinks": []}
        if st["gated"]:
            return {"allowed": False, "decision": "ESCALATE",
                    "note": f"{tool} is gated: needs a human click, none present"}
        if self.sink in st["scoped_sinks"]:
            return {"allowed": False, "decision": "DENY",
                    "note": f"{tool}'s token is scoped away from {self.sink}"}
        return {"allowed": True, "decision": "ALLOW", "note": "config permits this call"}


@dataclass
class GuardGateway:
    stack: str
    session: str = field(default_factory=lambda: f"rt-{uuid.uuid4().hex[:10]}")
    name: str = "guard"
    decisions: list[dict] = field(default_factory=list)

    def filter_content(self, source: str, text: str):
        return text, None  # the Guard never reads content

    def before_call(self, tool: str, args: dict) -> dict:
        d = decide.check(self.session, self.stack, tool, args)
        self.decisions.append({"tool": tool, "decision": d.decision, "reasons": d.reasons,
                               "latency_ms": d.latency_ms})
        note = "; ".join(d.reasons)
        if d.decision == decide.ESCALATE:
            note = "needs a human, not approved in a headless run: " + note
        return {"allowed": d.decision == decide.ALLOW, "decision": d.decision, "note": note}

    def cleanup(self) -> None:
        Graph(session_graph_name(self.session)).delete()
