"""The Guard: a deterministic ALLOW / ESCALATE / DENY decision for one pending tool call.

No LLM is involved anywhere in this file. Every fact the decision rests on is a FalkorDB query:

  guard_tool_facts    (stack graph)    what the tool reads, reaches, and whether it is gated
  session_taint       (session graph)  is attacker-influenced data in the agent's context?
  toxic_combinations  (stack graph)    does this agent hold the lethal trifecta?
  session_drift       (session graph)  counters behind the trust score

Rules, in order (first match wins):
  0. FalkorDB unreachable or tool unknown to the stack           -> DENY   (fail closed)
  1. session in Lockdown and the tool is not read-only           -> DENY
  2. tainted context, tool reaches a sink, agent is toxic        -> DENY   (structural, no text matching)
  3. secret-like string in the args of a tool that reaches exfil -> DENY
  3b. tainted context + tool reaches a sink + an ARMED learned    -> DENY   (precedent_rules_matching;
      rule matches (ingest tool already ran, this is the act tool)      the critic armed it from confirmed exploits)
  4. tainted context, tool reaches a sink, agent not toxic       -> ESCALATE
  5. tool is gated (config says a human must confirm)            -> ESCALATE
  6. otherwise                                                   -> ALLOW

The check never looks at the *text* of tool results, so a paraphrased or obfuscated injection
is treated exactly like an obvious one: what matters is the shape of the path.
"""
import time
from dataclasses import dataclass, field

from backend import config
from backend.graph import tenancy
from backend.graph.client import Graph, GraphUnavailable, parallel, stack_graph_name
from backend.guard import taint, trust
from backend.precedent import rules as precedent_rules

ALLOW, ESCALATE, DENY = "ALLOW", "ESCALATE", "DENY"


@dataclass
class Decision:
    decision: str
    reasons: list[str]
    session: str
    stack: str
    tool: str
    seq: int | None = None
    status: str = "decided"  # allowed | denied | pending
    tainted_call: bool = False
    context_tainted: bool = False
    score: int | None = None
    lockdown: bool = False
    penalties: list[dict] = field(default_factory=list)
    dlp: list[str] = field(default_factory=list)
    provenance: dict = field(default_factory=dict)
    fail_closed: bool = False
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "decision": self.decision, "status": self.status, "reasons": self.reasons,
            "session": self.session, "stack": self.stack, "tool": self.tool, "seq": self.seq,
            "tainted_call": self.tainted_call, "context_tainted": self.context_tainted,
            "trust_score": self.score, "lockdown": self.lockdown, "penalties": self.penalties,
            "dlp": self.dlp, "provenance": self.provenance, "fail_closed": self.fail_closed,
            "latency_ms": self.latency_ms,
        }


def fail_closed(session: str, stack: str, tool: str, why: str) -> Decision:
    return Decision(DENY, [f"fail closed: {why}"], session, stack, tool, status="denied",
                    fail_closed=True)


def check(session_id: str, stack_id: str, tool: str, args: dict | None = None,
          tenant: str = "public") -> Decision:
    t0 = time.perf_counter()
    try:
        d = _check(session_id, stack_id, tool, args, tenant)
    except GraphUnavailable as e:
        d = fail_closed(session_id, stack_id, tool, f"FalkorDB unavailable ({e})")
    d.latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    return d


def _check(session_id: str, stack_id: str, tool: str, args: dict | None,
           tenant: str = "public") -> Decision:
    now = time.time()
    stack_name = stack_graph_name(stack_id)
    stack = Graph(stack_name)

    # Round trips matter when FalkorDB is remote (each costs a network hop), so independent
    # reads go out together via parallel(). The ORDER of the dependent steps is unchanged:
    # no session graph is created until the stack is known to exist and to belong to the caller.
    #
    # Round trip 1: does the stack exist, and who owns it?
    owner, exists = parallel(lambda: tenancy.owner_of(stack_name), stack.exists)
    if owner != tenant or not exists:
        # A stack owned by someone else looks exactly like a stack that does not exist.
        return fail_closed(session_id, stack_id, tool, f"unknown stack {stack_id!r}")

    # Round trip 2: open the session (and take the next event number), and read the tool's facts.
    sg = taint.session_graph(session_id)
    sess, facts_res = parallel(
        lambda: taint.open_session(sg, session_id, stack_id, now),
        lambda: stack.named("guard_tool_facts", {"tool": tool}),
    )
    if sess["stack"] != stack_id:
        raise ValueError(
            f"session {session_id!r} belongs to stack {sess['stack']!r}, not {stack_id!r}"
        )
    seq = sess["seq"]

    facts = facts_res.dicts()[0] if facts_res.rows else None
    if facts is None or facts["tool"] is None:
        return _finish(sg, session_id, stack_id, tool, args, now, DENY,
                       [f"tool {tool!r} is not part of stack {stack_id!r}"],
                       tainted_call=False, context=[], facts={}, penalties=[], dlp=[],
                       score=sess["score"], lockdown=bool(sess["lockdown"]), seq=seq)

    ahash = trust.args_hash(args)
    sinks = [s for s in facts["sinks"] if s.get("sink")]
    exfil = any(s["kind"] == "exfil" for s in sinks)
    tainted_call = bool(facts["untrusted_sources"])

    # Round trip 3: drift counters and the taint set (session graph), plus the toxic-combination
    # check (stack graph) when this tool reaches a sink. The toxic result is only USED when the
    # context is also tainted, exactly as before; fetching it early just saves a round trip.
    d, context, toxic_res = parallel(
        lambda: taint.drift(sg, tool, ahash, now),
        lambda: taint.tainted_events(sg),
        (lambda: stack.named("toxic_combinations")) if sinks else (lambda: None),
    )

    # --- trust score: drift signals, then DLP on outbound args -----------------------------
    penalties = trust.drift_penalties(d, now_args_new=d["same_args"] == 0)
    dlp_kinds = trust.dlp_scan(args) if sinks else []
    dlp_pen = trust.dlp_penalty(dlp_kinds)
    if dlp_pen:
        penalties.append(dlp_pen)

    toxic_row = None
    reasons: list[str] = []
    decision = ALLOW

    # Apply penalties first so the call that tips the score is itself subject to lockdown.
    score, lockdown = sess["score"], bool(sess["lockdown"])
    total = sum(p.points for p in penalties)

    needs_toxic = bool(context) and bool(sinks)
    if needs_toxic:
        toxic_rows = toxic_res.dicts()
        toxic_row = next((r for r in toxic_rows if r["agent"] == facts["agent"]), None)
        if toxic_row and toxic_row["toxic"]:
            decision = DENY
            reasons.append(
                "structural: untrusted data is in context, this tool reaches "
                f"{'/'.join(sorted({s['kind'] for s in sinks}))} sink(s) "
                f"({', '.join(s['sink'] for s in sinks)}), and the agent holds the toxic "
                "combination (untrusted ingest + private data/secret + exfil egress)"
            )
            total += trust.PENALTY["blocked"]
            penalties.append(trust.Penalty("blocked", trust.PENALTY["blocked"],
                                           "tainted call to a sink was blocked"))
        else:
            decision = ESCALATE
            reasons.append(
                "untrusted data is in context and this tool reaches "
                f"{', '.join(s['sink'] for s in sinks)}; not toxic, so a human decides"
            )

    learned: list[dict] = []
    if decision != DENY and needs_toxic:
        # Procedural memory: rules learned from confirmed exploits on earlier stacks. Only
        # rules the critic armed are ever returned. A match can only tighten the decision.
        learned = precedent_rules.armed_rules_for(
            tenant, tool, sorted({e["tool"] for e in context}))
        if learned:
            decision = DENY
            reasons.append("learned rule: " + ", ".join(r["rule"] for r in learned) +
                           " (armed by the critic from confirmed exploits)")
            total += trust.PENALTY["blocked"]
            penalties.append(trust.Penalty("blocked", trust.PENALTY["blocked"],
                                           "learned rule blocked a tainted call"))

    if total:
        pen = taint.penalize(sg, session_id, total, config.GUARD_LOCKDOWN_THRESHOLD)
        score, lockdown = pen["score"], bool(pen["lockdown"])

    if lockdown and facts["side_effect"] != "read":
        decision = DENY
        reasons.insert(0, f"lockdown: trust score {score} is below "
                          f"{config.GUARD_LOCKDOWN_THRESHOLD}; only read-only tools may run")

    if decision != DENY and exfil and any(k in trust.SECRET_KINDS for k in dlp_kinds):
        decision = DENY
        reasons.append(f"DLP: outbound arguments contain {', '.join(dlp_kinds)} "
                       f"and {tool!r} reaches an exfil sink")

    if decision == ALLOW and facts["gated"]:
        decision = ESCALATE
        reasons.append(f"{tool!r} is gated in the stack config: a human must confirm")

    if decision == ALLOW:
        reasons.append("no untrusted data in context that this call could carry to a sink"
                       if sinks else "tool reaches no sink")

    return _finish(sg, session_id, stack_id, tool, args, now, decision, reasons,
                   tainted_call=tainted_call, context=context, facts=facts,
                   penalties=[p.to_dict() for p in penalties], dlp=dlp_kinds, score=score,
                   lockdown=lockdown, seq=seq, ahash=ahash, toxic=toxic_row, learned=learned)


def _finish(sg, session_id, stack_id, tool, args, now, decision, reasons, *, tainted_call,
            context, facts, penalties, dlp, score, lockdown, seq, ahash=None,
            toxic=None, learned=None) -> Decision:
    ahash = ahash or trust.args_hash(args)
    status = {ALLOW: "allowed", DENY: "denied", ESCALATE: "pending"}[decision]
    taint.record_event(
        sg, seq=seq, tool=tool, args_hash=ahash, tainted=tainted_call, decision=decision,
        executed=decision == ALLOW, status=status, reasons=reasons, dlp=dlp, ts=now,
        derived=bool(context),
    )
    return Decision(
        decision=decision, reasons=reasons, session=session_id, stack=stack_id, tool=tool,
        seq=seq, status=status, tainted_call=tainted_call, context_tainted=bool(context),
        score=score, lockdown=lockdown, penalties=penalties, dlp=dlp,
        provenance={
            "tool_facts": {k: facts.get(k) for k in
                           ("side_effect", "agent", "gated", "untrusted_sources", "sinks")},
            "tainted_events": context,
            "toxic_combination": toxic,
            "learned_rules": learned or [],
            "queries": ["guard_tool_facts", "session_taint", "toxic_combinations",
                        "session_drift", "precedent_rules_matching"],
        },
    )
