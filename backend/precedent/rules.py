"""Procedural memory: compile confirmed findings into reusable Guard rules, behind a critic.

A Rule says: "if data from `ingest_tool` is already in context and the agent is about to call
`act_tool` (which reaches a `sink_kind` sink), DENY". It is stack-independent, so a rule learned
on one stack protects the next stack that has the same two tools.

Nothing is trusted on arrival. A new rule is `proposed`; the deterministic critic must show:
  1. it BLOCKS the confirmed exploit it was derived from, and
  2. it does NOT block any recorded benign session
before it becomes `armed`. Otherwise it is `rejected`, and the reason is stored on the rule.
The critic uses the same Cypher match (`precedent_rules_matching`) the Guard uses at run time,
so what the critic approves is exactly what will fire.
"""
import json
import uuid

from backend.graph import schema
from backend.graph.client import Graph, stack_graph_name
from backend.precedent import store
from backend.redteam import benign

SEED_OWNER = "seed"


def rule_id(owner: str, ingest: str, act: str, kind: str) -> str:
    return f"{owner}:{ingest}>{act}>{kind}"


def propose(stack_id: str, owner: str) -> list[str]:
    """Derive a rule per distinct (ingest tool, act tool, sink kind) among confirmed findings."""
    store.ensure()
    groups: dict[tuple, dict] = {}
    for f in store.read("precedent_stack_findings", {"stack": stack_id}):
        if not f["confirmed"]:
            continue
        g = groups.setdefault((f["ingest_tool"], f["act_tool"], f["sink_kind"]),
                              {"findings": [], "f": f})
        g["findings"].append(f["id"])
    ids = []
    for (ingest, act, kind), g in sorted(groups.items()):
        rid = rule_id(owner, ingest, act, kind)
        store.graph().named("precedent_upsert_rule", {
            "id": rid, "owner": owner, "ingest_tool": ingest, "act_tool": act,
            "sink_kind": kind, "sink": g["f"]["sink"], "representative": g["f"]["id"],
            "exploit": g["f"]["exploit"], "findings": g["findings"], "ts": store.now(),
        }, write=True)
        ids.append(rid)
    return ids


def _matches(rule: dict, tool: str, tainted: list[str]) -> bool:
    rows = store.read("precedent_rules_matching", {
        "statuses": ["proposed", "armed", "rejected"], "tool": tool, "tainted": tainted,
        "owners": [rule["owner"]], "rid": rule["id"],
    })
    return bool(rows)


def _tainted_tools(stack_id: str) -> set[str]:
    """Tools that read an untrusted source, from the stack graph (what the Guard also uses)."""
    rows = Graph(stack_graph_name(stack_id)).ro_query(
        "MATCH (d:DataSource {trust:'untrusted'})-[:READ_BY]->(t:Tool) RETURN DISTINCT t.id"
    ).rows
    return {r[0] for r in rows}


def critique(rule_id_: str, stack_id: str) -> dict:
    """Run the critic on one rule and store the verdict. Returns the verdict."""
    rule = next(r for r in store.read("precedent_rules") if r["id"] == rule_id_)
    # The exploit is the call sequence recorded on the confirmed Finding (stored on the rule at
    # derivation time), NOT rebuilt from the rule's own fields: replaying the rule's own tools
    # would make "does it block the exploit?" true by construction.
    exploit_calls = json.loads(rule["exploit"] or "{}").get("calls") or []
    taint_tools = _tainted_tools(stack_id)

    # 1. does it block the confirmed exploit? (ingest call, then the act call)
    blocks_exploit = len(exploit_calls) == 2 and _matches(
        rule, exploit_calls[1], [exploit_calls[0]])

    # 2. does it block any recorded benign session?
    blocked = []
    sessions = [s for name in _benign_sets() for s in benign.load_sessions(name)]
    for s in sessions:
        tainted: list[str] = []
        for call in s["calls"]:
            if _matches(rule, call["tool"], sorted(set(tainted))):
                blocked.append({"session": s["name"], "call": call["tool"]})
                break
            if call["tool"] in taint_tools:
                tainted.append(call["tool"])

    armed = blocks_exploit and not blocked
    verdict = {
        "rule": rule_id_, "status": "armed" if armed else "rejected",
        "blocks_exploit": blocks_exploit, "benign_sessions_checked": len(sessions),
        "benign_blocked": blocked,
        "reason": ("blocks the confirmed exploit and none of "
                   f"{len(sessions)} benign sessions" if armed else
                   ("does not block the confirmed exploit" if not blocks_exploit else
                    "would block legitimate work: " +
                    ", ".join(f"{b['session']} (at {b['call']})" for b in blocked))),
    }
    store.graph().named("precedent_rule_status", {
        "id": rule_id_, "status": verdict["status"], "critic": json.dumps(verdict),
        "ts": store.now(),
    }, write=True)
    return verdict


def _benign_sets() -> list[str]:
    return sorted(p.stem for p in benign.BENIGN_DIR.glob("*.json"))


def learn(stack_id: str, owner: str) -> list[dict]:
    """Propose rules from this stack's confirmed findings, then run the critic on each."""
    return [critique(rid, stack_id) for rid in propose(stack_id, owner)]


def list_rules(owner: str | None = None) -> list[dict]:
    rows = store.read("precedent_rules")
    for r in rows:
        r["critic"] = json.loads(r["critic"]) if r.get("critic") else None
    if owner is not None:
        rows = [r for r in rows if r["owner"] in (owner, SEED_OWNER)]
    return rows


def armed_rules_for(owner: str, tool: str, tainted_tools: list[str]) -> list[dict]:
    """What the Guard calls on every tainted-context step."""
    return store.read("precedent_rules_matching", {
        "statuses": ["armed"], "tool": tool, "tainted": tainted_tools,
        "owners": [owner, SEED_OWNER], "rid": "",
    })


def new_probe_stack_id() -> str:
    return f"probe-{uuid.uuid4().hex[:8]}"


def stack_known(stack_id: str) -> bool:
    return stack_id in schema.stack_ids()
