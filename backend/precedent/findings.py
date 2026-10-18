"""Turn a scan of a stack into Findings in the shared precedent graph, and remember fixes.

A Finding is one attack path. The red team can confirm it (the canary really reached a
simulated sink); a confirmed finding also stores the exploit that worked, so the rule critic can
replay it later. Fixes are recorded with `held = true` only if the proof of absence returned
zero paths.
"""
import json

from backend import config
from backend.defense.mincut import FixPlan
from backend.graph import analysis, schema
from backend.precedent import patterns, store
from backend.redteam import compare, runner


def _exploit(path: analysis.AttackPath) -> dict:
    """The call sequence the attack makes. The Guard sees exactly this shape at run time."""
    return {"calls": [path.ingest_tool, path.act_tool], "source": path.source,
            "sink": path.sink, "sink_kind": path.sink_kind}


def confirm_paths(stack_id: str) -> dict[str, list[str]]:
    """Run the red team against every path; return path id -> variants that completed."""
    res = runner.run_redteam(stack_id, top_n=1000, defences=("unprotected",),
                             distinct_exits=False)
    confirmed: dict[str, list[str]] = {}
    for row in compare.summarize(res["trials"])["table"]:
        if row["results"]["unprotected"]["attack_succeeded"]:
            confirmed.setdefault(row["path_id"], []).append(row["variant"])
    return confirmed


def remember_scan(stack_id: str, owner: str = "public", seeded: bool = False,
                  confirm: bool = True) -> dict:
    """Scan `stack_id` and write the Stack, its Findings and their Patterns into precedent."""
    report = analysis.paths_to_sinks(stack_id)
    toxic = analysis.toxic_combinations(stack_id)["toxic"]
    confirmed = confirm_paths(stack_id) if confirm and report.paths else {}
    spec = schema.stored_spec(stack_id)

    rows = []
    for p in report.paths:
        variants = sorted(set(confirmed.get(p.id, [])))
        rows.append({
            "id": f"{stack_id}:{patterns.combo(p)}", "combo": patterns.combo(p),
            "source": p.source, "ingest_tool": p.ingest_tool, "act_tool": p.act_tool,
            "sink": p.sink, "sink_kind": p.sink_kind, "score": p.score,
            "confirmed": bool(variants), "variants": variants,
            "exploit": json.dumps(_exploit(p)),
            "patterns": patterns.classify(p, toxic),
        })

    g = store.ensure()
    g.named("precedent_upsert_stack", {
        "id": stack_id, "owner": owner, "seeded": seeded, "name": spec.name or stack_id,
        "ts": store.now(), "open_risk": report.open_risk, "path_count": len(report.paths),
    }, write=True)
    if rows:
        g.named("precedent_upsert_findings", {"stack": stack_id, "findings": rows}, write=True)
    return {"stack": stack_id, "findings": len(rows),
            "confirmed": sum(r["confirmed"] for r in rows), "toxic": toxic,
            "graph": config.PRECEDENT_GRAPH}


def remember_fix(stack_id: str, plan: FixPlan, proof: dict) -> list[dict]:
    """Record each fix and which findings it severed. `held` comes from the proof of absence."""
    g = store.ensure()
    held = bool(proof["verified_safe"])
    out = []
    for fx in plan.fixes:
        fix_id = f"{fx.action}:{fx.tool}" + (f":{fx.sink}" if fx.sink else "")
        affected = [f"{stack_id}:{patterns.combo(p)}" for p in
                    _paths_for(plan, fx)]
        g.named("precedent_record_fix", {
            "fix": fix_id, "action": fx.action, "tool": fx.tool, "sink": fx.sink or "",
            "cost": fx.cost, "describe": fx.describe(), "findings": affected, "held": held,
            "stack": stack_id, "ts": store.now(),
        }, write=True)
        out.append({"fix": fix_id, "findings": affected, "held": held})
    return out


def _paths_for(plan: FixPlan, fx):
    """Paths (re-queried from the stack graph) that this fix severs."""
    from backend.defense.mincut import _severs

    return [p for p in analysis.paths_to_sinks(plan.stack).paths if _severs(fx, p)]


def stack_findings(stack_id: str) -> list[dict]:
    rows = store.read("precedent_stack_findings", {"stack": stack_id})
    for r in rows:
        r["fixes"] = [f for f in r["fixes"] if f.get("fix")]
        r["variants"] = r["variants"] or []
    return rows
