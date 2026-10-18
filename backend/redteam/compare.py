"""Turn raw red-team trials into the honest comparison table.

Every cell is derived from `Trial.success` (did the canary reach a simulated sink?). A "caught"
cell means the attack did NOT complete under that defence. Nothing here is hardcoded.
"""
from backend.redteam.runner import DEFENCES, Trial


def summarize(trials: list[Trial]) -> dict:
    rows: dict[tuple[str, str], dict] = {}
    for t in trials:
        key = (t.path_id, t.variant.kind)
        row = rows.setdefault(key, {
            "path_id": t.path_id, "act_tool": t.path["act_tool"], "sink": t.path["sink"],
            "sink_kind": t.path["sink_kind"], "source": t.path["source"],
            "variant": t.variant.kind, "generated_by": t.variant.generated_by,
            "text": t.variant.text, "results": {},
        })
        row["results"][t.defence] = {
            "attack_succeeded": t.success, "blocked_by": t.blocked_by,
            "sink_calls": t.sink_calls,
        }
    table = list(rows.values())

    # An attack "applies" only if it succeeds with no defence; otherwise the toy agent never
    # fell for it and there is nothing to catch.
    live = [r for r in table if r["results"]["unprotected"]["attack_succeeded"]]
    totals = {"attacks_total": len(table), "attacks_that_work_unprotected": len(live)}
    # Only defences that were actually run appear in the output (the proof re-run uses just
    # "unprotected"), so a missing defence is simply absent, never a made-up zero.
    present = [d for d in DEFENCES if d != "unprotected"
               and all(d in r["results"] for r in table)]

    def succeeded(r, d):
        return r["results"][d]["attack_succeeded"]

    for d in present:
        caught = [r for r in live if not succeeded(r, d)]
        totals[f"{d}_caught"] = len(caught)
        totals[f"{d}_missed"] = len(live) - len(caught)
    by_variant: dict[str, dict] = {}
    for r in live:
        v = by_variant.setdefault(r["variant"], {"attacks": 0})
        v["attacks"] += 1
        for d in present:
            v[f"{d}_caught"] = v.get(f"{d}_caught", 0) + (not succeeded(r, d))
    both = "naive" in present and "guard" in present
    return {
        "table": table,
        "totals": totals,
        "by_variant": by_variant,
        "naive_missed_guard_blocked": [
            {"variant": r["variant"], "act_tool": r["act_tool"], "text": r["text"]}
            for r in live if both and succeeded(r, "naive") and not succeeded(r, "guard")
        ],
        "guard_missed": [
            {"variant": r["variant"], "act_tool": r["act_tool"], "path_id": r["path_id"]}
            for r in live if "guard" in present and succeeded(r, "guard")
        ],
    }
