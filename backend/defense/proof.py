"""Proof of absence: apply the fix, re-run the *same* path query, and show the result.

"No path exists" is not a claim we make from the plan. The patched spec is loaded as its own
FalkorDB graph and `paths_to_sinks` is executed against it; the badge is only "verified safe"
when that query really returns zero rows. The red-team variants are then re-run against the
patched stack to show the attacks no longer complete.
"""
from backend.defense import mincut, patch
from backend.graph import analysis, schema
from backend.graph.client import Graph, stack_graph_name
from backend.parser import annotate
from backend.redteam import compare, runner


def verify(stack_id: str, fp: mincut.FixPlan, patched_id: str | None = None,
           rerun_redteam: bool = True, keep: bool = True) -> dict:
    before_spec = schema.stored_spec(stack_id)
    patched = patch.apply_fixes(before_spec, fp.fixes, patched_id)
    annotate.annotate_stack(patched)  # no-op for already-annotated tools; keeps invariants
    schema.load_stack(patched)
    try:
        after = analysis.paths_to_sinks(patched.id)
        toxic = analysis.toxic_combinations(patched.id)
        out = {
            "patched_stack": patched.id,
            "paths_before": fp.paths_before,
            "open_risk_before": fp.open_risk_before,
            "paths_after": len(after.paths),
            "open_risk_after": after.open_risk,
            "query": "paths_to_sinks",
            "query_run_time_ms": after.run_time_ms,
            "verified_safe": len(after.paths) == 0,
            "badge": (f"0 paths found, {after.run_time_ms} ms"
                      if not after.paths else f"{len(after.paths)} paths still open"),
            "toxic_after": toxic["toxic"],
            "remaining_paths": [p.to_dict() for p in after.paths],
            "changes": patch.changes(before_spec, patched),
            "patched_spec": patched.model_dump(),
            "mcp_json": patch.to_mcp_json(patched),
        }
        if rerun_redteam:
            out["redteam_before"] = _redteam(stack_id)
            out["redteam_after"] = _redteam_patched(patched.id, before_spec, stack_id)
        return out
    finally:
        if not keep:
            Graph(stack_graph_name(patched.id)).delete()


def _redteam(stack_id: str) -> dict:
    res = runner.run_redteam(stack_id, top_n=6, defences=("unprotected",))
    summary = compare.summarize(res["trials"])
    return {
        "attacks": summary["totals"]["attacks_total"],
        "completed": summary["totals"]["attacks_that_work_unprotected"],
    }


def _redteam_patched(patched_id: str, before_spec, original_id: str) -> dict:
    """Re-run the exact attacks that worked before (same paths) against the patched stack.

    The patched stack has no open paths, so top_paths() on it would be empty. The attacks are
    built from the ORIGINAL stack's paths and replayed against the patched stack using the
    "config" defence: only what the patched config enforces (gates, scoped tokens, removed
    tools), with no Guard and no taint tracking. This isolates the effect of the patch itself.
    """
    import secrets

    from backend.redteam.variants import build_variants

    paths = runner.top_paths(original_id, 6)
    tool_names = {t.name for s in schema.stored_spec(patched_id).servers for t in s.tools}
    completed = failed = 0
    details = []
    for path in paths:
        canary = f"CANARY-{secrets.token_hex(4)}"
        for variant in build_variants(path.act_tool, canary):
            t = runner.run_trial(patched_id, tool_names, path, variant, "config", canary)
            completed += t.success
            failed += not t.success
            details.append({"path_id": path.id, "variant": variant.kind,
                            "attack_succeeded": t.success, "blocked_by": t.blocked_by,
                            "act_tool": path.act_tool})
    return {"attacks": completed + failed, "completed": completed,
            "failed_against_patch": failed, "defence": "patched config only (no Guard)",
            "details": details}
