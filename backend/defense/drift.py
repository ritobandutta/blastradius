"""Policy-drift diff: which attack paths does a config change introduce or remove?

Both specs are loaded into temporary FalkorDB graphs, the same paths_to_sinks query runs on
each, and the two path sets are compared by path id. The temp graphs are always deleted.
"""
import uuid

from backend.graph import analysis, schema
from backend.graph.client import Graph, stack_graph_name
from backend.parser.models import StackSpec
from backend.parser.stack_spec import parse_any


def _scan(spec: StackSpec) -> analysis.PathReport:
    tmp = spec.model_copy(update={"id": f"drift-{uuid.uuid4().hex[:8]}"})
    try:
        schema.load_stack(tmp)
        return analysis.paths_to_sinks(tmp.id)
    finally:
        Graph(stack_graph_name(tmp.id)).delete()


def diff_specs(old: StackSpec, new: StackSpec) -> dict:
    a, b = _scan(old), _scan(new)
    old_ids, new_ids = {p.id: p for p in a.paths}, {p.id: p for p in b.paths}
    introduced = [new_ids[i].to_dict() for i in new_ids if i not in old_ids]
    removed = [old_ids[i].to_dict() for i in old_ids if i not in new_ids]
    introduced.sort(key=lambda p: -p["score"])
    removed.sort(key=lambda p: -p["score"])
    return {
        "old": {"stack": old.id, "paths": len(a.paths), "open_risk": a.open_risk,
                "run_time_ms": a.run_time_ms},
        "new": {"stack": new.id, "paths": len(b.paths), "open_risk": b.open_risk,
                "run_time_ms": b.run_time_ms},
        "introduced": introduced,
        "removed": removed,
        "unchanged": len(set(old_ids) & set(new_ids)),
        "risk_delta": round(b.open_risk - a.open_risk, 2),
        "regression": bool(introduced) or b.open_risk > a.open_risk,
    }


def diff_dicts(old: dict, new: dict) -> dict:
    return diff_specs(parse_any(old, stack_id="drift-old"), parse_any(new, stack_id="drift-new"))


def markdown(d: dict) -> str:
    """Format the diff as a PR comment."""
    risk = d["risk_delta"]
    sign = "+" if risk > 0 else ""
    head = ("### BlastRadius: this change **opens new attack paths**"
            if d["introduced"] else
            "### BlastRadius: this change closes attack paths"
            if d["removed"] else "### BlastRadius: no change to the attack surface")
    lines = [head, "",
             f"| | paths | open risk |", "|---|---|---|",
             f"| before | {d['old']['paths']} | {d['old']['open_risk']} |",
             f"| after | {d['new']['paths']} | {d['new']['open_risk']} |",
             f"| **delta** | **{d['new']['paths'] - d['old']['paths']:+d}** | **{sign}{risk}** |",
             ""]

    def block(title, items, mark):
        if not items:
            return
        lines.extend([f"**{title} ({len(items)})**", ""])
        for p in items:
            lines.append(f"- {mark} `{' -> '.join(p['nodes'])}`  \n"
                         f"  {p['sink_kind']} sink, score {p['score']}")
        lines.append("")

    block("Introduced", d["introduced"], ":red_circle:")
    block("Removed", d["removed"], ":green_circle:")
    lines.append(f"_{d['unchanged']} path(s) unchanged. Paths found by Cypher on FalkorDB in "
                 f"{d['old']['run_time_ms']} ms and {d['new']['run_time_ms']} ms._")
    return "\n".join(lines)
