"""Build the seed corpus: synthetic "earlier stacks" so precedent citations are non-trivial.

Nothing in the precedent graph is typed in by hand. Each seed stack goes through the same
pipeline as a real one: load -> paths -> red-team confirmation -> min-cut -> patched graph ->
proof of absence -> remember findings, fixes (held only if the proof passed), and learned rules
(armed only if the critic passes). The stacks are synthetic (demo/seed_stacks) and are marked
`seeded = true` and owned by `seed` so the UI labels them as such.

Run: uv run python -m backend.precedent.seed [--reset]
"""
import json
import sys
from pathlib import Path

from backend.defense import mincut, proof
from backend.graph import schema
from backend.graph.client import Graph
from backend.parser.stack_spec import load_spec
from backend.precedent import findings, rules, store

SEED_DIR = Path(__file__).resolve().parent.parent.parent / "demo" / "seed_stacks"
SEED_OWNER = rules.SEED_OWNER


def build(reset: bool = False) -> dict:
    if reset:
        store.graph().delete()
    store.ensure()
    summary = []
    for path in sorted(SEED_DIR.glob("*.json")):
        spec = load_spec(json.loads(path.read_text()))
        schema.load_stack(spec)
        try:
            scan = findings.remember_scan(spec.id, owner=SEED_OWNER, seeded=True)
            plan = mincut.plan(spec.id)
            patched = f"{spec.id}-patched"
            fixes = []
            if plan.fixes:
                result = proof.verify(spec.id, plan, patched_id=patched, rerun_redteam=False,
                                      keep=False)
                fixes = findings.remember_fix(spec.id, plan, result)
            verdicts = rules.learn(spec.id, SEED_OWNER)
            summary.append({"stack": spec.id, **scan, "fixes": len(fixes),
                            "rules": [(v["rule"], v["status"]) for v in verdicts]})
        finally:
            # Seed stack graphs are scaffolding; their knowledge lives in the precedent graph.
            Graph(f"stack:{spec.id}").delete()
    return {"seeded": summary, "graph": store.graph().name}


def main() -> None:
    out = build(reset="--reset" in sys.argv)
    for s in out["seeded"]:
        print(f"{s['stack']}: {s['findings']} findings ({s['confirmed']} confirmed), "
              f"{s['fixes']} fixes, rules {s['rules']}")


if __name__ == "__main__":
    main()
