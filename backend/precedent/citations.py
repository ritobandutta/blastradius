"""Precedent citations: "this tool combination was exploited in N earlier stacks".

Everything here is a traversal of the shared precedent graph:
  precedent_citations     Stack -> Finding -> Pattern <- Finding <- Stack, grouped per pattern
  precedent_combo_history the same hop, narrowed to the identical tool combination, with the
                          fixes that held on those earlier stacks

The stack being scanned is excluded from its own citations, and other tenants' *private* stacks
are excluded unless they are part of the shared seed corpus.
"""
from backend.precedent import store


def _visible(owner_of_me: str, row_owner: str, seeded: bool) -> bool:
    return seeded or row_owner == owner_of_me or row_owner == "seed"


def citations(stack_id: str, owner: str = "public") -> dict:
    me = store.read("precedent_stack_exists", {"id": stack_id})
    if not me:
        return {"stack": stack_id, "remembered": False, "patterns": [], "combos": [],
                "headline": "This stack has not been scanned into the precedent graph yet."}

    patterns = []
    for r in store.read("precedent_citations", {"stack": stack_id}):
        stacks = [s for s in r["stacks"] if _visible(owner, s["owner"], s["seeded"])]
        if not stacks:
            continue
        patterns.append({**r, "stacks": stacks, "other_stacks": len(stacks)})

    combos: dict[str, dict] = {}
    for r in store.read("precedent_combo_history", {"stack": stack_id}):
        if r["earlier_stack"] is None or not _visible(owner, r["earlier_owner"],
                                                      r["earlier_seeded"]):
            continue
        c = combos.setdefault(r["finding"], {
            "finding": r["finding"], "combo": r["combo"], "act_tool": r["act_tool"],
            "earlier": {}, "fixes_that_held": {},
        })
        e = c["earlier"].setdefault(r["earlier_stack"], {
            "stack": r["earlier_stack"], "finding": r["earlier_finding"],
            "confirmed": r["earlier_confirmed"], "seeded": r["earlier_seeded"],
        })
        if r["fix"]:
            c["fixes_that_held"].setdefault(r["fix"], {"fix": r["fix"],
                                                         "describe": r["fix_describe"],
                                                         "stacks": set()})["stacks"].add(
                r["earlier_stack"])
    out = []
    for c in combos.values():
        c["earlier"] = sorted(c["earlier"].values(), key=lambda x: x["stack"])
        c["fixes_that_held"] = sorted(
            ({**f, "stacks": sorted(f["stacks"])} for f in c["fixes_that_held"].values()),
            key=lambda f: (-len(f["stacks"]), f["fix"]))
        c["message"] = _message(c)
        out.append(c)
    out.sort(key=lambda c: (-len(c["earlier"]), c["combo"]))
    return {"stack": stack_id, "remembered": True, "patterns": patterns, "combos": out,
            "headline": _headline(out, patterns)}


def _message(c: dict) -> str:
    n = len(c["earlier"])
    base = f"{c['combo']} was exploited in {n} earlier stack{'s' if n != 1 else ''}"
    if c["fixes_that_held"]:
        best = c["fixes_that_held"][0]
        base += f"; the fix that held was: {best['describe']} (held on {len(best['stacks'])})"
    return base + "."


def _headline(combos: list[dict], patterns: list[dict]) -> str:
    if combos:
        return combos[0]["message"]
    if patterns:
        p = patterns[0]
        return (f"No identical tool combination seen before, but the pattern "
                f"'{p['name']}' appeared in {p['other_stacks']} earlier stack(s).")
    return "Nothing like this has been seen before: no precedent."
