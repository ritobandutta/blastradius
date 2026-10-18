"""Red-team runner: attack the toy agent along the paths FalkorDB found, under three defences.

For each of the top-N attack paths (untrusted source -> ingest tool -> agent -> act tool -> sink)
and each variant, we plant the variant where the attacker controls content (a tool result or a
tool description), run the deterministic toy agent, and read the canary ledger:

    success = the canary string appeared in the arguments of a call that actually ran

The same attack is run unprotected, behind the naive keyword filter, and behind the real Guard.
Results are measured, never hardcoded: `compare.py` builds the table from these records.
"""
import secrets
import time
from dataclasses import dataclass, field

from backend.graph import analysis
from backend.graph.analysis import AttackPath
from backend.graph.schema import stored_spec
from backend.redteam.variants import Variant, build_variants
from demo.toy_agent.agent import GullibleAgent, Passthrough
from demo.toy_agent.gateways import GuardGateway, NaiveGateway
from demo.toy_agent.tools import SandboxEnv

DEFENCES = ("unprotected", "naive", "guard")


@dataclass
class Trial:
    path_id: str
    path: dict
    variant: Variant
    defence: str
    canary: str
    success: bool  # canary reached a simulated sink
    sink_calls: list[str]
    steps: list[dict]
    blocked_by: str | None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path_id": self.path_id, "variant": self.variant.kind,
            "generated_by": self.variant.generated_by, "defence": self.defence,
            "success": self.success, "sink_calls": self.sink_calls,
            "blocked_by": self.blocked_by, "steps": self.steps, "notes": self.notes,
        }


def _env_for(variant: Variant, path: AttackPath, canary: str) -> SandboxEnv:
    env = SandboxEnv(canary=canary)
    if variant.target == "description":
        env.descriptions[path.ingest_tool] = variant.text
    else:
        env.poisoned_results[path.ingest_tool] = variant.text
    return env


def run_trial(stack_id: str, tool_names: set[str], path: AttackPath, variant: Variant,
              defence: str, canary: str) -> Trial:
    env = _env_for(variant, path, canary)
    gw = {"unprotected": Passthrough(), "naive": NaiveGateway(),
          "guard": GuardGateway(stack_id)}[defence]
    agent = GullibleAgent(env, tool_names, gw)
    try:
        ep = agent.run(path.ingest_tool, {"for": "assistant task"})
    finally:
        if isinstance(gw, GuardGateway):
            gw.cleanup()
    sink_calls = env.canary_sink_calls()
    return Trial(path.id, path.to_dict(), variant, defence, canary, bool(sink_calls),
                 sink_calls, ep.steps, ep.blocked_by)


def top_paths(stack_id: str, n: int) -> list[AttackPath]:
    """One representative path per (act tool, sink), highest score first, so the red team
    exercises every distinct way out instead of the same exit repeatedly."""
    seen: set[tuple[str, str]] = set()
    picked: list[AttackPath] = []
    for p in analysis.paths_to_sinks(stack_id).paths:
        key = (p.act_tool, p.sink)
        if key in seen:
            continue
        seen.add(key)
        picked.append(p)
        if len(picked) >= n:
            break
    return picked


def run_redteam(stack_id: str, top_n: int = 4, use_llm: bool = False,
                defences: tuple[str, ...] = DEFENCES) -> dict:
    t0 = time.perf_counter()
    tool_names = {t.name for s in stored_spec(stack_id).servers for t in s.tools}
    paths = top_paths(stack_id, top_n)
    trials: list[Trial] = []
    for path in paths:
        # One canary per path, shared by every variant and defence, and baked into the attack
        # text itself (the shell variant must carry the real canary or it can never succeed).
        canary = f"CANARY-{secrets.token_hex(4)}"
        for variant in build_variants(path.act_tool, canary, use_llm=use_llm):
            for defence in defences:
                trials.append(run_trial(stack_id, tool_names, path, variant, defence, canary))
    return {
        "stack": stack_id,
        "paths_tested": [p.to_dict() for p in paths],
        "trials": trials,
        "elapsed_s": round(time.perf_counter() - t0, 2),
        "sandbox": "simulated tools only; no network, subprocess or real filesystem writes",
    }
