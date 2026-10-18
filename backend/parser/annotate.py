"""Fill in side effects, data sources, sinks and secrets for tools the author left blank.

Order of precedence for each field:
  1. the stack spec (author)            -> annotation[field] = "spec"
  2. a rule in rules.yaml (editable)    -> "rules"
  3. keyword heuristic, optionally      -> "suggested", and tool.confirmed = False
     refined by the LLM
A "suggested" annotation is never silent: the API returns it flagged, and the UI asks the
user to confirm it. The LLM (if enabled) can only *propose* values for tools no rule matched.
"""
import json
import re
from functools import lru_cache
from pathlib import Path

import yaml

from backend.llm import base as llm
from backend.parser.models import DataRef, HoldRef, ReachRef, StackSpec, ToolSpec

RULES_PATH = Path(__file__).parent / "rules.yaml"
FIELDS = ("side_effect", "reads", "reaches", "holds")


@lru_cache(maxsize=1)
def load_rules() -> dict:
    return yaml.safe_load(RULES_PATH.read_text())


def reload_rules() -> None:
    load_rules.cache_clear()


def _apply(tool: ToolSpec, source: str, side_effect, reads, reaches, holds) -> None:
    """Set any field still empty, recording where the value came from."""
    if tool.side_effect is None and side_effect:
        tool.side_effect = side_effect
        tool.annotation["side_effect"] = source
    if tool.reads is None and reads is not None:
        tool.reads = [DataRef(**r) for r in reads]
        tool.annotation["reads"] = source
    if tool.reaches is None and reaches is not None:
        tool.reaches = [ReachRef(**r) for r in reaches]
        tool.annotation["reaches"] = source
    if tool.holds is None and holds is not None:
        tool.holds = [HoldRef(**r) for r in holds]
        tool.annotation["holds"] = source


def _rule_for(name: str) -> dict | None:
    for rule in load_rules()["tool_rules"]:
        if re.fullmatch(rule["match"], name, flags=re.IGNORECASE):
            return rule
    return None


def _heuristic_for(name: str, description: str) -> dict | None:
    words = set(re.split(r"[^a-z]+", f"{name} {description}".lower()))
    for h in load_rules()["heuristics"]:
        if words & set(h["keywords"]):
            return h
    return None


def _llm_suggest(tool: ToolSpec) -> dict | None:
    """Ask the LLM to classify an unknown tool. Returns None in mock mode or on bad output.

    The result is only ever stored as a *suggestion*; mock mode skips this entirely rather than
    inventing an answer.
    """
    if llm.mock_mode():
        return None
    prompt = (
        "Classify this AI-agent tool for a security graph. Reply with JSON only, keys: "
        "side_effect (read|write|destructive|exec|network_out), reads_untrusted (bool), "
        "reaches (list of {kind: exfil|mutate|exec, label}), holds_secret (bool).\n"
        f"name: {tool.name}\ndescription: {tool.description}"
    )
    res = llm.run("You are a careful security analyst.", prompt, fallback=lambda: "{}")
    if res.mock:
        return None
    try:
        data = json.loads(re.search(r"\{.*\}", res.text, re.S).group(0))
    except (AttributeError, json.JSONDecodeError):
        return None
    if data.get("side_effect") not in {"read", "write", "destructive", "exec", "network_out"}:
        return None
    return {
        "side_effect": data["side_effect"],
        "reads": (
            [{"id": f"{tool.name}-input", "label": f"{tool.name} input", "trust": "untrusted"}]
            if data.get("reads_untrusted")
            else []
        ),
        "reaches": [
            {"id": f"{tool.name}-{r.get('kind')}", "kind": r["kind"], "label": r.get("label")}
            for r in data.get("reaches", [])
            if r.get("kind") in {"exfil", "mutate", "exec"}
        ],
        "holds": (
            [{"id": f"{tool.name}-secret", "type": "secret", "sensitivity": 3}]
            if data.get("holds_secret")
            else []
        ),
    }


def annotate_tool(tool: ToolSpec, use_llm: bool = False) -> ToolSpec:
    # Author-provided fields are recorded first so rules never overwrite them.
    for f in FIELDS:
        if getattr(tool, f) is not None:
            tool.annotation[f] = "spec"

    rule = _rule_for(tool.name)
    if rule:
        _apply(tool, "rules", rule.get("side_effect"), rule.get("reads", []),
               rule.get("reaches", []), rule.get("holds", []))

    unresolved = tool.side_effect is None
    if unresolved:
        suggestion = _llm_suggest(tool) if use_llm else None
        source = "suggested"
        if suggestion is None:
            suggestion = _heuristic_for(tool.name, tool.description)
        if suggestion:
            _apply(tool, source, suggestion.get("side_effect"), suggestion.get("reads", []),
                   suggestion.get("reaches", []), suggestion.get("holds", []))
            tool.confirmed = False

    # Anything still unset after this is simply "no edges of that kind".
    tool.reads = tool.reads or []
    tool.reaches = tool.reaches or []
    tool.holds = tool.holds or []
    if tool.side_effect is None:
        tool.side_effect = "read"
        tool.annotation["side_effect"] = "suggested"
        tool.confirmed = False
    return tool


def annotate_stack(spec: StackSpec, use_llm: bool = False) -> StackSpec:
    for server in spec.servers:
        for tool in server.tools:
            annotate_tool(tool, use_llm=use_llm)
    return spec


def unconfirmed_tools(spec: StackSpec) -> list[dict]:
    return [
        {"server": s.id, "tool": t.name, "fields": {k: v for k, v in t.annotation.items()
                                                    if v == "suggested"}}
        for s in spec.servers
        for t in s.tools
        if not t.confirmed
    ]
