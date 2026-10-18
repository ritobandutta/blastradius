"""Load a stack spec (BlastRadius JSON) or a real mcp.json / Claude Code settings file.

mcp.json files list servers but not their tools, so tools are inferred from `server_rules` in
rules.yaml. That inference is best effort and always marked "suggested".
"""
import json
import re
from pathlib import Path

from backend.parser import annotate
from backend.parser.models import ServerSpec, StackSpec, ToolSpec


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-]+", "-", text).strip("-")[:64] or "stack"


def load_spec(data: dict, use_llm: bool = False) -> StackSpec:
    """Parse a BlastRadius stack spec dict."""
    spec = StackSpec.model_validate(data)
    return annotate.annotate_stack(spec, use_llm=use_llm)


def load_spec_file(path: str | Path, use_llm: bool = False) -> StackSpec:
    return load_spec(json.loads(Path(path).read_text()), use_llm=use_llm)


def is_mcp_config(data: dict) -> bool:
    return isinstance(data.get("mcpServers"), dict) or (
        isinstance(data.get("mcp"), dict) and isinstance(data["mcp"].get("servers"), dict)
    )


def from_mcp_config(data: dict, stack_id: str, use_llm: bool = False) -> StackSpec:
    """Best-effort import of an mcp.json or Claude Code settings file."""
    servers_raw = data.get("mcpServers") or data.get("mcp", {}).get("servers") or {}
    rules = annotate.load_rules()["server_rules"]
    servers: list[ServerSpec] = []
    for name, cfg in servers_raw.items():
        haystack = " ".join(
            [name, str(cfg.get("command", "")), " ".join(map(str, cfg.get("args", [])))]
        ).lower()
        tool_names: list[str] = []
        for rule in rules:
            if re.search(rule["match"], haystack):
                tool_names += [t for t in rule["tools"] if t not in tool_names]
        tools = [ToolSpec(name=t, confirmed=False) for t in tool_names]
        servers.append(ServerSpec(id=_slug(name), command=cfg.get("command"),
                                  args=[str(a) for a in cfg.get("args", [])], tools=tools))
    spec = StackSpec(id=_slug(stack_id), source="mcp.json", servers=servers)
    annotate.annotate_stack(spec, use_llm=use_llm)
    # Everything in an imported config is a guess about tools, so require confirmation.
    for server in spec.servers:
        for tool in server.tools:
            tool.confirmed = False
    return spec


def parse_any(data: dict, stack_id: str | None = None, use_llm: bool = False) -> StackSpec:
    if is_mcp_config(data):
        return from_mcp_config(data, stack_id or "imported", use_llm=use_llm)
    if stack_id:
        data = {**data, "id": stack_id}
    return load_spec(data, use_llm=use_llm)
