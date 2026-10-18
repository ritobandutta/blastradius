"""Apply a fix plan to a stack spec and produce the patched config.

The patch is a pure transformation of the stored spec, so the "patched mcp.json" is the same
stack with `gated`, `scoped` and removed tools changed, nothing else.
"""
import copy

from backend.defense.mincut import Fix
from backend.parser.models import StackSpec


def apply_fixes(spec: StackSpec, fixes: list[Fix], new_id: str | None = None) -> StackSpec:
    out = copy.deepcopy(spec)
    out.id = new_id or f"{spec.id}-patched"
    out.name = f"{spec.name or spec.id} (patched by BlastRadius)"
    by_tool: dict[str, list[Fix]] = {}
    for f in fixes:
        by_tool.setdefault(f.tool, []).append(f)

    for server in out.servers:
        keep = []
        for tool in server.tools:
            todo = by_tool.get(tool.name, [])
            if any(f.action == "remove_tool" for f in todo):
                continue
            for f in todo:
                if f.action == "gate":
                    tool.gated = True
                elif f.action == "scope":
                    for r in tool.reaches or []:
                        if r.id == f.sink:
                            r.scoped = True
            keep.append(tool)
        server.tools = keep
    return out


def changes(before: StackSpec, after: StackSpec) -> list[dict]:
    """Human-readable diff between two specs: gates added, sinks scoped, tools removed."""
    b = {t.name: t for s in before.servers for t in s.tools}
    a = {t.name: t for s in after.servers for t in s.tools}
    out = []
    for name, t in b.items():
        if name not in a:
            out.append({"change": "remove_tool", "tool": name})
            continue
        if a[name].gated and not t.gated:
            out.append({"change": "gate", "tool": name})
        old = {r.id: r.scoped for r in t.reaches or []}
        for r in a[name].reaches or []:
            if r.scoped and not old.get(r.id):
                out.append({"change": "scope", "tool": name, "sink": r.id})
    return out


def to_mcp_json(spec: StackSpec) -> dict:
    """Render the patched stack as an mcp.json-style document. `blastradius` carries the policy
    levers an MCP client cannot express natively; the Guard proxy reads them from the graph."""
    servers = {}
    for s in spec.servers:
        servers[s.id] = {
            "command": s.command or "<unchanged>",
            "args": s.args,
            "blastradius": {
                "tools": {
                    t.name: {
                        "gated": t.gated,
                        "scoped_sinks": [r.id for r in t.reaches or [] if r.scoped],
                    }
                    for t in s.tools
                }
            },
        }
    return {"mcpServers": servers}
