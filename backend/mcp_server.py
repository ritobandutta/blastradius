"""BlastRadius as an MCP server (stdio, newline-delimited JSON-RPC).

An agent can ask the graph about its own attack surface through four tools. Each answer is a
FalkorDB query result returned with its path and latency, so the agent (and the human reading
its transcript) can see the evidence:

  paths_to_sinks       open untrusted -> sink paths for a stack
  toxic_combinations   does the agent hold the lethal trifecta?
  choke_points         tools whose removal/gating severs the most paths
  precedent_lookup     "this combination was exploited in N earlier stacks; the fix that held"

Read-only: no tool here changes a graph, the Guard, or an approval.

Run: python -m backend.mcp_server        (add to an MCP client config as a stdio server)
"""
import json
import sys

from backend.graph import analysis, schema, tenancy
from backend.graph.client import GraphQueryError, GraphUnavailable, stack_graph_name
from backend.llm import base as llm
from backend.precedent import citations

PROTOCOL = "2024-11-05"
TENANT = "public"

STACK_ARG = {"type": "string", "description": "Stack id (see list_stacks)"}
TOOLS = [
    {"name": "list_stacks", "description": "List the stacks loaded in BlastRadius.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "paths_to_sinks",
     "description": "Every path from untrusted input to a dangerous sink (exfil/mutate/exec) in "
                    "the stack, with a blast-radius score per path and the total open risk.",
     "inputSchema": {"type": "object", "properties": {"stack": STACK_ARG}, "required": ["stack"]}},
    {"name": "toxic_combinations",
     "description": "Whether the agent can ingest untrusted content AND read private data or "
                    "secrets AND reach an outbound channel.",
     "inputSchema": {"type": "object", "properties": {"stack": STACK_ARG}, "required": ["stack"]}},
    {"name": "choke_points",
     "description": "Tools ranked by how many attack paths run through them, with FalkorDB "
                    "betweenness centrality.",
     "inputSchema": {"type": "object", "properties": {"stack": STACK_ARG}, "required": ["stack"]}},
    {"name": "precedent_lookup",
     "description": "How often this stack's tool combinations were exploited in earlier stacks, "
                    "and which fix held. The stack must have been scanned into precedent memory.",
     "inputSchema": {"type": "object", "properties": {"stack": STACK_ARG}, "required": ["stack"]}},
]


def _stack(args: dict) -> str:
    sid = args.get("stack", "")
    owned = tenancy.owner_of(stack_graph_name(sid)) == TENANT
    if not sid or sid not in schema.stack_ids() or not owned:
        raise KeyError(f"unknown stack {sid!r}")
    return sid


def call_tool(name: str, args: dict) -> dict:
    if name == "list_stacks":
        owners = tenancy.owners()
        return {"stacks": [s for s in schema.stack_ids()
                           if owners.get(stack_graph_name(s), tenancy.PUBLIC) == TENANT]}
    if name == "paths_to_sinks":
        return analysis.paths_to_sinks(_stack(args)).to_dict()
    if name == "toxic_combinations":
        return analysis.toxic_combinations(_stack(args))
    if name == "choke_points":
        return analysis.choke_points(_stack(args))
    if name == "precedent_lookup":
        return citations.citations(_stack(args), owner=TENANT)
    raise KeyError(f"unknown tool {name!r}")


def _result(rid, payload: dict, error: bool = False) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": {
        "isError": error, "content": [{"type": "text", "text": json.dumps(payload, indent=2)}]}}


def handle(msg: dict) -> dict | None:
    method, rid = msg.get("method"), msg.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
            "serverInfo": {"name": "blastradius", "version": "0.1.0"}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        p = msg.get("params") or {}
        try:
            return _result(rid, call_tool(p.get("name", ""), p.get("arguments") or {}))
        except GraphUnavailable as e:  # fail loudly, never an empty answer
            return _result(rid, {"error": "falkordb_unavailable", "detail": str(e)}, True)
        except (KeyError, GraphQueryError) as e:
            return _result(rid, {"error": "not_found_or_failed", "detail": str(e)}, True)
    if rid is None:
        return None  # notification (for example notifications/initialized)
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": f"method not found: {method}"}}


def main() -> None:
    st = llm.llm_status()
    if st["mock_mode"]:
        print(f"[blastradius-mcp] MOCK MODE: {st['reason']} (these tools never use an LLM)",
              file=sys.stderr, flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            reply = handle(json.loads(line))
        except json.JSONDecodeError:
            reply = {"jsonrpc": "2.0", "id": None,
                     "error": {"code": -32700, "message": "parse error"}}
        if reply is not None:
            print(json.dumps(reply), flush=True)


if __name__ == "__main__":
    main()
