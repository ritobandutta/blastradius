"""A tiny stand-in MCP server (stdio, newline-delimited JSON-RPC) used to test the proxy.

It answers initialize, tools/list and tools/call, and appends every tools/call it actually
receives to the file named by FAKE_MCP_LOG so tests can assert what reached the child.
"""
import json
import os
import sys

LOG = os.environ.get("FAKE_MCP_LOG")

for line in sys.stdin:
    msg = json.loads(line)
    method, rid = msg.get("method"), msg.get("id")
    if method == "initialize":
        out = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
               "serverInfo": {"name": "fake", "version": "0"}}
    elif method == "tools/list":
        out = {"tools": [{"name": n, "description": n, "inputSchema": {"type": "object"}}
                         for n in ("read_email", "send_email", "db_query")]}
    elif method == "tools/call":
        if LOG:
            with open(LOG, "a") as f:
                f.write(msg["params"]["name"] + "\n")
        out = {"content": [{"type": "text", "text": f"ran {msg['params']['name']}"}]}
    else:
        continue  # notifications get no reply
    print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": out}), flush=True)
