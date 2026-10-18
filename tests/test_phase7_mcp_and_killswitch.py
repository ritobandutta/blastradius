"""BlastRadius-as-MCP-server, and the "FalkorDB removed" kill-test.

If the product still worked with FalkorDB gone, the graph would be decoration. These tests run
the Guard, the MCP server and the API against a database that is not there and require loud,
safe failure: DENY, an error result, a 503. Never an empty or canned answer.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import mcp_server
from backend.api.main import app
from backend.graph import client, tenancy
from backend.graph.client import stack_graph_name
from tests.conftest import unique

ROOT = Path(__file__).resolve().parent.parent
DEAD = {"FALKORDB_HOST": "127.0.0.1", "FALKORDB_PORT": "1"}  # nothing listens on port 1


def _py(code: str, env_extra: dict | None = None, stdin: str | None = None):
    env = {**os.environ, "BLASTRADIUS_LLM": "mock", "PYTHONPATH": str(ROOT), **(env_extra or {})}
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, input=stdin,
                          capture_output=True, text=True, timeout=60)


# ---- the MCP server ----------------------------------------------------------------------

def _rpc(method, params=None, i=1):
    return {"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}


def test_mcp_server_lists_tools_and_answers_with_evidence(load_demo):
    sid = load_demo("vulnerable")
    init = mcp_server.handle(_rpc("initialize"))
    assert init["result"]["serverInfo"]["name"] == "blastradius"
    names = {t["name"] for t in mcp_server.handle(_rpc("tools/list"))["result"]["tools"]}
    assert names == {"list_stacks", "paths_to_sinks", "toxic_combinations", "choke_points",
                     "precedent_lookup"}
    r = mcp_server.handle(_rpc("tools/call", {"name": "paths_to_sinks", "arguments": {"stack": sid}}))
    body = json.loads(r["result"]["content"][0]["text"])
    assert r["result"]["isError"] is False
    assert body["path_count"] == 8 and body["run_time_ms"] < 100 and body["paths"][0]["nodes"]


def test_mcp_server_toxic_and_choke_points(load_demo):
    sid = load_demo("vulnerable")

    def call(name):
        r = mcp_server.handle(_rpc("tools/call", {"name": name, "arguments": {"stack": sid}}))
        return json.loads(r["result"]["content"][0]["text"])

    assert call("toxic_combinations")["toxic"] is True
    assert call("choke_points")["choke_points"][0]["id"] == "fetch_url"


def test_mcp_server_precedent_lookup(load_demo):
    from backend.precedent import findings, seed

    seed.build(reset=True)
    sid = load_demo("vulnerable")
    findings.remember_scan(sid, owner="public")
    r = mcp_server.handle(_rpc("tools/call", {"name": "precedent_lookup",
                                              "arguments": {"stack": sid}}))
    body = json.loads(r["result"]["content"][0]["text"])
    assert "exploited in 2 earlier stacks" in body["headline"]


def test_mcp_server_is_tenant_scoped_and_reports_unknown_stacks(track_graph):
    sid = unique("mcpt")
    api = TestClient(app)
    api.post("/stacks", params={"stack_id": sid}, headers={"X-Tenant": "acme"},
             json={"id": sid, "servers": [{"id": "a", "tools": [{"name": "read_email"}]}]})
    track_graph(stack_graph_name(sid))
    assert tenancy.owner_of(stack_graph_name(sid)) == "acme"
    r = mcp_server.handle(_rpc("tools/call", {"name": "paths_to_sinks", "arguments": {"stack": sid}}))
    assert r["result"]["isError"] is True  # the MCP server runs as the public tenant
    r = mcp_server.handle(_rpc("tools/call", {"name": "nope", "arguments": {}}))
    assert r["result"]["isError"] is True


def test_mcp_server_never_writes(load_demo):
    sid = load_demo("vulnerable")
    g = client.Graph(stack_graph_name(sid))
    before = g.ro_query("MATCH (n) RETURN count(n)").rows
    for name in ("paths_to_sinks", "toxic_combinations", "choke_points"):
        mcp_server.handle(_rpc("tools/call", {"name": name, "arguments": {"stack": sid}}))
    assert g.ro_query("MATCH (n) RETURN count(n)").rows == before


def test_mcp_server_over_real_stdio(load_demo):
    sid = load_demo("vulnerable")
    stdin = "\n".join(json.dumps(m) for m in [
        _rpc("initialize"),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        _rpc("tools/call", {"name": "paths_to_sinks", "arguments": {"stack": sid}}, 2),
    ]) + "\n"
    p = subprocess.run([sys.executable, "-m", "backend.mcp_server"], cwd=ROOT, input=stdin,
                       env={**os.environ, "BLASTRADIUS_LLM": "mock", "PYTHONPATH": str(ROOT)},
                       capture_output=True, text=True, timeout=60)
    lines = [json.loads(l) for l in p.stdout.splitlines()]
    assert len(lines) == 2, "the notification must get no reply"
    assert json.loads(lines[1]["result"]["content"][0]["text"])["path_count"] == 8
    assert "MOCK MODE" in p.stderr


# ---- FalkorDB removed: everything fails closed and loudly ---------------------------------

@pytest.mark.no_db
def test_guard_denies_when_falkordb_is_unreachable():
    r = _py(
        "import json; from backend.guard import decide\n"
        "d = decide.check('s1', 'any-stack', 'read_email', {})\n"
        "print(json.dumps({'decision': d.decision, 'closed': d.fail_closed, 'why': d.reasons}))",
        DEAD)
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["decision"] == "DENY" and out["closed"] is True
    assert "FalkorDB unavailable" in out["why"][0]


@pytest.mark.no_db
def test_bad_credentials_are_reported_as_such_and_still_fail_closed(monkeypatch):
    import redis

    from backend import config
    from backend.graph import client

    def refuse(*a, **k):
        raise redis.exceptions.AuthenticationError("invalid username-password pair")

    monkeypatch.setattr(client, "FalkorDB", refuse)
    monkeypatch.setattr(config, "FALKORDB_HOST", "db.example")
    client._db.cache_clear()
    try:
        with pytest.raises(client.GraphUnavailable, match="rejected the credentials"):
            client.ping()
    finally:
        client._db.cache_clear()


@pytest.mark.no_db
def test_api_returns_503_not_an_empty_200_when_falkordb_is_unreachable():
    r = _py(
        "from fastapi.testclient import TestClient\n"
        "from backend.api.main import app\n"
        "c = TestClient(app, raise_server_exceptions=False)\n"
        "a = c.get('/health'); b = c.get('/stacks')\n"
        "print(a.status_code, b.status_code, b.json().get('error'))",
        DEAD)
    status_health, status_stacks, err = r.stdout.strip().splitlines()[-1].split()
    assert status_stacks == "503" and err == "falkordb_unavailable"
    assert status_health in ("500", "503")


@pytest.mark.no_db
def test_mcp_server_reports_an_error_when_falkordb_is_unreachable():
    r = _py(
        "import json; from backend import mcp_server\n"
        "x = mcp_server.handle({'jsonrpc':'2.0','id':1,'method':'tools/call',"
        "'params':{'name':'list_stacks','arguments':{}}})\n"
        "print(json.dumps(x['result']['isError']), x['result']['content'][0]['text'][:60].replace(chr(10),' '))",
        DEAD)
    assert r.stdout.strip().splitlines()[-1].startswith("true")


@pytest.mark.no_db
def test_proxy_denies_every_tool_call_when_falkordb_is_unreachable():
    msgs = "\n".join(json.dumps(_rpc("tools/call", {"name": t, "arguments": {}}, i))
                     for i, t in enumerate(["read_email", "send_email", "db_query"], 1)) + "\n"
    env = {**os.environ, "BLASTRADIUS_LLM": "mock", "PYTHONPATH": str(ROOT), **DEAD}
    p = subprocess.run(
        [sys.executable, "-m", "backend.guard.mcp_proxy", "--stack", "s", "--session", "k",
         "--approve", "deny", "--", sys.executable, str(ROOT / "tests" / "fake_mcp_server.py")],
        cwd=ROOT, env=env, input=msgs, capture_output=True, text=True, timeout=60)
    replies = [json.loads(l) for l in p.stdout.splitlines()]
    assert len(replies) == 3
    for r in replies:
        assert r["result"]["isError"] is True
        assert "BlastRadius DENY" in r["result"]["content"][0]["text"]
        assert "ran " not in r["result"]["content"][0]["text"], "nothing may reach the child"


@pytest.mark.no_db
def test_the_graph_is_load_bearing_no_decision_code_keeps_a_copy_of_it():
    """Static guard against a shadow in-memory graph: the Guard must not hold the stack
    structure in module-level state, and networkx is only used by the defense planner."""
    for f in ("decide.py", "taint.py", "trust.py", "approvals.py"):
        src = (ROOT / "backend" / "guard" / f).read_text()
        assert "networkx" not in src and "nx." not in src, f
    for f in ("analysis.py", "client.py"):
        src = (ROOT / "backend" / "graph" / f).read_text()
        assert "networkx" not in src, f
