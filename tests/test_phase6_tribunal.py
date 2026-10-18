import ast
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.graph.client import session_graph_name, stack_graph_name
from backend.guard import approvals, decide, taint
from backend.precedent import store, tribunal
from tests.conftest import demo_spec_dict, unique

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def gated_stack(load_demo):
    data = demo_spec_dict("vulnerable")
    for s in data["servers"]:
        for t in s["tools"]:
            if t["name"] == "slack_post":
                t["gated"] = True
    return load_demo("vulnerable", servers=data["servers"])


@pytest.fixture
def escalated(gated_stack, track_graph):
    sess = unique("tr")
    track_graph(session_graph_name(sess))
    d = decide.check(sess, gated_stack, "slack_post", {"text": "hello"})
    assert d.decision == decide.ESCALATE
    return gated_stack, sess, d.seq


def _snapshot(sess, seq):
    g = taint.session_graph(sess)
    return (g.named("session_event_status", {"seq": seq}).rows,
            g.named("session_events").rows, g.named("session_edges").rows)


# ---- the Tribunal can never change a DENY -------------------------------------------------

def test_tribunal_refuses_to_hear_a_deny(load_demo, track_graph):
    sid = load_demo("vulnerable")
    sess = unique("trd")
    track_graph(session_graph_name(sess))
    decide.check(sess, sid, "read_email")
    deny = decide.check(sess, sid, "send_email", {"to": "a@b.co"})
    assert deny.decision == decide.DENY
    before = _snapshot(sess, deny.seq)
    with pytest.raises(tribunal.NotEscalated):
        tribunal.hear(sess, deny.seq)
    assert _snapshot(sess, deny.seq) == before
    assert store.read("precedent_stats") == [] or \
        all(r["label"] != "Ruling" for r in store.read("precedent_stats"))


def test_deny_stays_deny_even_if_the_tribunal_is_asked_for_a_ruling_via_http(load_demo,
                                                                             track_graph):
    sid = load_demo("vulnerable")
    sess = unique("trh")
    track_graph(session_graph_name(sess))
    api = TestClient(app)
    api.post("/guard/check", json={"session": sess, "stack": sid, "tool": "read_email"})
    deny = api.post("/guard/check", json={"session": sess, "stack": sid, "tool": "send_email",
                                          "args": {"to": "a@b.co"}}).json()
    r = api.post(f"/guard/sessions/{sess}/events/{deny['seq']}/tribunal")
    assert r.status_code == 409
    ev = api.get(f"/guard/sessions/{sess}").json()["events"][-1]
    assert ev["decision"] == "DENY" and ev["status"] == "denied" and ev["executed"] is False
    # and the human gate still refuses to flip it
    assert api.post(f"/guard/sessions/{sess}/events/{deny['seq']}/resolve",
                    json={"approve": True}).status_code == 409


def test_hearing_an_escalate_leaves_the_event_pending_and_unexecuted(escalated):
    _, sess, seq = escalated
    before = _snapshot(sess, seq)
    out = tribunal.hear(sess, seq)
    assert out["advisory"] is True and out["suggested_verdict"] in ("HOLD", "ALLOW")
    assert _snapshot(sess, seq) == before
    st = taint.event_status(taint.session_graph(sess), seq)
    assert st["decision"] == "ESCALATE" and st["status"] == "pending" and st["executed"] is False


def test_even_an_allow_verdict_cannot_approve_the_call(escalated, monkeypatch):
    """Force the judge to say ALLOW: the call must still be pending until a human clicks."""
    _, sess, seq = escalated
    from backend.llm import base as llm

    monkeypatch.setattr(llm, "run", lambda system, prompt, fallback, max_tokens=1024:
                        llm.LLMResult("Verdict: ALLOW. Looks fine.", mock=False, model="m"))
    out = tribunal.hear(sess, seq)
    assert out["suggested_verdict"] == "ALLOW"
    st = taint.event_status(taint.session_graph(sess), seq)
    assert st["status"] == "pending" and st["executed"] is False
    assert approvals.wait_for_resolution(sess, seq, timeout=0.2, poll=0.05) == "pending"


@pytest.mark.no_db
def test_tribunal_module_cannot_reach_the_approval_gate_or_the_guard():
    tree = ast.parse((ROOT / "backend" / "precedent" / "tribunal.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
            imported |= {f"{node.module}.{a.name}" for a in node.names}
        elif isinstance(node, ast.Import):
            imported |= {a.name for a in node.names}
    assert not any("approvals" in i or "decide" in i for i in imported), imported


@pytest.mark.no_db
def test_guard_decision_code_does_not_import_the_tribunal():
    for f in ("decide.py", "approvals.py", "taint.py", "trust.py"):
        src = (ROOT / "backend" / "guard" / f).read_text()
        assert "tribunal" not in src, f"{f} must not depend on the Tribunal"


# ---- behaviour ---------------------------------------------------------------------------

def test_mock_mode_is_visible_on_every_ruling(escalated):
    _, sess, seq = escalated
    out = tribunal.hear(sess, seq)
    assert out["mock_mode"] is True and out["model"] == "mock-deterministic"
    assert out["prosecutor"] and out["defense"] and out["judge"]


def test_judge_cites_earlier_rulings_on_the_same_tool(gated_stack, track_graph):
    seqs = []
    for i in range(2):
        sess = unique(f"cite{i}")
        track_graph(session_graph_name(sess))
        d = decide.check(sess, gated_stack, "slack_post", {"text": str(i)})
        seqs.append((sess, d.seq))
    first = tribunal.hear(*seqs[0])
    assert first["cites"] == []
    second = tribunal.hear(*seqs[1])
    assert [c["id"] for c in second["cites"]] == [first["ruling"]]
    chain = tribunal.chain(second["ruling"])
    assert [c["id"] for c in chain["cites"]] == [first["ruling"]]
    assert first["ruling"] in second["judge"]


def test_ruling_is_stored_as_advisory_in_the_precedent_graph(escalated):
    _, sess, seq = escalated
    out = tribunal.hear(sess, seq)
    rows = store.graph().ro_query(
        "MATCH (r:Ruling {id:$id}) RETURN r.advisory AS a, r.tool AS t, r.mock AS m",
        {"id": out["ruling"]}).dicts()
    assert rows == [{"a": True, "t": "slack_post", "m": True}]


def test_a_failed_live_call_is_reported_not_hidden(escalated, monkeypatch):
    _, sess, seq = escalated
    from backend import config
    from backend.llm import base as llm

    monkeypatch.setattr(config, "LLM_MODE", "auto")
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "sk-test-not-real")

    def fail(system, prompt, max_tokens):
        raise llm.LLMError("AuthenticationError: invalid x-api-key")

    monkeypatch.setattr(llm, "_live_complete", fail)
    out = tribunal.hear(sess, seq)
    assert out["mock_mode"] is True
    assert "AuthenticationError" in out["llm_error"]


def test_tribunal_endpoint_and_tenant_scoping(gated_stack, track_graph):
    api = TestClient(app)
    sess = unique("trapi")
    track_graph(session_graph_name(sess))
    r = api.post("/guard/check", json={"session": sess, "stack": gated_stack,
                                       "tool": "slack_post", "args": {"text": "x"}}).json()
    out = api.post(f"/guard/sessions/{sess}/events/{r['seq']}/tribunal")
    assert out.status_code == 200 and out.json()["advisory"] is True
    assert api.get(f"/guard/rulings/{out.json()['ruling']}").status_code == 200
    # another tenant cannot convene a hearing on a session it does not own
    foreign = api.post(f"/guard/sessions/{sess}/events/{r['seq']}/tribunal",
                       headers={"X-Tenant": "globex"})
    assert foreign.status_code == 404
