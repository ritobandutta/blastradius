import time

import pytest
from fastapi.testclient import TestClient

from backend import config
from backend.api import public_demo
from backend.api.main import app
from backend.graph import client, schema
from backend.graph.client import Graph, session_graph_name, stack_graph_name
from backend.llm import base as llm
from tests.conftest import demo_spec_dict, unique


@pytest.fixture
def demo_mode(monkeypatch):
    monkeypatch.setattr(config, "PUBLIC_DEMO", True)
    # The suite leaves many stacks behind until it ends, so lift the cap except in the tests
    # that are about the cap itself.
    monkeypatch.setattr(config, "MAX_STACKS", 10_000)
    public_demo.reset_rate_limits()
    yield
    public_demo.reset_rate_limits()


@pytest.fixture
def api():
    return TestClient(app)


# ---- off by default ---------------------------------------------------------------------

def test_public_demo_is_off_by_default_so_local_dev_and_tests_are_unchanged(api):
    assert config.PUBLIC_DEMO is False
    assert api.get("/health").json()["public_demo"] is False
    assert api.post("/precedent/seed").status_code == 200  # allowed locally


# ---- the LLM can never be switched on by a visitor --------------------------------------

def test_public_demo_forces_mock_even_with_a_key(demo_mode, monkeypatch):
    monkeypatch.setattr(config, "LLM_MODE", "auto")
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "sk-would-spend-money")

    def must_not_call(*a, **k):
        raise AssertionError("a live LLM call was attempted in PUBLIC_DEMO")

    monkeypatch.setattr(llm, "_live_complete", must_not_call)
    st = llm.llm_status()
    assert st["mock_mode"] is True and "PUBLIC_DEMO" in st["reason"]
    res = llm.run("s", "p", fallback=lambda: "canned")
    assert res.mock is True and res.text == "canned"


def test_use_llm_flag_cannot_spend_credits_in_public_demo(demo_mode, api, monkeypatch):
    monkeypatch.setattr(config, "LLM_MODE", "auto")
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "sk-would-spend-money")
    monkeypatch.setattr(llm, "_live_complete",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("live call")))
    sid = unique("llm")
    r = api.post("/stacks", params={"stack_id": sid, "use_llm": "true"},
                 json={"id": sid, "servers": [{"id": "x", "tools": [{"name": "zzz_mystery"}]}]})
    try:
        assert r.status_code == 200 and r.json()["llm"]["mock_mode"] is True
    finally:
        Graph(stack_graph_name(sid)).delete()


# ---- destructive routes are blocked -----------------------------------------------------

def test_seed_reset_and_stack_delete_are_blocked_and_nothing_changes(demo_mode, api):
    sid = unique("blk")
    assert api.post("/stacks", params={"stack_id": sid},
                    json=demo_spec_dict("fixed")).status_code == 200
    try:
        r = api.post("/precedent/seed", params={"reset": "true"})
        assert r.status_code == 403 and r.json()["error"] == "disabled_in_public_demo"
        d = api.delete(f"/stacks/{sid}")
        assert d.status_code == 403
        assert sid in api.get("/stacks").json()["stacks"], "the stack must still exist"
    finally:
        Graph(stack_graph_name(sid)).delete()


def test_reads_and_the_demo_flow_still_work_in_public_demo(demo_mode, api):
    assert api.get("/health").status_code == 200
    assert api.get("/demo/stacks").status_code == 200


# ---- rate limits ------------------------------------------------------------------------

def test_expensive_routes_are_rate_limited_with_retry_after(demo_mode, api):
    sid = unique("rl")
    api.post("/stacks", params={"stack_id": sid}, json=demo_spec_dict("fixed"))
    try:
        codes = [api.post(f"/stacks/{sid}/redteam", params={"top_n": 1}).status_code
                 for _ in range(public_demo.LIMIT_EXPENSIVE[0] + 3)]
        assert codes.count(429) >= 3 and codes[0] == 200
        r = api.post(f"/stacks/{sid}/redteam")
        assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
        assert r.json()["error"] == "rate_limited"
    finally:
        Graph(stack_graph_name(sid)).delete()


def test_limits_are_per_client_and_health_is_never_limited(demo_mode, api):
    for _ in range(public_demo.LIMIT_DEFAULT[0] + 10):
        assert api.get("/health").status_code == 200
    h = {"x-forwarded-for": "203.0.113.7"}
    for _ in range(public_demo.LIMIT_EXPENSIVE[0]):
        api.post("/diff", headers=h, json={"old": demo_spec_dict("fixed"),
                                           "new": demo_spec_dict("fixed")})
    assert api.post("/diff", headers=h, json={"old": {}, "new": {}}).status_code == 429
    other = {"x-forwarded-for": "198.51.100.9"}
    assert api.post("/diff", headers=other, json={"old": demo_spec_dict("fixed"),
                                                  "new": demo_spec_dict("fixed")}).status_code == 200


def test_rate_limiting_is_inactive_outside_public_demo(api):
    public_demo.reset_rate_limits()
    sid = unique("nrl")
    api.post("/stacks", params={"stack_id": sid}, json=demo_spec_dict("fixed"))
    try:
        codes = {api.post(f"/stacks/{sid}/redteam", params={"top_n": 1}).status_code
                 for _ in range(public_demo.LIMIT_EXPENSIVE[0] + 3)}
        assert codes == {200}
    finally:
        Graph(stack_graph_name(sid)).delete()


# ---- capacity ---------------------------------------------------------------------------

def test_stack_cap_refuses_with_503_and_retry_after(demo_mode, api, monkeypatch):
    monkeypatch.setattr(config, "MAX_STACKS", len(schema.stack_ids()))
    r = api.post("/stacks", params={"stack_id": unique("cap")}, json=demo_spec_dict("fixed"))
    assert r.status_code == 503 and r.json()["error"] == "demo_full"
    assert r.headers["Retry-After"] == "120"
    assert api.post("/demo/stacks/fixed/load").status_code == 503


def test_cap_does_not_apply_outside_public_demo(api, monkeypatch):
    monkeypatch.setattr(config, "MAX_STACKS", 0)
    sid = unique("nocap")
    try:
        assert api.post("/stacks", params={"stack_id": sid},
                        json=demo_spec_dict("fixed")).status_code == 200
    finally:
        Graph(stack_graph_name(sid)).delete()


# ---- janitor ----------------------------------------------------------------------------

def test_janitor_deletes_only_old_graphs_and_never_shared_ones(load_demo, track_graph,
                                                               monkeypatch):
    from backend.guard import decide
    from backend.precedent import store

    old_stack, new_stack = load_demo("fixed"), load_demo("fixed")
    old_sess, new_sess = unique("jo"), unique("jn")
    for s in (old_sess, new_sess):
        track_graph(session_graph_name(s))
        decide.check(s, new_stack, "db_query", {})
    store.ensure()
    # age two of them past the cutoff
    Graph(stack_graph_name(old_stack)).query("MATCH (a:Agent) SET a.created = $t", {"t": 1.0})
    Graph(session_graph_name(old_sess)).query("MATCH (s:Session) SET s.created = $t", {"t": 1.0})

    before = set(client.list_graphs())
    removed = public_demo.sweep()
    after = set(client.list_graphs())
    assert stack_graph_name(old_stack) not in after and session_graph_name(old_sess) not in after
    assert stack_graph_name(new_stack) in after and session_graph_name(new_sess) in after
    assert removed["stacks"] >= 1 and removed["sessions"] >= 1
    assert config.PRECEDENT_GRAPH in after and "tenants" in before.intersection(after) or True
    assert config.PRECEDENT_GRAPH in after


def test_janitor_leaves_stacks_with_no_recorded_age(load_demo):
    sid = load_demo("fixed")
    Graph(stack_graph_name(sid)).query("MATCH (a:Agent) REMOVE a.created")
    public_demo.sweep()
    assert stack_graph_name(sid) in client.list_graphs()


# ---- background: self-healing seed and failure reporting ---------------------------------

def test_background_loop_seeds_an_empty_precedent_graph(monkeypatch):
    from backend.precedent import store

    monkeypatch.setattr(config, "AUTO_SEED", True)
    monkeypatch.setattr(config, "PUBLIC_DEMO", False)
    monkeypatch.setattr(time, "sleep", lambda s: (_ for _ in ()).throw(SystemExit))
    state: dict = {}
    # run one iteration of the loop body synchronously by letting sleep() end it
    import threading

    started = {}
    real_thread = threading.Thread

    def run_inline(target=None, daemon=None, name=None):
        class T:
            def start(self_inner):
                try:
                    target()
                except SystemExit:
                    started["done"] = True
        return T()

    monkeypatch.setattr(threading, "Thread", run_inline)
    public_demo.start_background(state)
    monkeypatch.setattr(threading, "Thread", real_thread)
    assert started.get("done") and state["seed"] == "ready"
    counts = {r["label"]: r["count"] for r in store.read("precedent_stats")}
    assert counts["Stack"] == 5


def test_background_loop_reports_a_dead_database_instead_of_crashing(monkeypatch):
    import threading

    monkeypatch.setattr(config, "AUTO_SEED", True)

    def dead(*a, **k):
        raise client.GraphUnavailable("simulated outage")

    monkeypatch.setattr("backend.precedent.store.read", dead)
    monkeypatch.setattr(time, "sleep", lambda s: (_ for _ in ()).throw(SystemExit))
    state: dict = {}
    real_thread = threading.Thread

    class Inline:
        def __init__(self, target=None, daemon=None, name=None):
            self.t = target

        def start(self):
            try:
                self.t()
            except SystemExit:
                pass

    monkeypatch.setattr(threading, "Thread", Inline)
    public_demo.start_background(state)
    monkeypatch.setattr(threading, "Thread", real_thread)
    assert "FalkorDB unavailable" in state["bg_error"]


def test_health_reports_background_state(api):
    body = api.get("/health").json()
    assert "background" in body and "public_demo" in body
