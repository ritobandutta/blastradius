import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.graph import client
from tests.conftest import demo_spec_dict, unique


@pytest.fixture
def api():
    return TestClient(app)


@pytest.fixture
def stack(api, track_graph):
    sid = unique("api")
    r = api.post("/stacks", params={"stack_id": sid}, json=demo_spec_dict("vulnerable"))
    assert r.status_code == 200, r.text
    track_graph(client.stack_graph_name(sid))
    return sid


def test_health_reports_mock_mode(api):
    h = api.get("/health").json()
    assert h["ok"] and h["llm"]["mock_mode"] is True and h["llm"]["reason"]


def test_paths_endpoint_returns_paths_with_latency(api, stack):
    body = api.get(f"/stacks/{stack}/paths").json()
    assert body["path_count"] == 8
    assert body["open_risk"] > 0
    assert body["run_time_ms"] < 100
    assert body["paths"][0]["nodes"][0] and body["paths"][0]["edges"]


def test_unknown_stack_is_404(api):
    assert api.get("/stacks/does-not-exist/paths").status_code == 404


def test_node_endpoint_explains_a_tool(api, stack):
    body = api.get(f"/stacks/{stack}/nodes/run_shell").json()
    assert body["props"]["side_effect"] == "exec"


def test_graph_endpoint_has_nodes_and_edges(api, stack):
    body = api.get(f"/stacks/{stack}/graph").json()
    assert {n["label"] for n in body["nodes"]} >= {"Agent", "Tool", "DataSource", "Sink"}
    assert any(e["type"] == "CAN_INVOKE" for e in body["edges"])


def test_mcp_json_upload_flags_unconfirmed_tools(api, track_graph):
    sid = unique("mcpimport")
    r = api.post("/stacks", params={"stack_id": sid},
                 json={"mcpServers": {"gmail": {"command": "gmail-mcp"}}})
    track_graph(client.stack_graph_name(sid))
    assert r.status_code == 200
    assert r.json()["needs_confirmation"], "imported tools must be confirmed by a human"


def test_invalid_spec_is_422(api):
    r = api.post("/stacks", json={"id": "bad id!", "servers": []})
    assert r.status_code == 422
