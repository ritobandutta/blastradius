import pytest

from backend.graph import analysis, client
from backend.graph.client import Graph, stack_graph_name
from backend.parser import annotate
from backend.parser.models import StackSpec, ToolSpec
from backend.parser.stack_spec import from_mcp_config, load_spec


def test_vulnerable_stack_exact_paths(load_demo):
    sid = load_demo("vulnerable")
    report = analysis.paths_to_sinks(sid)
    ids = {p.id for p in report.paths}
    # The two worst: an untrusted email or web page steers the agent into a host shell.
    assert "inbound-email>read_email>support-agent>run_shell>host-shell" in ids
    assert "web-content>fetch_url>support-agent>run_shell>host-shell" in ids
    # An email can also be leaked out through three different egress tools.
    for tool, sink in [("send_email", "outbound-email"), ("slack_post", "slack-channel"),
                       ("fetch_url", "web-egress")]:
        assert f"inbound-email>read_email>support-agent>{tool}>{sink}" in ids
    assert len(report.paths) == 8
    assert report.paths[0].score >= report.paths[-1].score
    assert report.open_risk == pytest.approx(sum(p.score for p in report.paths))


def test_path_query_is_fast(load_demo):
    sid = load_demo("vulnerable")
    report = analysis.paths_to_sinks(sid)
    assert report.run_time_ms < 100, f"traversal took {report.run_time_ms} ms"


def test_fixed_stack_has_zero_paths(load_demo):
    sid = load_demo("fixed")
    report = analysis.paths_to_sinks(sid)
    assert report.paths == []
    assert report.open_risk == 0
    assert analysis.toxic_combinations(sid)["toxic"] is False


def test_cypher_paths_agree_with_falkordb_sspaths(load_demo):
    """Cross-check: the (source, sink) pairs found by our pattern query must equal the pairs
    FalkorDB's own algo.SSpaths reaches (valid on a stack with no gated/scoped edges)."""
    sid = load_demo("vulnerable")
    ours = {(p.source, p.sink) for p in analysis.paths_to_sinks(sid).paths}
    g = Graph(stack_graph_name(sid))
    res = g.ro_query(
        "MATCH (d:DataSource {trust:'untrusted'}) CALL algo.SSpaths({sourceNode:d, "
        "relTypes:['READ_BY','RETURNS_TO','CAN_INVOKE','REACHES'], maxLen:6, "
        "relDirection:'outgoing', pathCount:1000}) YIELD path "
        "WITH d, nodes(path) AS ns WHERE 'Sink' IN labels(ns[size(ns)-1]) "
        "RETURN DISTINCT d.id AS source, ns[size(ns)-1].id AS sink"
    )
    theirs = {(r["source"], r["sink"]) for r in res.dicts()}
    assert ours == theirs


def test_toxic_combination_detected(load_demo):
    sid = load_demo("vulnerable")
    t = analysis.toxic_combinations(sid)
    assert t["toxic"] is True
    agent = t["agents"][0]
    assert {x["tool"] for x in agent["ingest"]} == {"read_email", "fetch_url"}
    assert {x["tool"] for x in agent["egress"]} >= {"send_email", "slack_post"}
    assert agent["private_data"], "db_query/read_file expose private data"


def test_gating_one_tool_removes_only_its_paths(load_demo):
    from tests.conftest import demo_spec_dict

    data = demo_spec_dict("vulnerable")
    for s in data["servers"]:
        for t in s["tools"]:
            if t["name"] == "run_shell":
                t["gated"] = True
    sid = load_demo("vulnerable", servers=data["servers"])
    ids = {p.id for p in analysis.paths_to_sinks(sid).paths}
    assert not any(i.endswith("run_shell>host-shell") for i in ids)
    assert len(ids) == 6


def test_scoped_token_removes_edge(load_demo):
    from tests.conftest import demo_spec_dict

    data = demo_spec_dict("vulnerable")
    for s in data["servers"]:
        for t in s["tools"]:
            if t["name"] == "slack_post":
                t["reaches"] = [{"id": "slack-channel", "kind": "exfil", "scoped": True}]
    sid = load_demo("vulnerable", servers=data["servers"])
    assert not any(p.sink == "slack-channel" for p in analysis.paths_to_sinks(sid).paths)


def test_choke_points_rank_fetch_url_first(load_demo):
    sid = load_demo("vulnerable")
    cp = analysis.choke_points(sid)["choke_points"]
    assert cp[0]["id"] == "fetch_url"
    assert cp[0]["paths_through"] == 5
    # betweenness comes from FalkorDB's algo.betweenness, not from us
    assert any(c["score"] > 0 for c in cp)


def test_second_pattern_is_tool_description_poisoning(load_demo):
    sid = load_demo("second_pattern")
    sources = {p.source for p in analysis.paths_to_sinks(sid).paths}
    assert "community-notes-tool-descriptions" in sources
    assert "community-notes" in sources


def test_tool_facts_explain_a_node(load_demo):
    sid = load_demo("vulnerable")
    facts = analysis.tool_facts(sid, "run_shell")
    assert facts["label"] == "Tool"
    assert facts["props"]["side_effect"] == "exec"
    assert facts["on_paths"] and facts["open_risk_through"] > 0
    assert any(e["type"] == "REACHES" and e["other"] == "host-shell" for e in facts["edges"])


def test_duplicate_tool_names_rejected():
    spec = load_spec({
        "id": "dup",
        "servers": [{"id": "a", "tools": [{"name": "read_file"}]},
                    {"id": "b", "tools": [{"name": "read_file"}]}],
    })
    from backend.graph import schema

    with pytest.raises(ValueError, match="appears twice"):
        schema.load_stack(spec)


def test_reloading_a_stack_replaces_it(load_demo):
    sid = load_demo("vulnerable")
    g = Graph(stack_graph_name(sid))
    n1 = g.ro_query("MATCH (n) RETURN count(n)").rows[0][0]
    from backend.graph import schema

    schema.load_stack(schema.stored_spec(sid))
    assert g.ro_query("MATCH (n) RETURN count(n)").rows[0][0] == n1


# ---- parser / annotation ----------------------------------------------------------------

@pytest.mark.no_db
def test_rules_table_annotates_known_tools():
    t = annotate.annotate_tool(ToolSpec(name="read_email"))
    assert t.side_effect == "read"
    assert t.reads[0].trust == "untrusted"
    assert t.annotation["side_effect"] == "rules" and t.confirmed


@pytest.mark.no_db
def test_author_values_beat_rules():
    t = annotate.annotate_tool(ToolSpec(name="read_email", side_effect="exec"))
    assert t.side_effect == "exec"
    assert t.annotation["side_effect"] == "spec"


@pytest.mark.no_db
def test_unknown_tool_is_suggested_and_unconfirmed():
    t = annotate.annotate_tool(ToolSpec(name="tweet_it", description="publish a tweet"))
    assert t.side_effect == "network_out"
    assert t.annotation["side_effect"] == "suggested"
    assert t.confirmed is False


@pytest.mark.no_db
def test_mock_mode_never_calls_llm_for_suggestions():
    t = annotate.annotate_tool(ToolSpec(name="zzz_mystery"), use_llm=True)
    assert t.confirmed is False and t.annotation["side_effect"] == "suggested"


@pytest.mark.no_db
def test_mcp_json_import_is_best_effort_and_unconfirmed():
    spec = from_mcp_config(
        {"mcpServers": {
            "gmail": {"command": "npx", "args": ["gmail-mcp"]},
            "slack": {"command": "npx", "args": ["slack-mcp"]},
            "playwright": {"command": "npx", "args": ["@playwright/mcp"]},
        }},
        "imported",
    )
    names = {t.name for s in spec.servers for t in s.tools}
    assert {"read_email", "slack_post", "fetch_url"} <= names
    assert all(not t.confirmed for s in spec.servers for t in s.tools)
    assert isinstance(spec, StackSpec) and spec.source == "mcp.json"


def test_imported_mcp_config_produces_paths(track_graph):
    from backend.graph import schema
    from tests.conftest import unique

    spec = from_mcp_config(
        {"mcpServers": {"gmail": {"command": "gmail-mcp"}, "slack": {"command": "slack-mcp"}}},
        unique("mcp"),
    )
    schema.load_stack(spec)
    track_graph(stack_graph_name(spec.id))
    assert any(p.sink == "slack-channel" for p in analysis.paths_to_sinks(spec.id).paths)


def test_every_query_file_is_listed_in_cypher_docs():
    from pathlib import Path

    docs = (Path(__file__).resolve().parent.parent / "docs" / "CYPHER.md").read_text()
    missing = [n for n in client.query_names() if f"`{n}`" not in docs]
    assert not missing, f"document these in docs/CYPHER.md: {missing}"
