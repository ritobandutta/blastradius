import json
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.defense import drift, mincut, patch, pr_text, proof
from backend.graph import analysis, client, schema
from backend.graph.client import stack_graph_name
from tests.conftest import demo_spec_dict, unique

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def vuln(load_demo):
    return load_demo("vulnerable")


# ---- min-cut -----------------------------------------------------------------------------

def test_plan_severs_every_path_with_minimum_cost(vuln):
    fp = mincut.plan(vuln)
    assert fp.paths_before == 8
    # four exits (shell, email, slack, fetch) each need one gate: cost 4, nothing cheaper exists
    assert fp.plan_cost == 4 and {f.action for f in fp.fixes} == {"gate"}
    assert {f.tool for f in fp.fixes} == {"run_shell", "send_email", "slack_post", "fetch_url"}
    assert sum(f.paths_severed for f in fp.fixes) == 8


def test_networkx_cut_equals_falkordb_maxflow(vuln):
    fp = mincut.plan(vuln)
    assert fp.maxflow_falkordb is not None
    assert fp.maxflow_falkordb == pytest.approx(fp.cut_value)
    assert fp.to_dict()["maxflow_agrees"] is True


def test_constraints_change_the_plan_and_stay_minimal(vuln):
    base = mincut.plan(vuln)
    keep = mincut.plan(vuln, keep_ungated={"slack_post"})
    # slack_post may not be gated, so the cut routes around it with a scoped token (cost 3)
    assert {f.action for f in keep.fixes if f.tool == "slack_post"} == {"scope"}
    assert keep.plan_cost == base.plan_cost + 2
    assert keep.maxflow_falkordb == pytest.approx(keep.cut_value)


def test_forbidding_gate_and_remove_falls_back_to_scoping(vuln):
    # With the ingest tool protected from removal and the acting tool protected from gating,
    # the only lever left is a scoped token. (A scoped token is always available, so the
    # "no fix exists" ValueError in plan() is a defensive guard that constraints cannot reach.)
    data = demo_spec_dict("vulnerable")
    for s in data["servers"]:
        s["tools"] = [t for t in s["tools"] if t["name"] in ("read_email", "run_shell")]
    data["servers"] = [s for s in data["servers"] if s["tools"]]
    sid = unique("unsat")
    spec = __import__("backend.parser.stack_spec", fromlist=["load_spec"]).load_spec(
        {**data, "id": sid})
    schema.load_stack(spec)
    try:
        fp = mincut.plan(sid, keep_ungated={"run_shell"}, keep_tools={"read_email"})
        assert {f.action for f in fp.fixes} == {"scope"}
    finally:
        schema.delete_stack(sid)


def test_clean_stack_needs_no_fixes(load_demo):
    fp = mincut.plan(load_demo("fixed"))
    assert fp.fixes == [] and fp.paths_before == 0


def test_scratch_graphs_are_cleaned_up(vuln):
    mincut.plan(vuln)
    assert not [g for g in client.list_graphs() if g.startswith("defense:")]


# ---- proof of absence --------------------------------------------------------------------

def test_proof_of_absence_reruns_the_same_query(vuln):
    fp = mincut.plan(vuln)
    pid = unique("patched")
    try:
        r = proof.verify(vuln, fp, patched_id=pid)
        assert r["verified_safe"] is True and r["paths_after"] == 0
        assert r["badge"].startswith("0 paths found,") and r["badge"].endswith("ms")
        assert r["query"] == "paths_to_sinks"
        # independent re-check straight against the patched graph
        assert analysis.paths_to_sinks(pid).paths == []
        assert analysis.toxic_combinations(pid)["toxic"] is False
    finally:
        schema.delete_stack(pid)


def test_redteam_attacks_complete_before_and_fail_after_the_patch(vuln):
    fp = mincut.plan(vuln)
    pid = unique("patched")
    try:
        r = proof.verify(vuln, fp, patched_id=pid)
        assert r["redteam_before"]["completed"] == r["redteam_before"]["attacks"] > 0
        after = r["redteam_after"]
        assert after["completed"] == 0 and after["failed_against_patch"] == after["attacks"] > 0
        assert after["defence"] == "patched config only (no Guard)"
    finally:
        schema.delete_stack(pid)


def test_a_half_fix_is_not_reported_as_safe(vuln):
    fp = mincut.plan(vuln)
    fp.fixes = fp.fixes[:2]  # apply only part of the plan
    pid = unique("half")
    try:
        r = proof.verify(vuln, fp, patched_id=pid, rerun_redteam=False)
        assert r["verified_safe"] is False and r["paths_after"] > 0
        assert "still open" in r["badge"]
    finally:
        schema.delete_stack(pid)


def test_patch_changes_only_what_the_plan_says(vuln):
    fp = mincut.plan(vuln)
    before = schema.stored_spec(vuln)
    after = patch.apply_fixes(before, fp.fixes, "x")
    assert {c["tool"] for c in patch.changes(before, after)} == {f.tool for f in fp.fixes}
    assert before.tool_count() == after.tool_count()  # nothing removed
    mcp = patch.to_mcp_json(after)
    assert mcp["mcpServers"]["ops"]["blastradius"]["tools"]["run_shell"]["gated"] is True


def test_scoped_fix_is_applied_and_proven(vuln):
    fp = mincut.plan(vuln, keep_ungated={"slack_post"})
    pid = unique("scoped")
    try:
        r = proof.verify(vuln, fp, patched_id=pid, rerun_redteam=False)
        assert r["verified_safe"] is True
        assert any(c["change"] == "scope" and c["tool"] == "slack_post" for c in r["changes"])
    finally:
        schema.delete_stack(pid)


def test_remediation_markdown_contains_the_measured_proof(vuln):
    fp = mincut.plan(vuln)
    pid = unique("pr")
    try:
        r = proof.verify(vuln, fp, patched_id=pid)
        md = pr_text.remediation_markdown(fp, r)
        assert "Verified safe: 0 attack paths remain" in md
        assert r["badge"] in md and "algo.maxFlow" in md and "run_shell" in md
    finally:
        schema.delete_stack(pid)


# ---- drift diff --------------------------------------------------------------------------

def test_drift_introduced_and_removed_paths():
    old, new = demo_spec_dict("fixed"), demo_spec_dict("vulnerable")
    d = drift.diff_dicts(old, new)
    assert len(d["introduced"]) == 8 and d["removed"] == [] and d["regression"] is True
    back = drift.diff_dicts(new, old)
    assert len(back["removed"]) == 8 and back["introduced"] == [] and back["regression"] is False


def test_drift_single_tool_change():
    old = demo_spec_dict("fixed")
    new = json.loads(json.dumps(old))
    for s in new["servers"]:
        for t in s["tools"]:
            if t["name"] == "send_email":
                t["gated"] = False
    d = drift.diff_dicts(old, new)
    assert {p["act_tool"] for p in d["introduced"]} == {"send_email"}
    md = drift.markdown(d)
    assert "opens new attack paths" in md and "send_email" in md and "| **delta** |" in md


def test_drift_no_change_and_temp_graphs_removed():
    s = demo_spec_dict("vulnerable")
    d = drift.diff_dicts(s, s)
    assert d["introduced"] == [] and d["removed"] == [] and d["risk_delta"] == 0
    assert not [g for g in client.list_graphs() if g.startswith("stack:drift-")]


# ---- API and CLI -------------------------------------------------------------------------

def test_api_verify_returns_plan_proof_and_markdown(vuln):
    api = TestClient(app)
    r = api.post(f"/stacks/{vuln}/defense/verify", json={"keep_ungated": ["slack_post"]})
    body = r.json()
    try:
        assert r.status_code == 200
        assert body["proof"]["verified_safe"] and body["plan"]["maxflow_agrees"]
        assert "Proof of absence" in body["pr_markdown"]
    finally:
        schema.delete_stack(body["proof"]["patched_stack"])


def test_api_diff_endpoint():
    api = TestClient(app)
    r = api.post("/diff", json={"old": demo_spec_dict("fixed"), "new": demo_spec_dict("vulnerable")})
    assert r.status_code == 200 and "opens new attack paths" in r.json()["markdown"]


def _cli(*args):
    import os

    env = {**os.environ, "BLASTRADIUS_LLM": "mock", "PYTHONPATH": str(ROOT)}
    return subprocess.run([sys.executable, "-m", "backend.cli", *args], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=120)


def test_cli_diff_fails_on_regression_and_prints_mock_banner():
    r = _cli("diff", "demo/stacks/fixed.json", "demo/stacks/vulnerable.json",
             "--fail-on-regression")
    assert r.returncode == 1 and "opens new attack paths" in r.stdout
    assert "MOCK MODE" in r.stderr
    ok = _cli("diff", "demo/stacks/vulnerable.json", "demo/stacks/fixed.json",
              "--fail-on-regression")
    assert ok.returncode == 0 and "closes attack paths" in ok.stdout


def test_cli_fix_writes_files_and_proves_safety(tmp_path):
    r = _cli("fix", "demo/stacks/vulnerable.json", "-o", str(tmp_path))
    assert r.returncode == 0, r.stderr + r.stdout
    assert "0 paths found" in r.stdout
    assert (tmp_path / "mcp.patched.json").exists()
    assert "Verified safe" in (tmp_path / "PR_DESCRIPTION.md").read_text()
    assert not [g for g in client.list_graphs() if g.startswith("stack:cli-")]


def test_cli_scan_lists_paths():
    r = _cli("scan", "demo/stacks/second_pattern.json")
    assert r.returncode == 0 and "open risk" in r.stdout and "http_post" in r.stdout
