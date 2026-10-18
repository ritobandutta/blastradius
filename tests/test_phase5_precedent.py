import threading

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.defense import mincut, proof
from backend.graph import analysis, client, schema, tenancy
from backend.graph.client import session_graph_name, stack_graph_name
from backend.guard import decide
from backend.precedent import citations, findings, patterns, rules, seed, store
from tests.conftest import demo_spec_dict, unique


@pytest.fixture
def seeded():
    return seed.build(reset=True)


@pytest.fixture
def api():
    return TestClient(app)


def hdr(tenant):
    return {"X-Tenant": tenant}


# ---- the seed corpus is built by the real pipeline, not typed in --------------------------

def test_seed_runs_the_full_pipeline(seeded):
    assert len(seeded["seeded"]) == 5
    counts = {r["label"]: r["count"] for r in store.read("precedent_stats")}
    assert counts["Stack"] == 5 and counts["Pattern"] == len(patterns.PATTERNS)
    assert counts["Finding"] >= 8 and counts["Fix"] >= 4
    stacks = {r["owner"] for r in store.read("precedent_stack_exists", {"id": "seed-helpdesk-bot"})}
    assert stacks == {"seed"}


def test_seed_findings_are_confirmed_by_the_red_team_not_assumed(seeded):
    rows = store.read("precedent_stack_findings", {"stack": "seed-research-agent"})
    assert rows and all(r["confirmed"] for r in rows)
    assert all(r["variants"] for r in rows), "a confirmed finding records which variants worked"


def test_seed_fixes_hold_only_because_proof_of_absence_passed(seeded):
    rows = store.read("precedent_stack_findings", {"stack": "seed-helpdesk-bot"})
    assert any(fx["held"] is True for r in rows for fx in r["fixes"])


def test_seed_stack_graphs_are_cleaned_up_but_knowledge_remains(seeded):
    assert not [g for g in client.list_graphs() if g.startswith("stack:seed-")]
    assert store.read("precedent_stats")


# ---- citations: the two-hop traversal -----------------------------------------------------

def test_new_scan_cites_earlier_stacks_and_the_fix_that_held(seeded, load_demo):
    sid = load_demo("vulnerable")
    findings.remember_scan(sid, owner="public")
    c = citations.citations(sid, owner="public")
    assert c["remembered"]
    send = next(x for x in c["combos"] if x["act_tool"] == "send_email")
    assert {e["stack"] for e in send["earlier"]} == {"seed-helpdesk-bot", "seed-sales-assistant"}
    assert all(e["seeded"] for e in send["earlier"])
    best = send["fixes_that_held"][0]
    assert best["fix"] == "gate:send_email" and len(best["stacks"]) == 2
    assert "exploited in 2 earlier stacks" in send["message"]
    assert "fix that held was" in send["message"]


def test_citations_carry_owasp_tags(seeded, load_demo):
    sid = load_demo("vulnerable")
    findings.remember_scan(sid, owner="public")
    pats = {p["pattern"]: p for p in citations.citations(sid, owner="public")["patterns"]}
    assert pats["indirect-injection-via-email"]["owasp"] == ["LLM01"]
    assert "LLM06" in pats["lethal-trifecta"]["owasp"]


def test_a_stack_never_cites_itself(seeded, load_demo):
    sid = load_demo("vulnerable")
    findings.remember_scan(sid, owner="public")
    for c in citations.citations(sid, owner="public")["combos"]:
        assert sid not in {e["stack"] for e in c["earlier"]}


def test_unscanned_stack_has_no_citations(seeded):
    c = citations.citations("never-scanned", owner="public")
    assert c["remembered"] is False and c["patterns"] == []


def test_second_pattern_stack_is_classified_as_tool_description_poisoning(seeded, load_demo):
    sid = load_demo("second_pattern")
    findings.remember_scan(sid, owner="public")
    pats = {p["pattern"] for p in citations.citations(sid, owner="public")["patterns"]}
    assert "tool-description-poisoning" in pats
    seed_rows = store.read("precedent_stack_findings", {"stack": "seed-plugin-hub"})
    assert any("tool-description-poisoning" in r["patterns"] for r in seed_rows)


def test_rescan_does_not_duplicate_findings(seeded, load_demo):
    sid = load_demo("vulnerable")
    findings.remember_scan(sid, owner="public")
    n = len(findings.stack_findings(sid))
    findings.remember_scan(sid, owner="public")
    assert len(findings.stack_findings(sid)) == n == 8


def test_failed_fix_is_remembered_as_not_held(seeded, load_demo):
    sid = load_demo("vulnerable")
    findings.remember_scan(sid, owner="public")
    fp = mincut.plan(sid)
    fp.fixes = fp.fixes[:1]  # a half fix
    pid = unique("half")
    try:
        result = proof.verify(sid, fp, patched_id=pid, rerun_redteam=False)
        assert result["verified_safe"] is False
        findings.remember_fix(sid, fp, result)
        held = [fx["held"] for r in findings.stack_findings(sid) for fx in r["fixes"]]
        assert held and not any(held)
    finally:
        schema.delete_stack(pid)


# ---- learned rules and the critic --------------------------------------------------------

def test_critic_arms_rules_that_block_exploit_and_spare_benign(seeded):
    by = {r["id"]: r for r in rules.list_rules()}
    ok = by["seed:fetch_url>http_post>exfil"]
    assert ok["status"] == "armed"
    assert ok["critic"]["blocks_exploit"] is True and ok["critic"]["benign_blocked"] == []
    assert ok["critic"]["benign_sessions_checked"] == 8


def test_critic_rejects_a_rule_that_would_block_legitimate_work(seeded):
    by = {r["id"]: r for r in rules.list_rules()}
    bad = by["seed:read_email>send_email>exfil"]
    assert bad["status"] == "rejected"
    assert "reply-to-customer-after-reading-email" in bad["critic"]["reason"]
    assert bad["critic"]["benign_blocked"][0]["call"] == "send_email"


def test_critic_rejects_a_rule_that_does_not_block_its_exploit(seeded, load_demo):
    """The confirmed exploit is read_email -> send_email, but the rule targets slack_post, so it
    would not have stopped the attack it claims to come from. The critic must replay the
    exploit recorded on the finding, not the rule's own fields, or this check is circular."""
    import json

    sid = load_demo("vulnerable")
    store.graph().named("precedent_upsert_rule", {
        "id": "t:wrong", "owner": "t", "ingest_tool": "read_email", "act_tool": "slack_post",
        "sink_kind": "exfil", "sink": "slack-channel", "representative": "x",
        "exploit": json.dumps({"calls": ["read_email", "send_email"]}),
        "findings": [], "ts": 0}, write=True)
    v = rules.critique("t:wrong", sid)
    assert v["status"] == "rejected" and v["blocks_exploit"] is False
    assert v["reason"] == "does not block the confirmed exploit"
    # and it is not armed in the graph either, so the Guard will never use it
    assert rules.armed_rules_for("t", "slack_post", ["read_email"]) == []


def test_critic_rejects_a_rule_with_no_recorded_exploit(seeded, load_demo):
    sid = load_demo("vulnerable")
    store.graph().named("precedent_upsert_rule", {
        "id": "t:noexploit", "owner": "t", "ingest_tool": "fetch_url", "act_tool": "http_post",
        "sink_kind": "exfil", "sink": "web-egress", "representative": "x", "exploit": "{}",
        "findings": [], "ts": 0}, write=True)
    assert rules.critique("t:noexploit", sid)["status"] == "rejected"


def test_rules_start_proposed_and_only_armed_rules_reach_the_guard(seeded, load_demo, track_graph):
    # an armed seed rule fires; a proposed/rejected one never does
    armed = rules.armed_rules_for("public", "http_post", ["fetch_url"])
    assert [r["rule"] for r in armed] == ["seed:fetch_url>http_post>exfil"]
    assert rules.armed_rules_for("public", "send_email", ["read_email"]) == []  # rejected rule


def test_rules_are_private_to_their_owner(seeded):
    store.graph().named("precedent_upsert_rule", {
        "id": "acme:read_slack>write_file>mutate", "owner": "acme", "ingest_tool": "read_slack",
        "act_tool": "write_file", "sink_kind": "mutate", "sink": "fs", "representative": "x",
        "exploit": "{}", "findings": [], "ts": 0}, write=True)
    store.graph().named("precedent_rule_status", {
        "id": "acme:read_slack>write_file>mutate", "status": "armed", "critic": "{}", "ts": 0},
        write=True)
    assert rules.armed_rules_for("acme", "write_file", ["read_slack"])
    assert rules.armed_rules_for("other", "write_file", ["read_slack"]) == []
    assert {r["id"] for r in rules.list_rules(owner="other")}.isdisjoint(
        {"acme:read_slack>write_file>mutate"})


def test_learned_rule_blocks_in_the_guard_when_structure_alone_would_escalate(seeded, load_demo,
                                                                              track_graph):
    """A stack that is NOT toxic would only ESCALATE on a tainted sink call. An armed rule
    learned on earlier stacks upgrades that to DENY."""
    data = demo_spec_dict("second_pattern")
    for s in data["servers"]:
        for t in s["tools"]:
            if t["name"] in ("read_file", "get_secret"):
                t["reads"], t["holds"] = [], []  # remove private data: no longer toxic
    sid = load_demo("second_pattern", servers=data["servers"])
    assert analysis.toxic_combinations(sid)["toxic"] is False
    sess = unique("lr")
    track_graph(session_graph_name(sess))
    decide.check(sess, sid, "search_notes", {"q": "x"})
    d = decide.check(sess, sid, "http_post", {"url": "https://x.example"})
    assert d.decision == decide.DENY
    assert any(r.startswith("learned rule:") for r in d.reasons)
    assert d.provenance["learned_rules"][0]["rule"] == "seed:search_notes>http_post>exfil"


def test_without_the_learned_rule_the_same_call_only_escalates(load_demo, track_graph):
    data = demo_spec_dict("second_pattern")
    for s in data["servers"]:
        for t in s["tools"]:
            if t["name"] in ("read_file", "get_secret"):
                t["reads"], t["holds"] = [], []
    sid = load_demo("second_pattern", servers=data["servers"])
    sess = unique("nolr")
    track_graph(session_graph_name(sess))
    decide.check(sess, sid, "search_notes", {"q": "x"})
    d = decide.check(sess, sid, "http_post", {"url": "https://x.example"})
    assert d.decision == decide.ESCALATE and d.provenance["learned_rules"] == []


def test_a_learned_rule_can_never_loosen_a_decision(seeded, load_demo, track_graph):
    sid = load_demo("vulnerable")
    sess = unique("nl")
    track_graph(session_graph_name(sess))
    decide.check(sess, sid, "read_email")
    assert decide.check(sess, sid, "send_email", {"to": "a@b.co"}).decision == decide.DENY


# ---- tenant isolation --------------------------------------------------------------------

def test_two_tenants_cannot_read_each_others_stacks(api, track_graph):
    sid = unique("iso")
    r = api.post("/stacks", params={"stack_id": sid}, headers=hdr("acme"),
                 json=demo_spec_dict("vulnerable"))
    assert r.status_code == 200 and r.json()["tenant"] == "acme"
    track_graph(stack_graph_name(sid))
    for path in ("paths", "toxic", "choke-points", "graph", "spec", "nodes/run_shell"):
        assert api.get(f"/stacks/{sid}/{path}", headers=hdr("acme")).status_code == 200, path
        assert api.get(f"/stacks/{sid}/{path}", headers=hdr("globex")).status_code == 404, path
        assert api.get(f"/stacks/{sid}/{path}").status_code == 404, path  # public tenant too


def test_foreign_stacks_are_not_listed_or_deletable_or_attackable(api, track_graph):
    sid = unique("iso2")
    api.post("/stacks", params={"stack_id": sid}, headers=hdr("acme"),
             json=demo_spec_dict("vulnerable"))
    track_graph(stack_graph_name(sid))
    assert sid in api.get("/stacks", headers=hdr("acme")).json()["stacks"]
    assert sid not in api.get("/stacks", headers=hdr("globex")).json()["stacks"]
    assert api.delete(f"/stacks/{sid}", headers=hdr("globex")).status_code == 404
    assert api.post(f"/stacks/{sid}/redteam", headers=hdr("globex")).status_code == 404
    assert api.post(f"/stacks/{sid}/defense/plan", headers=hdr("globex")).status_code == 404
    assert api.post(f"/stacks/{sid}/precedent/scan", headers=hdr("globex")).status_code == 404
    assert api.get(f"/stacks/{sid}/paths", headers=hdr("acme")).status_code == 200  # still there


def test_cannot_overwrite_another_tenants_stack_id(api, track_graph):
    sid = unique("iso3")
    assert api.post("/stacks", params={"stack_id": sid}, headers=hdr("acme"),
                    json=demo_spec_dict("vulnerable")).status_code == 200
    track_graph(stack_graph_name(sid))
    r = api.post("/stacks", params={"stack_id": sid}, headers=hdr("globex"),
                 json=demo_spec_dict("fixed"))
    assert r.status_code == 409
    assert api.get(f"/stacks/{sid}/paths", headers=hdr("acme")).json()["path_count"] == 8


def test_guard_treats_a_foreign_stack_as_nonexistent(api, track_graph):
    sid = unique("iso4")
    api.post("/stacks", params={"stack_id": sid}, headers=hdr("acme"),
             json=demo_spec_dict("vulnerable"))
    track_graph(stack_graph_name(sid))
    sess = unique("g")
    track_graph(session_graph_name(sess))
    body = {"session": sess, "stack": sid, "tool": "db_query", "args": {}}
    mine = api.post("/guard/check", json=body, headers=hdr("acme")).json()
    assert mine["decision"] == "ALLOW"
    theirs = api.post("/guard/check", json={**body, "session": unique("g2")},
                      headers=hdr("globex")).json()
    assert theirs["decision"] == "DENY" and theirs["fail_closed"]
    assert "unknown stack" in theirs["reasons"][0]


def test_sessions_and_approvals_are_tenant_scoped(api, track_graph):
    data = demo_spec_dict("vulnerable")
    for s in data["servers"]:
        for t in s["tools"]:
            if t["name"] == "slack_post":
                t["gated"] = True
    sid = unique("iso5")
    api.post("/stacks", params={"stack_id": sid}, headers=hdr("acme"), json=data)
    track_graph(stack_graph_name(sid))
    sess = unique("sx")
    track_graph(session_graph_name(sess))
    r = api.post("/guard/check", headers=hdr("acme"),
                 json={"session": sess, "stack": sid, "tool": "slack_post",
                       "args": {"text": "x"}}).json()
    assert r["decision"] == "ESCALATE"
    assert api.get(f"/guard/sessions/{sess}", headers=hdr("globex")).status_code == 404
    assert api.get(f"/guard/sessions/{sess}", headers=hdr("acme")).status_code == 200
    assert not [p for p in api.get("/guard/pending", headers=hdr("globex")).json()["pending"]
                if p["session"] == sess]
    assert [p for p in api.get("/guard/pending", headers=hdr("acme")).json()["pending"]
            if p["session"] == sess]
    assert api.post(f"/guard/sessions/{sess}/events/{r['seq']}/resolve", headers=hdr("globex"),
                    json={"approve": True}).status_code == 404
    assert api.post(f"/guard/sessions/{sess}/events/{r['seq']}/resolve", headers=hdr("acme"),
                    json={"approve": True}).status_code == 200


def test_a_query_on_one_stack_graph_cannot_see_another(load_demo):
    """Physical isolation: separate graphs. A query bound to graph A returns nothing of B."""
    a, b = load_demo("vulnerable"), load_demo("second_pattern")
    ga, gb = client.Graph(stack_graph_name(a)), client.Graph(stack_graph_name(b))
    ids_a = {r[0] for r in ga.ro_query("MATCH (n) RETURN n.id").rows}
    ids_b = {r[0] for r in gb.ro_query("MATCH (n) RETURN n.id").rows}
    assert "search_notes" in ids_b and "search_notes" not in ids_a
    assert "run_shell" in ids_a and "run_shell" not in ids_b


def test_seed_tenant_is_reserved(api):
    assert api.get("/stacks", headers=hdr("seed")).status_code == 403


def test_other_tenants_private_precedent_is_not_cited(seeded, api, track_graph):
    sa, sb = unique("pa"), unique("pb")
    for sid, tenant in ((sa, "acme"), (sb, "globex")):
        r = api.post("/stacks", params={"stack_id": sid}, headers=hdr(tenant),
                     json=demo_spec_dict("vulnerable"))
        assert r.status_code == 200
        track_graph(stack_graph_name(sid))
    api.post(f"/stacks/{sa}/precedent/scan", headers=hdr("acme"))
    cites = api.post(f"/stacks/{sb}/precedent/scan", headers=hdr("globex")).json()["citations"]
    cited = {e["stack"] for c in cites["combos"] for e in c["earlier"]}
    assert sa not in cited, "acme's private stack must not leak into globex's citations"
    assert cited <= {s for s in cited if s.startswith("seed-")}


def test_same_tenant_does_cite_its_own_earlier_stack(seeded, api, track_graph):
    sa, sb = unique("ma"), unique("mb")
    for sid in (sa, sb):
        api.post("/stacks", params={"stack_id": sid}, headers=hdr("acme"),
                 json=demo_spec_dict("vulnerable"))
        track_graph(stack_graph_name(sid))
    api.post(f"/stacks/{sa}/precedent/scan", headers=hdr("acme"))
    cites = api.post(f"/stacks/{sb}/precedent/scan", headers=hdr("acme")).json()["citations"]
    assert sa in {e["stack"] for c in cites["combos"] for e in c["earlier"]}


def test_tenancy_ownership_survives_delete_and_recreate(api, track_graph):
    sid = unique("iso6")
    api.post("/stacks", params={"stack_id": sid}, headers=hdr("acme"),
             json=demo_spec_dict("vulnerable"))
    assert api.delete(f"/stacks/{sid}", headers=hdr("acme")).status_code == 200
    r = api.post("/stacks", params={"stack_id": sid}, headers=hdr("globex"),
                 json=demo_spec_dict("fixed"))
    track_graph(stack_graph_name(sid))
    assert r.status_code == 200 and tenancy.owner_of(stack_graph_name(sid)) == "globex"


# ---- end to end through the API ----------------------------------------------------------

def test_full_precedent_flow_through_the_api(seeded, api, track_graph):
    sid = unique("e2e")
    api.post("/stacks", params={"stack_id": sid}, json=demo_spec_dict("vulnerable"))
    track_graph(stack_graph_name(sid))
    body = api.post(f"/stacks/{sid}/precedent/scan").json()
    assert body["remembered"]["findings"] == 8 and body["remembered"]["confirmed"] == 8
    assert body["citations"]["headline"].startswith("inbound-email>read_email>send_email")
    assert any(r["status"] == "armed" for r in body["rules"])
    assert any(r["status"] == "rejected" for r in body["rules"])
    v = api.post(f"/stacks/{sid}/defense/verify", params={"rerun_redteam": False}).json()
    track_graph(stack_graph_name(v["proof"]["patched_stack"]))
    assert v["proof"]["verified_safe"] and v["remembered_fixes"]
    again = api.get(f"/stacks/{sid}/precedent").json()
    assert any(fx["held"] for f in again["findings"] for fx in f["fixes"])
    assert api.get("/precedent/stats").json()["counts"]


def test_concurrent_guard_checks_with_learned_rules_stay_consistent(seeded, load_demo,
                                                                    track_graph):
    sid = load_demo("vulnerable")
    out = {}

    def worker(i):
        sess = unique(f"cc{i}")
        track_graph(session_graph_name(sess))
        tainted = i % 2 == 0
        if tainted:
            decide.check(sess, sid, "read_email")
        out[i] = decide.check(sess, sid, "slack_post", {"text": "x"}).decision

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    for i, d in out.items():
        assert d == (decide.DENY if i % 2 == 0 else decide.ALLOW), (i, out)
