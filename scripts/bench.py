"""Measure Guard and path-query latency against the real FalkorDB. Numbers go in the README.

Run: uv run python scripts/bench.py
"""
import json
import statistics as st
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from backend.graph import analysis, schema
from backend.graph.client import Graph, session_graph_name
from backend.guard import decide
from backend.parser.stack_spec import load_spec_file


def pct(xs, p):
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(len(xs) * p))], 2)


spec = load_spec_file("demo/stacks/vulnerable.json")
spec.id = f"bench-{uuid.uuid4().hex[:6]}"
schema.load_stack(spec)

# 1. path query (FalkorDB-reported execution time and round trip)
srv, wall = [], []
for _ in range(200):
    r = analysis.paths_to_sinks(spec.id)
    srv.append(r.run_time_ms); wall.append(r.wall_ms)
out = {"paths_to_sinks": {"runs": 200, "paths": len(r.paths),
       "server_ms": {"p50": pct(srv, .5), "p95": pct(srv, .95), "max": round(max(srv), 2)},
       "round_trip_ms": {"p50": pct(wall, .5), "p95": pct(wall, .95)}}}

# 2. one Guard decision, sequential (tainted -> blocked sink call)
lat = []
for _ in range(60):
    sid = f"b-{uuid.uuid4().hex[:8]}"
    decide.check(sid, spec.id, "read_email", {})
    d = decide.check(sid, spec.id, "send_email", {"to": "a@b.co"})
    assert d.decision == "DENY"
    lat.append(d.latency_ms)
    Graph(session_graph_name(sid)).delete()
out["guard_decision_blocked_call"] = {"runs": 60, "ms": {"p50": pct(lat, .5), "p95": pct(lat, .95)}}

# 3. concurrent sessions: N workers, each its own session, 10 calls each
def worker(i):
    sid = f"c-{i}-{uuid.uuid4().hex[:6]}"
    times, decisions = [], []
    for k in range(10):
        tool = ["read_email", "db_query", "send_email", "slack_post", "read_file"][k % 5]
        d = decide.check(sid, spec.id, tool, {"k": k})
        times.append(d.latency_ms); decisions.append((tool, d.decision))
    Graph(session_graph_name(sid)).delete()
    return times, decisions

for workers in (1, 8, 16):
    t0 = time.perf_counter()
    with ThreadPoolExecutor(workers) as ex:
        results = list(ex.map(worker, range(workers)))
    total = time.perf_counter() - t0
    all_ms = [m for t, _ in results for m in t]
    # every session ran the same script, so every session must have the same decisions
    same = len({tuple(d) for _, d in results}) == 1
    out[f"concurrent_{workers}_sessions"] = {
        "decisions": len(all_ms), "wall_s": round(total, 2),
        "throughput_per_s": round(len(all_ms) / total, 1),
        "ms": {"p50": pct(all_ms, .5), "p95": pct(all_ms, .95)},
        "identical_decisions_across_sessions": same}

schema.delete_stack(spec.id)
print(json.dumps(out, indent=2))
