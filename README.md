# BlastRadius

**A graph-native firewall for AI agents.** It answers one question: *if an attacker controls
any single thing this agent reads, what is the worst it can do, and can we prove it can't?*

Built for the WeMakeDevs x FalkorDB **Graph Hacks: Context for AI Agents** hackathon.

**Tracks entered:** 1. Agents That Act on Connected Data, and 2. Agent Memory and Coordination.

| | |
|---|---|
| What it does | Maps an agent's tools, MCP servers, data sources, secrets and permissions into a FalkorDB graph, finds every path from untrusted input to a dangerous sink, enforces policy at run time, and proves a fix works by re-running the same query and getting zero paths. |
| Where FalkorDB matters | Every path finding, every Guard decision and every precedent lookup is a Cypher query. There is no in-memory copy of any graph. Stop FalkorDB and the Guard denies everything (tested). |
| Live deployment | **Not deployed yet.** `render.yaml` and the hardening are ready; see "Deploying" below. Run it locally with one command in the meantime. |
| Demo script | [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) (under 3 minutes) |
| Design explained | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Every query | [docs/CYPHER.md](docs/CYPHER.md) |

## Run it

Requires Docker. The Anthropic key is optional.

```bash
git clone https://github.com/ritobandutta/blastradius && cd blastradius
docker compose up --build        # FalkorDB + the app
# open http://localhost:8010     (FalkorDB Browser: http://localhost:3010)
```

Without an LLM key everything runs, and the UI, CLI and proxy show a **MOCK MODE** badge. Only
the optional LLM features (red-team rewrite variant, annotation assist, the Tribunal's wording)
are affected. The graph analysis and the Guard never use an LLM. To turn the live path on, put
`OPENROUTER_API_KEY` in `.env` (OpenRouter has free `:free` models; default
`nvidia/nemotron-3-super-120b-a12b:free`) or set `ANTHROPIC_API_KEY`. On a public deployment only
free OpenRouter models may run, within a daily request budget (default 35).

Ports are 6390 (FalkorDB), 8010 (app) and 3010 (FalkorDB Browser) because 6379/8000/3000 are
commonly taken.

Development without Docker for the app:

```bash
docker compose up -d falkordb
uv sync && uv run uvicorn backend.api.main:app --port 8010
cd frontend && npm install && npm run dev        # http://localhost:5173
uv run pytest                                    # 210 tests, real FalkorDB
```

CLI:

```bash
uv run python -m backend.cli scan    demo/stacks/vulnerable.json
uv run python -m backend.cli redteam demo/stacks/vulnerable.json
uv run python -m backend.cli fix     demo/stacks/vulnerable.json -o out/
uv run python -m backend.cli diff    demo/stacks/fixed.json demo/stacks/vulnerable.json --fail-on-regression
```

## Graph data model

Three kinds of graph, all in one FalkorDB instance:

**Stack graph** `stack:<id>`: one per scanned agent stack.

```
(MCPServer)-[:EXPOSES]->(Tool {side_effect: read|write|destructive|exec|network_out})
(DataSource {trust: untrusted|internal|trusted})-[:READ_BY]->(Tool)
(Tool)-[:RETURNS_TO]->(Agent)
(Agent)-[:CAN_INVOKE {gated}]->(Tool)
(Tool)-[:REACHES {scoped}]->(Sink {kind: exfil|mutate|exec})
(Tool)-[:HOLDS]->(Secret | Permission)
```

An attack path is `untrusted DataSource -> Tool -> Agent -> Tool -> Sink`. `gated` (a human must
confirm) and `scoped` (the token can no longer reach that sink) are the two fix levers; path
queries skip edges that have either.

**Session graph** `session:<id>`: one per run-time session, written on every step.

```
(Session {score, lockdown})   (Event {seq, tool, args_hash, tainted, decision, executed, status})
(Event)-[:NEXT]->(Event)      (Event)-[:DERIVED_FROM]->(Event)
```

**Precedent graph** `precedent`: shared, persistent memory.

```
(Stack)-[:HAS]->(Finding)-[:INSTANCE_OF]->(Pattern {owasp})
(Finding)-[:FIXED_BY {held}]->(Fix)
(Rule)-[:DERIVED_FROM]->(Finding)
(Ruling)-[:CITES]->(Ruling)
```

Plus a small `tenants` graph, `(Tenant)-[:OWNS]->(GraphRef)`, for isolation.

## The Cypher and algorithms we rely on

All 44 queries live in `backend/graph/queries/*.cypher` and are catalogued in
[docs/CYPHER.md](docs/CYPHER.md); a test fails if one is missing from that catalogue. The ones
that carry the product:

| What | How |
|---|---|
| Attack paths | Pattern match `(ds)-[:READ_BY]->(t1)-[:RETURNS_TO]->(a)-[i:CAN_INVOKE]->(t2)-[r:REACHES]->(s)` with `WHERE NOT i.gated AND NOT r.scoped` (`paths_to_sinks`) |
| Cross-check of those paths | `algo.SSpaths` from each untrusted source; a test requires the same (source, sink) pairs |
| Choke points | Path counts per tool (`choke_points`) plus **`algo.betweenness`** |
| Toxic combination | Chained `OPTIONAL MATCH` for untrusted ingest + private data/secret + exfil egress |
| Taint check | `session_taint` over the session graph |
| Min-cut cross-check | The path subgraph is loaded into a scratch graph and **`algo.maxFlow`** must equal the networkx cut |
| Precedent | Two-hop traversal `Stack -> Finding -> Pattern <- Finding <- Stack`, then `FIXED_BY {held: true}` |
| Learned rules | `precedent_rules_matching`: the Guard and the critic run this exact query |

Things that did **not** work on the real server and are not used: `shortestPath` in `MATCH`,
multi-type `algo.maxFlow`, `algo.BFS` for our shape. These were found by
[scripts/spike_cypher.py](scripts/spike_cypher.py) and are recorded in `docs/CYPHER.md`.

## What it does, mapped to the tracks

**Track 1: agents that act on connected data.** The Guard is an agent-facing decision-maker
driven by graph results: tainted context plus a sink the agent can reach, in a stack that holds
the lethal trifecta, is a DENY, derived by traversal rather than by reading text. Each decision
returns the Cypher facts behind it. BlastRadius also runs as an MCP server
(`python -m backend.mcp_server`) so an agent can query its own attack surface.

**Track 2: memory and coordination.**
Episodic: a session graph per run. Semantic: the precedent graph of stacks, findings and
patterns. Procedural: learned Guard rules, armed only after a critic checks them. Separate
memory per tenant: a graph per stack and per session.

## Measured results

From `scripts/bench.py` and the red team, on a laptop, with the real database. Reproduce them.

| Measurement | Result |
|---|---|
| `paths_to_sinks` on the demo stack (8 paths) | 0.27 ms p50, 0.9 ms p95 server-side (200 runs); 0.62 ms p50 round trip |
| One Guard decision (a blocked call) | 3.2 ms p50, 7.7 ms p95 (60 runs, sequential, local database) |
| 8 concurrent sessions | ~1,050 decisions/s, 6.6 ms p50, 14.6 ms p95; decisions identical across sessions |
| 16 concurrent sessions | ~1,200 decisions/s, 12.6 ms p50, 18.6 ms p95; decisions identical across sessions |
| Attacks that complete with no defence | 20 of 20 |
| Naive keyword/regex filter | stops 4 of 20 (only the "ignore previous instructions" variant) |
| The Guard | stops 20 of 20 |
| Guard false positives on 5 benign sessions | **1 of 5** (see limits) |
| After the min-cut patch | 0 paths, and 0 of 20 attacks complete against the patched config alone |

These are **local** numbers (database on the same machine). Against FalkorDB Cloud from a laptop
the round trip was about 290 ms per query while the database itself spent 0.55 ms, so a hosted
deployment is dominated by network distance. A Guard decision needs 7 to 9 queries; they were
grouped so independent ones run in parallel (simulated 30 ms round trip: about 300 ms before,
about 150 ms after). Figures come from one process and describe this setup, not a capacity claim.

## Deploying

The app runs as one container (`Dockerfile`) against any FalkorDB. For a public, unauthenticated
demo set `PUBLIC_DEMO=true`, which:

- forces **MOCK MODE** so visitors cannot spend API credits,
- blocks the seed-reset and stack-delete routes, caps the number of stacks, and rate-limits
  requests per client (tighter on the expensive routes),
- deletes stacks and sessions older than an hour (the shared `precedent` graph is never touched),
- seeds the precedent memory at startup and re-seeds if the database was wiped.

This limits damage; it is **not authentication**. `render.yaml` describes a free Render web
service; the database is FalkorDB Cloud's free tier, configured with `FALKORDB_HOST`,
`FALKORDB_PORT`, `FALKORDB_USERNAME` and `FALKORDB_PASSWORD` as secrets. `/healthz` is liveness
only; `/health` runs a real query and is what `keepalive.yml` pings so the free tiers do not idle out.
FalkorDB Cloud's free tier has **no TLS**, so the password crosses the internet in plaintext;
use a password that is used nowhere else. It also has no backups, which is why the app re-seeds.

## Honest limits

- **The toy agent is not an LLM.** It is a deterministic stand-in that follows instructions
  in what it reads, so results are reproducible. The Guard's result holds regardless of the
  agent because it never reads text, but the keyword filter's 4/20 depends on *my* filter and
  *my* variants. A different filter would score differently. We did not test against a real LLM agent.
- **The Guard has a real false-positive cost.** "Read a customer email, then reply to it" is the
  exact shape of an attack path, so it is stopped unless a human approves. The comparison panel
  reports this instead of hiding it.
- **Taint is session-wide, not data-flow precise.** Once untrusted data is in context, the Guard
  does not know which later call actually used it.
- **Tenant isolation is application-level.** `X-Tenant` is identification, not authentication,
  and we did not configure FalkorDB-level ACLs. Put a gateway in front for real use.
- **Annotation is best effort.** `mcp.json` files do not list tools, so tools are inferred
  from names and flagged `suggested` for a human to confirm.
- **The precedent corpus is synthetic.** Five seeded stacks (`demo/seed_stacks`), labelled
  `seeded` in the UI. They are built by the real pipeline, not typed in, but they are not real incidents.
- **Live-LLM paths were each run once, not soaked.** The Tribunal, the LLM-written red-team
  variant and the annotation assist ran end to end against a free OpenRouter model (output was
  sensible, and the Tribunal left the call pending). Free models rate-limit and come and go: in
  testing several answered 429 and one auto-router served an unusable model, so the default was
  chosen by trial. Failures are reported as MOCK MODE with the error, never hidden.
- **No live deployment yet**, and when deployed the free tiers sleep when idle, the database is
  unencrypted in transit, and queries cross a network instead of a loopback.

## AI assistance disclosure

This project was built with Claude Code (Claude Sonnet 5.5) as a coding assistant, during
the hackathon window. The design brief and decisions are the author's; the assistant wrote
code, tests and docs under direction. Everything is covered by tests that run against a real
FalkorDB, and `docs/ARCHITECTURE.md` explains each decision in plain language.

Data is synthetic only. "Attacks" are harmless canary strings against simulated tools that
touch no network, subprocess or real file (a test checks the sandbox imports none of those).

## Layout

```
backend/   graph/ (client, schema, queries/*.cypher, analysis, tenancy)  parser/  guard/
           redteam/  defense/  precedent/  llm/  api/  cli.py  mcp_server.py
demo/      toy_agent/ (simulated tools)  stacks/ (vulnerable, fixed, second_pattern)
           seed_stacks/  benign_sessions/
frontend/  Vite + React + Cytoscape      tests/  210 tests      docs/  design + demo
```
