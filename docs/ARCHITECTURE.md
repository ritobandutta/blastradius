# Architecture, in plain language

This explains every major decision so one person can defend the whole system. Each section says
what we chose, why, and what it costs.

## 1. The core idea

An AI agent is dangerous when three things meet: it **reads content an attacker can influence**,
it **can reach something valuable**, and it **can send data or run commands somewhere harmful**.
We do not try to detect a malicious *sentence*. We model the agent's *capabilities* as a graph
and ask a structural question: is there a path from untrusted input to a dangerous sink?

Why a graph: the question is a traversal. "Which sequences of tools let attacker-controlled
text end up in a shell?" is awkward in tables and natural in Cypher. And "no path exists" is a
statement a traversal can actually prove by returning zero rows.

## 2. FalkorDB is the system, not a cache

Every path finding, Guard decision and precedent lookup is a Cypher query. We keep no copy of
a graph in memory. Three things enforce that:

- One access layer (`graph/client.py`). All Cypher goes through it.
- A test (`test_the_graph_is_load_bearing...`) checks the Guard code does not use networkx and
  holds no graph in module state.
- A kill-test stops FalkorDB (points the app at a dead port) and requires: the Guard returns
  DENY, the API returns 503, the MCP server returns an error, the proxy denies every call.

Cost: every decision is a database round trip (about 4 ms measured). We accepted that to keep
the graph honest.

## 3. Three kinds of graph, and why separate graphs

FalkorDB lets one instance hold many isolated graphs. We use that:

- `stack:<id>` per scanned stack. A query sent to one graph cannot name a node in another.
- `session:<id>` per run-time session. Sessions never interfere, and concurrent sessions are
  tested (identical decisions across 16 parallel sessions).
- `precedent` shared. This is the memory that spans stacks.

A fourth tiny graph `tenants` records who owns which stack graph (section 10).

## 4. The stack graph

Nodes: Agent, MCPServer, Tool, DataSource, Secret, Permission, Sink. The two attributes that
matter are `DataSource.trust` (is the content attacker-influenceable?) and `Sink.kind`
(exfil, mutate, exec). An annotation table (`parser/rules.yaml`, editable) fills in what the
author did not state, such as "`read_email` reads untrusted inbound mail". Whatever it cannot
classify is guessed by keyword and marked **suggested**, and the API reports it as needing
confirmation. An LLM may *propose* a classification, but it is stored as a suggestion and is
skipped entirely in mock mode.

Tool-description poisoning (a malicious MCP server hiding instructions in its tool descriptions)
is modelled by giving that server an untrusted DataSource for its descriptions.

## 5. Finding attack paths

`paths_to_sinks` is one pattern match for `untrusted DataSource -> Tool -> Agent -> Tool -> Sink`.
Both tools may be the same (a fetch tool that reads a poisoned page and can also send a request).
Each path gets a score: sink weight (exec 10, exfil 8, mutate 7) times a secret multiplier
(a 5/5 secret doubles it) times 0.85 if two different tools are needed. The total is the
"open risk". We cross-check the paths against FalkorDB's own `algo.SSpaths`: a test requires
the same (source, sink) pairs from both. Choke points combine exact path counts per tool with
`algo.betweenness`.

The score weights are judgment calls, not measurements. They rank paths; they do not predict loss.

## 6. The Guard (deterministic, no LLM)

For each pending tool call the Guard asks FalkorDB four questions: what does this tool read and
reach (`guard_tool_facts`), is untrusted data already in context (`session_taint`), does this
agent hold the toxic combination (`toxic_combinations`), and what do the drift counters say
(`session_drift`). The rules, first match wins:

1. Database unreachable, or tool unknown: **DENY** (fail closed).
2. Lockdown and the tool is not read-only: **DENY**.
3. Tainted context + tool reaches a sink + toxic agent: **DENY**.
4. A secret-like string in the args of a tool that reaches an exfil sink: **DENY**.
5. Tainted context + sink + an armed learned rule matches: **DENY**.
6. Tainted context + sink, not toxic: **ESCALATE** (a human decides).
7. Tool is gated in config: **ESCALATE**.
8. Otherwise **ALLOW**.

The Guard never looks at the text of a tool result. That is the point: a paraphrased,
zero-width-split or base64-encoded injection looks identical to an obvious one, because the
decision rests on the shape of the path. The cost is false positives (section 12).

A call "taints" the session only if it actually ran. A denied call returned no data, so it does
not extend the taint set.

## 7. Trust score and lockdown

A second, weaker layer for drift. The score starts at 100 and drops on a burst of calls,
rapid enumeration, a tool never seen in the baseline, and key-like strings or emails in outbound
arguments. Below a threshold (default 40) the session enters sticky **lockdown**: read-only
tools only. The thresholds are heuristics we chose; they are not tuned on real traffic. The DLP
patterns are deliberately small and generic.

## 8. The approval gate and why a DENY cannot change

Only a person can turn an ESCALATE into an ALLOW. The guarantee is enforced inside the
database: `session_resolve.cypher` matches only an event with `decision = 'ESCALATE' AND
status = 'pending'`. A DENY never matches, so no caller can flip it. We tested this through the
Python API, HTTP, and the Tribunal.

## 9. The Tribunal is advice, structurally

For a pending ESCALATE, a Prosecutor, Defense and Judge argue the call, with the Judge citing earlier
`Ruling` nodes about the same tool. It is advisory by construction: it refuses anything that is
not a pending ESCALATE before calling any LLM, it writes only a `Ruling` to the precedent graph,
and a test asserts it cannot import the approval gate or the Guard (and the Guard cannot import
it). Even a forced "Verdict: ALLOW" leaves the call pending until a human clicks.

## 10. Per-tenant isolation

Physical: a graph per stack and per session. Logical: the `tenants` graph records ownership, and
every route checks it. A foreign stack looks *nonexistent* (404, or a fail-closed DENY from the
Guard), so the API is not an oracle for which names exist. Other tenants' private findings are
never cited. The shared seed corpus is owned by a reserved tenant, `seed`.

What this is not: authentication. `X-Tenant` is a header. A real deployment needs a gateway
that sets it from a verified credential, and ideally per-tenant FalkorDB users.

## 11. The defense graph and proof of absence

Step 1: paths come from FalkorDB. Step 2: the paths become a flow network where each tool is
split into an "ingest" role and an "act" role (so a dual-role tool cannot create a shortcut that
skips the agent). The only cuttable edges are `ingest -> agent` (remove the tool, cost 10),
`agent -> act` (gate it, cost 1) and `act -> sink` (scope its token, cost 3); everything else is
uncuttable. Step 3: networkx finds the min-cut. Step 4: the same network is loaded into a scratch
FalkorDB graph and `algo.maxFlow` must return the same value (max-flow equals min-cut). Both
numbers are shown.

The user can say "this tool must stay ungated" or "must not be removed", and the cut routes around
it (for example, a scoped token instead of a gate).

**Proof of absence** applies the fixes to the stored spec, loads the result as its own graph, and
re-runs `paths_to_sinks`. The "verified safe" badge appears only if that query returns zero rows.
A half-applied plan is correctly reported as not safe (tested). The red-team attacks are also
re-run against the patched config alone, with no Guard, to isolate the patch.

## 12. The red team and the honest comparison

The sandbox agent is **not an LLM**. It is a deterministic, gullible stand-in so results are
reproducible, and every doc says so. Its tools are simulated (a test checks the module imports no
network, subprocess or file-writing library). An attack succeeds only if a canary string reaches a
simulated sink.

Variants: direct, paraphrased, zero-width-split, base64, and tool-description poisoning. The same
attacks run unprotected, behind a keyword/regex filter, and behind the Guard. Every table cell is
computed from a run. The filter is written to be reasonable, not a strawman, but its score depends
on my choices.

We also replay benign sessions to measure false positives, because a firewall that blocks
everything would score perfectly on attacks. The Guard blocks 1 of 5: reading a customer email
and replying to it. That is a genuine cost of a structural check, shown in the UI.

## 13. Precedent and procedural memory

Each scan writes Findings (one per path) into the shared graph, linked to named **Patterns** such
as "indirect injection via email" or "tool description poisoning", tagged with OWASP LLM Top 10
categories. Like a tutoring system that gives each wrong mental model its own node instead of
lumping students by score, a Pattern node lets findings from different stacks be compared.

Citations use the two-hop traversal `Stack -> Finding -> Pattern <- Finding <- Stack`, narrowed by
`combo` (the stack-independent tool combination) to say "exploited in N earlier stacks; the fix that
held was X". A fix is marked `held` only if its proof of absence found zero paths.

**Learned rules.** A confirmed finding is compiled into a rule: "if `ingest_tool` already ran and
the agent calls `act_tool`, deny". A rule starts `proposed`. A deterministic critic must show it
(1) blocks the exploit recorded on the confirmed finding and (2) blocks none of 8 recorded benign
sessions. Then it is `armed`; otherwise `rejected`, with the reason stored. The critic and the
Guard run the same query, so what the critic approves is what fires. Learned rules can only
*tighten* a decision, never loosen it.

We found and fixed one bug here: the first critic replayed the rule's own fields, which made "does
it block the exploit?" true by construction. It now replays the call sequence recorded on the finding.

The seed corpus (five synthetic stacks) goes through the full real pipeline, so its findings,
fixes and rules are produced, not typed in. They are labelled `seeded`.

## 14. Fail loudly

- LLM unavailable or key missing: a visible **MOCK MODE** badge in the UI, CLI and proxy, with the
  reason. A failed live call is reported on the result (`llm_error`), never swallowed.
- FalkorDB down: DENY / 503 / error result, never an empty or canned answer.
- Unknown stack or tool: DENY.
- A never-created session is a 404, not an empty success.

## 15. What is not covered

No real LLM agent was tested; taint is session-wide rather than data-flow precise; tenant isolation
is app-level; the score weights and trust thresholds are unvalidated heuristics; `mcp.json` import
is a guess; live deployment is not done; the live-LLM Tribunal and rewrite variants were not run
end to end against the API.
