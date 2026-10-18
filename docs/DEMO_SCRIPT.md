# Demo script (under 3 minutes)

Setup before recording: `docker compose up --build`, open http://localhost:8010, click
**Build seed corpus** once in the Precedent tab (about 0.2 s) so step 5 has history.
Keep the browser at about 1500 px wide. Leave the MOCK MODE badge visible if no key is set; it is
honest and the demo does not depend on the LLM.

## 1. The red path (0:00 - 0:30)

Click **Load vulnerable**.

> "This is a support agent. It reads customer email and web pages, and it holds a customer
> database and a shell. BlastRadius turned its tools into a graph in FalkorDB and asked one
> Cypher question: is there a path from something an attacker controls to something dangerous?"

Point at the pulsing red path `inbound-email → read_email → support-agent → run_shell → host-shell`,
the **8 attack paths**, **open risk 76**, and the **2.6 ms** query time. Click `run_shell` to show
the "why" panel. Point at the **TOXIC COMBINATION** badge.

## 2. Confirm it in the sandbox (0:30 - 1:00)

**Red team** tab, **Run red team**.

> "Don't take the graph's word for it. A simulated agent, no network, no real shell, gets harmless
> canary strings planted in what it reads. Success means the canary reached a sink."

Show the table: 20 of 20 attacks complete with no defence.

## 3. Keyword filter vs the Guard (1:00 - 1:50)

Same table, the two right-hand columns.

> "A keyword filter stops 4 of 20: only the 'ignore previous instructions' version. Paraphrase it,
> split the words with zero-width characters, hide it in base64, or put it in a tool description,
> and it misses all of them. The Guard stops all 20, because it never reads the text. It sees the
> path."

Then the **Guard** tab: click `read_email` (ALLOW, tainted), then `send_email`. Show **DENY**, the
structural reason, "derived from #1", the trust score, and the latency.

> "And it isn't free. The panel above shows the cost: one of five benign sessions, reading an
> email and replying to it, is blocked too. That is what the approval gate is for."

## 4. Fix it and prove it (1:50 - 2:30)

**Defense** tab, **Plan minimum cut and prove it**.

> "The cheapest set of fixes that cuts every path: four confirmation gates, cost 4. A min-cut in
> networkx, and FalkorDB's own max-flow returns the same number. Now apply it and re-run the exact
> same query on the patched graph."

Point at **VERIFIED SAFE · 0 paths found, ~1 ms** and "0 of 20 attacks complete against the patched
config". Mention the generated patched config and PR description below.

## 5. Memory (2:30 - 3:00)

**Precedent** tab, **Scan into precedent memory**.

> "Now the memory. This stack's tool combination was exploited in two earlier stacks, and the fix
> that held there was a confirmation gate. That came from a two-hop traversal across stacks.
> Those earlier stacks are synthetic seed data, labelled as such. Below, the learned rules: armed
> ones passed a critic that replays the exploit and eight benign sessions; this one was rejected
> because it would have blocked legitimate work."

## If something goes wrong on camera

- Empty stack list: click **Load vulnerable** again.
- Precedent shows no history: click **Build seed corpus**, then scan again.
- A request fails: the red error banner shows the server's reason. Nothing fails silently.
