import { useEffect, useMemo, useState } from "react";
import { api, setTenant } from "./api";
import GraphView from "./GraphView";
import HeroGraph from "./HeroGraph";
import { DefensePanel, GuardPanel, PrecedentPanel, RedTeamPanel } from "./panels";
import { Arrow, Bar, Btn, Card, CardHead, Chip, Empty, Err, Logo, Metric, MockChip, SectionHead, fmt, useAction } from "./ui";

const TABS = ["Guard", "Red team", "Defense", "Precedent", "Node"];
const NAV = [["Overview", "#overview"], ["Graph", "#graph"], ["Analysis", "#analysis"], ["How it works", "#how"]];
const REPO = "https://github.com/ritobandutta/blastradius";
const KIND_LABEL = { exec: "EXEC", exfil: "EXFIL", mutate: "MUTATE" };

export default function App() {
  const [health, setHealth] = useState(null);
  const [demos, setDemos] = useState([]);
  const [stacks, setStacks] = useState([]);
  const [stack, setStack] = useState("");
  const [tenant, setT] = useState("public");
  const [graph, setGraph] = useState(null);
  const [report, setReport] = useState(null);
  const [toxic, setToxic] = useState(null);
  const [choke, setChoke] = useState(null);
  const [pathIdx, setPathIdx] = useState(0);
  const [node, setNode] = useState(null);
  const [nodeInfo, setNodeInfo] = useState(null);
  const [tab, setTab] = useState("Guard");
  const [menu, setMenu] = useState(false);
  const [solid, setSolid] = useState(false);
  const { busy, error, run } = useAction();

  const refreshStacks = () => api("/stacks").then((r) => setStacks(r.stacks));
  useEffect(() => {
    api("/health").then(setHealth).catch((e) => setHealth({ error: e.message }));
    api("/demo/stacks").then((r) => setDemos(r.demos)).catch(() => {});
    const onScroll = () => setSolid(window.scrollY > 24);
    onScroll(); window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);
  useEffect(() => { setTenant(tenant); setStack(""); refreshStacks().catch(() => {}); }, [tenant]);

  const load = (id) => run(async () => {
    const [g, p, t, c] = await Promise.all([api(`/stacks/${id}/graph`), api(`/stacks/${id}/paths`),
      api(`/stacks/${id}/toxic`), api(`/stacks/${id}/choke-points`)]);
    setStack(id); setGraph(g); setReport(p); setToxic(t); setChoke(c); setPathIdx(0); setNode(null); setNodeInfo(null);
  });
  const loadDemo = (name) => run(async () => {
    const r = await api(`/demo/stacks/${name}/load`, { method: "POST" });
    await refreshStacks(); await load(r.stack);
    document.getElementById("graph")?.scrollIntoView({ behavior: "smooth" });
  });
  const upload = (file) => file && run(async () => {
    const body = JSON.parse(await file.text());
    const r = await api("/stacks", { method: "POST", body,
      params: { stack_id: file.name.replace(/\.json$/, "").replace(/[^A-Za-z0-9_.-]/g, "-") } });
    await refreshStacks(); await load(r.stack);
  });
  const clickNode = (id) => { setNode(id); setTab("Node"); api(`/stacks/${stack}/nodes/${id}`).then(setNodeInfo).catch(() => setNodeInfo(null)); };

  const paths = report?.paths || [];
  const active = paths[pathIdx] || null;
  const maxScore = Math.max(1, ...paths.map((p) => p.score));
  const tools = useMemo(() => (graph?.nodes || []).filter((n) => n.label === "Tool").map((n) => n.id), [graph]);
  const toxicAgent = toxic?.agents?.[0];
  const topChoke = choke?.choke_points?.filter((c) => c.paths_through)[0];
  const safe = report && report.path_count === 0;
  const go = (href) => { setMenu(false); document.querySelector(href)?.scrollIntoView({ behavior: "smooth" }); };
  const firstDemo = demos.find((d) => d.name === "vulnerable")?.name || demos[0]?.name;

  return (
    <>
      {/* ------------------------------------------------ header */}
      <header className={`header ${solid ? "solid" : ""}`}>
        <a className="brand" href="#overview" onClick={(e) => { e.preventDefault(); go("#overview"); }}><Logo /> BlastRadius</a>
        <nav className="nav" aria-label="Sections">
          {NAV.map(([l, h]) => <a key={h} href={h} onClick={(e) => { e.preventDefault(); go(h); }}>{l}</a>)}
        </nav>
        <div className="right">
          {health?.llm && <span className="hide-m"><MockChip llm={health.llm} /></span>}
          {health?.falkordb_ping_ms !== undefined && <span className="hide-m"><Chip tone="pass">FALKORDB {fmt(health.falkordb_ping_ms)} MS</Chip></span>}
          {health?.error && <Chip tone="fail">API DOWN</Chip>}
          <a className="btn-square primary hide-m" href={REPO} target="_blank" rel="noreferrer">Source <Arrow /></a>
        </div>
        <button className="burger" aria-label="Open menu" aria-expanded={menu} onClick={() => setMenu(true)}>MENU</button>
      </header>
      {menu && (
        <div className="mobile-menu" role="dialog" aria-modal="true" aria-label="Menu">
          <div className="top"><span className="brand"><Logo /> BlastRadius</span>
            <button className="burger" style={{ display: "block" }} onClick={() => setMenu(false)}>CLOSE</button></div>
          {NAV.map(([l, h]) => <a key={h} href={h} onClick={(e) => { e.preventDefault(); go(h); }}>{l}</a>)}
          <a href={REPO} target="_blank" rel="noreferrer">Source ↗</a>
        </div>)}

      {/* ------------------------------------------------ hero */}
      <main>
        <section className="hero" id="overview">
          <HeroGraph />
          <div className="hero-inner">
            <div className="chips"><Chip tone="active">BUILT ON FALKORDB</Chip><Chip tone="warn">TRACKS 1 + 2</Chip></div>
            <h1 className="headline-fluid">If an attacker controls one thing your agent reads, what can it do?</h1>
            <p className="hero-sub">BlastRadius maps an agent's tools, data sources and secrets into a FalkorDB graph, finds every path from
              untrusted input to a dangerous action, blocks risky calls without reading the text, and proves a fix by returning zero paths.</p>
            <div className="hero-cta">
              <Btn variant="primary" size="lg" arrow disabled={busy || !firstDemo} onClick={() => firstDemo && loadDemo(firstDemo)}>
                {busy ? "Loading…" : "Scan the demo agent"}</Btn>
              <Btn variant="ghost" size="lg" onClick={() => go("#how")}>How it works</Btn>
            </div>
          </div>
          <div className="hero-stat">
            <span className="big">{report ? report.path_count : "8"}</span>
            <span className="small mono">{report ? `attack paths in ${stack}` : "attack paths in the demo support agent"}</span>
          </div>
        </section>

        {/* ------------------------------------------------ graph + paths */}
        <div className="wrap">
          <section className="section" id="graph">
            <SectionHead index="01" eyebrow="Attack surface" title="Every path from untrusted input to a dangerous action."
              sub="Each answer is a Cypher query against FalkorDB, returned with the exact path and how long the query took." />
            <div className="loadbar">
              <label>stack
                <select value={stack} onChange={(e) => e.target.value && load(e.target.value)} aria-label="Stack">
                  <option value="">{stacks.length ? "choose a stack…" : "none loaded"}</option>
                  {stacks.map((s) => <option key={s} value={s}>{s}</option>)}
                </select></label>
              {demos.map((d) => <Btn key={d.name} variant="ghost" size="sm" title={d.blurb} onClick={() => loadDemo(d.name)}>{d.name}</Btn>)}
              <span className="grow" />
              <label>upload spec or mcp.json<input type="file" accept=".json" onChange={(e) => upload(e.target.files[0])} /></label>
              <label>tenant<input style={{ width: 90 }} value={tenant} onChange={(e) => setT(e.target.value.trim() || "public")} /></label>
            </div>
            <Err error={error} />

            <div className="metrics" aria-live="polite">
              <Metric label="Attack paths" value={report ? report.path_count : "—"} sub={report ? `across ${tools.length} tools` : "load a stack"} />
              <Metric label="Open risk" value={report ? fmt(report.open_risk) : "—"} sub="sum of weighted path scores" tone={report && !safe ? "" : undefined} />
              <Metric label="Query time" value={report ? fmt(report.run_time_ms) : "—"} unit="ms" sub="FalkorDB execution time, paths_to_sinks" />
              <Metric label="Toxic combination" value={toxicAgent ? (toxicAgent.toxic ? "YES" : "NO") : "—"}
                sub={toxicAgent?.toxic ? "untrusted ingest + private data + egress" : toxicAgent ? "no lethal trifecta" : "load a stack"}
                tone={toxicAgent && !toxicAgent.toxic ? "pass" : undefined} />
            </div>

            <div className="grid2" style={{ gridTemplateColumns: "minmax(0,1.15fr) minmax(0,1fr)" }}>
              <Card className="graph-card">
                <CardHead title="Capability graph" sub={stack || "no stack loaded"}>
                  {safe && <Chip tone="pass">0 PATHS · VERIFIED SAFE</Chip>}
                  {report && !safe && <Chip tone="fail">{report.path_count} OPEN</Chip>}
                  {topChoke && <Chip tone="warn">CHOKE POINT: {topChoke.id}</Chip>}
                </CardHead>
                <div className="graph-stage">
                  {graph ? <GraphView graph={graph} activePath={active} onNode={clickNode} selected={node} />
                    : <Empty action={firstDemo && <Btn variant="primary" size="sm" arrow onClick={() => loadDemo(firstDemo)}>Load the demo</Btn>}>
                        Load a stack to see its capability graph.</Empty>}
                </div>
                <div className="legend">
                  <span><i style={{ background: "#ededed" }} />untrusted source</span>
                  <span><i style={{ background: "#999" }} />internal source</span>
                  <span><i style={{ background: "#fff", transform: "rotate(45deg) scale(.8)" }} />sink (size = severity)</span>
                  <span><i style={{ background: "#52a8ff" }} />active path</span>
                  <span><i style={{ background: "#62c073" }} />gated / scoped</span>
                </div>
              </Card>

              <Card>
                <CardHead title="Attack paths" sub="ranked by blast-radius score">
                  {toxicAgent?.toxic && <Chip tone="fail">TOXIC</Chip>}</CardHead>
                {!report ? <Empty>Paths appear here once a stack is loaded.</Empty>
                  : safe ? <div className="card-body"><div className="note pass">Zero paths. The traversal ran in {fmt(report.run_time_ms)} ms and found nothing.</div></div>
                  : (
                    <div style={{ maxHeight: 520, overflow: "auto" }}>
                      <table>
                        <thead><tr><th>Sink</th><th>Path</th><th className="num">Score</th></tr></thead>
                        <tbody>
                          {paths.map((p, i) => (
                            <tr key={p.id} className={`click path-row ${i === pathIdx ? "on" : ""}`} onClick={() => setPathIdx(i)}>
                              <td><Chip tone={i === pathIdx ? "active" : p.sink_kind === "exec" ? "fail" : "warn"}>{KIND_LABEL[p.sink_kind] || p.sink_kind}</Chip></td>
                              <td className="nodes">{p.nodes.join(" → ")}
                                <Bar width={(p.score / maxScore) * 100} active={i === pathIdx} /></td>
                              <td className="num">{fmt(p.score)}</td>
                            </tr>))}
                        </tbody>
                      </table>
                    </div>)}
              </Card>
            </div>
          </section>

          {/* ------------------------------------------------ analysis */}
          <section className="section" id="analysis">
            <SectionHead index="02" eyebrow="Analysis" title="Guard it, attack it, fix it, remember it."
              sub="Four tools over the same graph. Every number on this page is measured on the loaded stack." />
            <Card>
              <div className="tabs" role="tablist">
                {TABS.map((t) => <button key={t} role="tab" aria-selected={tab === t} className={`tab ${tab === t ? "on" : ""}`} onClick={() => setTab(t)}>{t}</button>)}
              </div>
              {!stack && tab !== "Precedent" && <Empty action={firstDemo && <Btn variant="primary" size="sm" arrow onClick={() => loadDemo(firstDemo)}>Load the demo stack</Btn>}>
                Load a stack first.</Empty>}
              {tab === "Guard" && stack && <GuardPanel stack={stack} tools={tools} />}
              {tab === "Red team" && <RedTeamPanel stack={stack} />}
              {tab === "Defense" && <DefensePanel stack={stack} onPatched={refreshStacks} onPaths={(id) => { load(id); document.getElementById("graph")?.scrollIntoView({ behavior: "smooth" }); }} />}
              {tab === "Precedent" && <PrecedentPanel stack={stack} tenant={tenant} />}
              {tab === "Node" && stack && (nodeInfo ? (
                <div className="panel stack">
                  <div className="row"><Chip tone="warn">{nodeInfo.label}</Chip><b className="mono">{nodeInfo.id}</b></div>
                  <p className="mono small muted" style={{ margin: 0 }}>on {nodeInfo.on_paths.length} attack path(s); open risk through it {fmt(nodeInfo.open_risk_through)}</p>
                  <pre>{JSON.stringify(nodeInfo.props, null, 2)}</pre>
                  <table><thead><tr><th></th><th>Edge</th><th>Node</th><th>Type</th></tr></thead>
                    <tbody>{nodeInfo.edges.map((e, i) => (<tr key={i}><td>{e.outgoing ? "→" : "←"}</td><td>{e.type}</td><td>{e.other}</td><td className="muted">{e.other_label}</td></tr>))}</tbody></table>
                </div>) : <Empty>Click a node in the graph to see why it is there.</Empty>)}
            </Card>
          </section>

          {/* ------------------------------------------------ bento */}
          <section className="section" id="how">
            <SectionHead index="03" eyebrow="How it works" title="A graph that decides, not a filter that reads."
              sub="The Guard never looks at the text of a tool result. A paraphrased injection and an obvious one produce the same path." />
            <div className="grid3">
              <Card>
                <CardHead title="Guard decisions" sub="deterministic · no LLM" />
                <div className="card-body">
                  {[["read_email", "ALLOW", "pass", "taints the session"], ["db_query", "ALLOW", "pass", "reaches no sink"],
                    ["send_email", "DENY", "fail", "tainted + toxic agent"], ["slack_post", "ESCALATE", "warn", "gated: human decides"]].map(([t, d, tone, why]) => (
                    <div className="status-row" key={t}><span>{t}<br /><span className="muted">{why}</span></span><Chip tone={tone}>{d}</Chip><span /></div>))}
                  <p className="muted small mono" style={{ marginBottom: 0 }}>Illustrative sequence. Run it live in Analysis → Guard.</p>
                </div>
              </Card>
              <Card>
                <CardHead title="Attacks stopped" sub="measured on the test agent: 20 attacks" />
                <div className="card-body">
                  {[["direct", 4, 4], ["paraphrased", 0, 4], ["zero-width", 0, 4], ["base64", 0, 4], ["tool description", 0, 4]].map(([n, naive, guard]) => (
                    <div key={n}><div className="hbar"><span>{n}</span><div className="track"><div className="fill" style={{ width: `${(naive / 4) * 100}%` }} /></div><span>filter {naive}/4</span></div>
                      <div className="hbar"><span /><div className="track"><div className="fill hi" style={{ width: `${(guard / 4) * 100}%` }} /></div><span>guard {guard}/4</span></div></div>))}
                  <p className="muted small mono" style={{ marginBottom: 0 }}>Gray: keyword filter, 4 of 20. Blue: Guard, 20 of 20. Re-run live in Analysis → Red team.</p>
                </div>
              </Card>
              <Card>
                <CardHead title="Proof of absence" sub="same query, patched graph" />
                <div className="card-body">
                  <div className="diff">
                    <div className="mod">~ CAN_INVOKE support-agent → run_shell</div>
                    <div className="add">+ gated: true</div>
                    <div className="mod">~ CAN_INVOKE support-agent → send_email</div>
                    <div className="add">+ gated: true</div>
                    <div>  … 2 more gates</div>
                    <div className="add">paths_to_sinks → 0 rows</div>
                  </div>
                  <p className="muted small mono" style={{ marginBottom: 0 }}>FalkorDB <b>algo.maxFlow</b> returns the same value as the min-cut: 4.</p>
                </div>
              </Card>
            </div>
            <div className="metrics" style={{ marginTop: 12 }}>
              <Metric label="Stack graph query" value="0.22" unit="ms" sub="paths_to_sinks p50, local FalkorDB, 8 paths" />
              <Metric label="Guard decision" value="3.2" unit="ms" sub="p50 on a local database; ~125-155 ms on the hosted demo" />
              <Metric label="Attacks stopped" value="20" unit="/ 20" sub="keyword filter: 4 / 20" />
              <Metric label="False positives" value="1" unit="/ 5" sub="a reply after reading email is blocked" />
            </div>
          </section>
        </div>
      </main>

      <footer className="footer">
        <div>BlastRadius · built on FalkorDB for the WeMakeDevs × FalkorDB hackathon.<br />
          Synthetic data and harmless canary strings only. Built with Claude Code as a coding assistant.</div>
        <div><a href={REPO} target="_blank" rel="noreferrer">Source</a> · <a href={`${REPO}/blob/main/docs/ARCHITECTURE.md`} target="_blank" rel="noreferrer">Architecture</a> ·{" "}
          <a href={`${REPO}/blob/main/docs/CYPHER.md`} target="_blank" rel="noreferrer">Every query</a></div>
      </footer>
    </>
  );
}
