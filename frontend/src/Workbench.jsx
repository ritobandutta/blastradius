import { useEffect, useMemo, useState } from "react";
import { api, setTenant } from "./api";
import GraphView from "./GraphView";
import { DefensePanel, GuardPanel, PrecedentPanel, RedTeamPanel } from "./panels";
import { Bar, Btn, Card, CardHead, Chip, Empty, Err, Metric, fmt, useAction } from "./ui";

const TABS = [
  ["Guard", "Try a live session"],
  ["Red team", "Attack it"],
  ["Defense", "Fix and prove"],
  ["Precedent", "What we've seen"],
  ["Node", "Inspect a node"],
];
const KIND_LABEL = { exec: "EXEC", exfil: "EXFIL", mutate: "MUTATE" };

const GUIDE = [
  ["1", "Load a stack", "Pick a sample agent (or upload your own spec or mcp.json). It becomes a graph in the database. Nothing is run; this only describes what the agent could do."],
  ["2", "Read the numbers", "Attack paths is how many routes lead from untrusted input to a dangerous action. Open risk adds up their scores. Query time is how long the database took to find them."],
  ["3", "Study the graph", "Light squares are places data comes in (brighter = less trusted). The hexagon is the agent. Circles are its tools. Diamonds are sinks, where damage happens; bigger means worse. The blue line is the path you selected."],
  ["4", "Pick a path", "Click a row in the path table. The graph highlights that route end to end. The score weighs the sink type, any secret the tools hold, and how many different tools the attacker needs."],
  ["5", "Use the tools below", "Guard lets you play the agent and watch calls get allowed or blocked. Red team attacks a simulated agent. Defense finds the cheapest fix and proves it. Precedent shows what earlier scans found."],
];

export default function Workbench({ health }) {
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
  const [guide, setGuide] = useState(() => {
    try { return localStorage.getItem("br-guide") !== "hidden"; } catch { return true; }
  });
  const { busy, error, run } = useAction();

  const setGuideOpen = (v) => {
    setGuide(v);
    try { localStorage.setItem("br-guide", v ? "shown" : "hidden"); } catch { /* storage unavailable */ }
  };
  const refreshStacks = () => api("/stacks").then((r) => setStacks(r.stacks));
  useEffect(() => { api("/demo/stacks").then((r) => setDemos(r.demos)).catch(() => {}); }, []);
  useEffect(() => { setTenant(tenant); setStack(""); refreshStacks().catch(() => {}); }, [tenant]);

  const load = (id) => run(async () => {
    const [g, p, t, c] = await Promise.all([api(`/stacks/${id}/graph`), api(`/stacks/${id}/paths`),
      api(`/stacks/${id}/toxic`), api(`/stacks/${id}/choke-points`)]);
    setStack(id); setGraph(g); setReport(p); setToxic(t); setChoke(c); setPathIdx(0); setNode(null); setNodeInfo(null);
  });
  const loadDemo = (name) => run(async () => {
    const r = await api(`/demo/stacks/${name}/load`, { method: "POST" });
    await refreshStacks(); await load(r.stack);
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
  const firstDemo = demos.find((d) => d.name === "vulnerable")?.name || demos[0]?.name;
  const publicDemo = !!health?.public_demo;
  const demoLabel = { vulnerable: "Support agent", fixed: "Support agent (patched)", second_pattern: "Dev assistant" };

  return (
    <main className="wb">
      <div className="wb-top wrap">
        <div>
          <div className="eyebrow mono">Workbench</div>
          <h1 className="display wb-title">Analyze an agent</h1>
        </div>
        <Btn variant="ghost" size="sm" onClick={() => setGuideOpen(!guide)}>{guide ? "Hide guide" : "How to read this page"}</Btn>
      </div>

      <div className="wrap">
        {guide && (
          <Card className="guide">
            <CardHead title="How to read this page" sub="Five steps, left to right, top to bottom." />
            <ol className="guide-list">
              {GUIDE.map(([n, t, d]) => (<li key={n}><span className="mono muted small">{n}</span><div><b>{t}</b><p className="muted small" style={{ margin: "4px 0 0" }}>{d}</p></div></li>))}
            </ol>
          </Card>
        )}

        <div className="loadbar">
          <label>agent
            <select value={stack} onChange={(e) => e.target.value && load(e.target.value)} aria-label="Loaded agent">
              <option value="">{stacks.length ? "choose…" : "none loaded"}</option>
              {stacks.map((s) => <option key={s} value={s}>{s}</option>)}
            </select></label>
          {demos.map((d) => <Btn key={d.name} variant="ghost" size="sm" title={d.blurb} disabled={busy} onClick={() => loadDemo(d.name)}>{demoLabel[d.name] || d.name}</Btn>)}
          <span className="grow" />
          <label>upload spec or mcp.json<input type="file" accept=".json" onChange={(e) => upload(e.target.files[0])} /></label>
          <label>workspace<input style={{ width: 96 }} value={tenant} onChange={(e) => setT(e.target.value.trim() || "public")} /></label>
        </div>
        <Err error={error} />

        <div className="metrics" aria-live="polite">
          <Metric label="Attack paths" value={report ? report.path_count : "—"} sub={report ? `across ${tools.length} tools` : "load an agent"} />
          <Metric label="Open risk" value={report ? fmt(report.open_risk) : "—"} sub="sum of weighted path scores" />
          <Metric label="Query time" value={report ? fmt(report.run_time_ms) : "—"} unit="ms" sub="database time to find every path" />
          <Metric label="Toxic combination" value={toxicAgent ? (toxicAgent.toxic ? "YES" : "NO") : "—"}
            sub={toxicAgent?.toxic ? "untrusted input + private data + a way out" : toxicAgent ? "at least one leg is missing" : "load an agent"}
            tone={toxicAgent && !toxicAgent.toxic ? "pass" : undefined} />
        </div>

        <div className="wb-split">
          <Card className="graph-card">
            <CardHead title="Capability graph" sub={stack || "no agent loaded"}>
              {safe && <Chip tone="pass">0 PATHS · VERIFIED SAFE</Chip>}
              {report && !safe && <Chip tone="fail">{report.path_count} OPEN</Chip>}
              {topChoke && <Chip tone="warn" title="Gating or removing this tool severs the most paths">CHOKE POINT: {topChoke.id}</Chip>}
            </CardHead>
            <div className="graph-stage">
              {graph ? <GraphView graph={graph} activePath={active} onNode={clickNode} selected={node} />
                : <Empty action={firstDemo && <Btn variant="primary" size="sm" arrow onClick={() => loadDemo(firstDemo)}>Load the sample agent</Btn>}>
                    Load an agent to see its capability graph.</Empty>}
            </div>
            <div className="legend">
              <span><i style={{ background: "#ededed" }} />untrusted source</span>
              <span><i style={{ background: "#999" }} />internal source</span>
              <span><i style={{ background: "#fff", transform: "rotate(45deg) scale(.8)" }} />sink (bigger = worse)</span>
              <span><i style={{ background: "#52a8ff" }} />selected path</span>
              <span><i style={{ background: "#62c073" }} />gated or scoped</span>
            </div>
          </Card>

          <Card>
            <CardHead title="Attack paths" sub="ranked by score; click one to highlight it">
              {toxicAgent?.toxic && <Chip tone="fail">TOXIC</Chip>}</CardHead>
            {!report ? <Empty>Paths appear here once an agent is loaded.</Empty>
              : safe ? <div className="card-body"><div className="note pass">Zero paths. The database ran the traversal in {fmt(report.run_time_ms)} ms and found nothing.</div></div>
              : (
                <div style={{ maxHeight: 520, overflow: "auto" }}>
                  <table>
                    <thead><tr><th>Sink</th><th>Path</th><th className="num">Score</th></tr></thead>
                    <tbody>
                      {paths.map((p, i) => (
                        <tr key={p.id} className={`click path-row ${i === pathIdx ? "on" : ""}`} onClick={() => setPathIdx(i)}>
                          <td><Chip tone={i === pathIdx ? "active" : p.sink_kind === "exec" ? "fail" : "warn"}>{KIND_LABEL[p.sink_kind] || p.sink_kind}</Chip></td>
                          <td className="nodes">{p.nodes.join(" → ")}<Bar width={(p.score / maxScore) * 100} active={i === pathIdx} /></td>
                          <td className="num">{fmt(p.score)}</td>
                        </tr>))}
                    </tbody>
                  </table>
                </div>)}
          </Card>
        </div>

        <Card style={{ marginTop: 12 }}>
          <div className="tabs" role="tablist">
            {TABS.map(([t, hint]) => (
              <button key={t} role="tab" aria-selected={tab === t} className={`tab ${tab === t ? "on" : ""}`} onClick={() => setTab(t)}>
                {t}<span className="tab-hint">{hint}</span></button>))}
          </div>
          {!stack && tab !== "Precedent" && <Empty action={firstDemo && <Btn variant="primary" size="sm" arrow onClick={() => loadDemo(firstDemo)}>Load the sample agent</Btn>}>
            Load an agent first.</Empty>}
          {tab === "Guard" && stack && <GuardPanel stack={stack} tools={tools} />}
          {tab === "Red team" && <RedTeamPanel stack={stack} />}
          {tab === "Defense" && <DefensePanel stack={stack} onPatched={refreshStacks} onPaths={(id) => { load(id); window.scrollTo({ top: 0, behavior: "smooth" }); }} />}
          {tab === "Precedent" && <PrecedentPanel stack={stack} tenant={tenant} canSeed={!publicDemo} />}
          {tab === "Node" && stack && (nodeInfo ? (
            <div className="panel stack">
              <div className="row"><Chip tone="warn">{nodeInfo.label}</Chip><b className="mono">{nodeInfo.id}</b></div>
              <p className="mono small muted" style={{ margin: 0 }}>on {nodeInfo.on_paths.length} attack path(s); open risk through it {fmt(nodeInfo.open_risk_through)}</p>
              <pre>{JSON.stringify(nodeInfo.props, null, 2)}</pre>
              <table><thead><tr><th></th><th>Edge</th><th>Node</th><th>Type</th></tr></thead>
                <tbody>{nodeInfo.edges.map((e, i) => (<tr key={i}><td>{e.outgoing ? "→" : "←"}</td><td>{e.type}</td><td>{e.other}</td><td className="muted">{e.other_label}</td></tr>))}</tbody></table>
            </div>) : <Empty>Click a node in the graph to see why it is there and what it connects to.</Empty>)}
        </Card>
      </div>
    </main>
  );
}
