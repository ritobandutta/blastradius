import { useEffect, useMemo, useState } from "react";
import { api, setTenant } from "./api";
import GraphView from "./GraphView";
import { DefensePanel, Err, GuardPanel, MockBadge, PrecedentPanel, RedTeamPanel, useAction } from "./panels";

const TABS = ["Node", "Guard", "Red team", "Defense", "Precedent"];

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
  const { error, run } = useAction();

  const refreshStacks = () => api("/stacks").then((r) => setStacks(r.stacks));
  useEffect(() => {
    api("/health").then(setHealth).catch((e) => setHealth({ error: e.message }));
    api("/demo/stacks").then((r) => setDemos(r.demos)).catch(() => {});
  }, []);
  useEffect(() => { setTenant(tenant); setStack(""); refreshStacks().catch(() => {}); }, [tenant]);

  const load = (id) => run(async () => {
    const [g, p, t, c] = await Promise.all([
      api(`/stacks/${id}/graph`), api(`/stacks/${id}/paths`),
      api(`/stacks/${id}/toxic`), api(`/stacks/${id}/choke-points`)]);
    setStack(id); setGraph(g); setReport(p); setToxic(t); setChoke(c);
    setPathIdx(0); setNode(null); setNodeInfo(null);
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
  const clickNode = (id) => { setNode(id); setTab("Node");
    api(`/stacks/${stack}/nodes/${id}`).then(setNodeInfo).catch(() => setNodeInfo(null)); };

  const paths = report?.paths || [];
  const active = paths[pathIdx] || null;
  const tools = useMemo(() => (graph?.nodes || []).filter((n) => n.label === "Tool").map((n) => n.id), [graph]);
  const toxicAgent = toxic?.agents?.[0];

  return (
    <div className="app">
      <header className="top">
        <div className="brand">Blast<span>Radius</span></div>
        <select value={stack} onChange={(e) => e.target.value && load(e.target.value)} aria-label="Stack">
          <option value="">{stacks.length ? "choose a stack…" : "no stacks loaded"}</option>
          {stacks.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        {demos.map((d) => <button key={d.name} title={d.blurb} onClick={() => loadDemo(d.name)}>Load {d.name}</button>)}
        <label className="small muted">upload spec / mcp.json&nbsp;
          <input type="file" accept=".json" onChange={(e) => upload(e.target.files[0])} /></label>
        <div className="spacer" />
        <label className="small muted">tenant&nbsp;
          <input style={{ width: 90 }} value={tenant} onChange={(e) => setT(e.target.value.trim() || "public")} /></label>
        {health?.llm && <MockBadge llm={health.llm} />}
        {health?.error && <span className="badge bad">API down: {health.error}</span>}
        {health?.falkordb_ping_ms !== undefined && <span className="badge ms">FalkorDB {health.falkordb_ping_ms} ms</span>}
      </header>

      <div className="main">
        <section className="left">
          <div className="graphwrap">
            {graph ? <GraphView graph={graph} activePath={active} onNode={clickNode} selected={node} />
              : <div className="pane muted">Load a demo stack to see its capability graph.</div>}
            {report && (
              <div className="risk">
                <span className={`badge ${report.path_count ? "bad" : "safe"}`}>
                  {report.path_count ? `${report.path_count} attack paths` : "0 attack paths"}</span>
                <span className="num">{report.open_risk}</span><span className="muted small">open risk</span>
                <span className="badge ms" title="FalkorDB execution time">{report.run_time_ms} ms</span>
              </div>)}
            <div className="legend">
              <span><i style={{ background: "#f59e0b" }} />untrusted</span>
              <span><i style={{ background: "#38bdf8" }} />internal</span>
              <span><i style={{ background: "#fb7185" }} />exfil sink</span>
              <span><i style={{ background: "#ef4444" }} />exec sink</span>
              <span><i style={{ background: "#c084fc" }} />mutate sink</span>
              <span><i style={{ background: "#34d399" }} />gated/scoped edge</span>
            </div>
          </div>
          <div className="paths">
            <Err error={error} />
            <h2>Attack paths {toxicAgent?.toxic && <span className="badge bad">TOXIC COMBINATION</span>}</h2>
            {report && !paths.length && <div className="note">Zero paths. The traversal ran in {report.run_time_ms} ms and found nothing.</div>}
            {paths.map((p, i) => (
              <div key={p.id} className={`path ${i === pathIdx ? "active" : ""}`} onClick={() => setPathIdx(i)}>
                <span className={`score ${p.sink_kind}`}>{p.score}</span>
                <span className="chain">{p.nodes.join(" → ")}</span>
                <span className="kind">{p.sink_kind}</span>
              </div>))}
            {choke && <p className="small muted">Choke points: {choke.choke_points.filter((c) => c.paths_through).slice(0, 4)
              .map((c) => `${c.id} (${c.paths_through} paths)`).join(", ")}</p>}
          </div>
        </section>

        <section className="right">
          <nav className="tabs">{TABS.map((t) => (
            <button key={t} className={`tab ${tab === t ? "on" : ""}`} onClick={() => setTab(t)}>{t}</button>))}</nav>
          <div className="pane">
            {!stack && tab !== "Precedent" && <p className="muted">Load a stack first.</p>}
            {tab === "Node" && stack && (nodeInfo ? (
              <div>
                <h3>{nodeInfo.label}: {nodeInfo.id}</h3>
                <p>On <b>{nodeInfo.on_paths.length}</b> attack path(s), open risk through it <b>{nodeInfo.open_risk_through}</b>.</p>
                <pre>{JSON.stringify(nodeInfo.props, null, 2)}</pre>
                <h3>Edges</h3>
                <table><tbody>{nodeInfo.edges.map((e, i) => (
                  <tr key={i}><td>{e.outgoing ? "→" : "←"}</td><td>{e.type}</td><td>{e.other}</td>
                    <td className="muted">{e.other_label}</td></tr>))}</tbody></table>
              </div>) : <p className="muted">Click a node in the graph to see why it is there.</p>)}
            {tab === "Guard" && stack && <GuardPanel stack={stack} tools={tools} />}
            {tab === "Red team" && <RedTeamPanel stack={stack} />}
            {tab === "Defense" && <DefensePanel stack={stack}
              onPatched={refreshStacks} onPaths={(id) => load(id)} />}
            {tab === "Precedent" && <PrecedentPanel stack={stack} tenant={tenant} />}
          </div>
        </section>
      </div>
    </div>
  );
}
