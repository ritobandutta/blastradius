import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";

// Colour by what the node IS in the security model, not by type alone.
const COLORS = {
  untrusted: "#f59e0b", internal: "#38bdf8", trusted: "#34d399",
  exfil: "#fb7185", mutate: "#c084fc", exec: "#ef4444",
  tool: "#94a3b8", agent: "#e2e8f0", server: "#475569", secret: "#fde047",
};

function nodeColor(n) {
  if (n.label === "DataSource") return COLORS[n.trust] || COLORS.untrusted;
  if (n.label === "Sink") return COLORS[n.kind] || COLORS.exfil;
  if (n.label === "Agent") return COLORS.agent;
  if (n.label === "MCPServer") return COLORS.server;
  if (n.label === "Secret" || n.label === "Permission") return COLORS.secret;
  return COLORS.tool;
}

const SHAPE = { DataSource: "round-rectangle", Sink: "diamond", Agent: "hexagon",
  MCPServer: "barrel", Secret: "tag", Permission: "tag", Tool: "ellipse" };

export default function GraphView({ graph, activePath, onNode, selected }) {
  const ref = useRef(null);
  const cy = useRef(null);

  useEffect(() => {
    if (!graph) return;
    const elements = [
      ...graph.nodes.map((n) => ({
        data: { id: n.id, label: n.name && n.label !== "Tool" ? n.name : n.id, kind: n.label,
                color: nodeColor(n), shape: SHAPE[n.label] || "ellipse",
                unconfirmed: n.confirmed === false },
      })),
      ...graph.edges.map((e, i) => ({
        data: { id: `e${i}`, source: e.source, target: e.target, type: e.type,
                gated: e.gated, scoped: e.scoped },
      })),
    ];
    cy.current?.destroy();
    cy.current = cytoscape({
      container: ref.current,
      elements,
      wheelSensitivity: 0.25,
      style: [
        { selector: "node", style: {
            "background-color": "data(color)", shape: "data(shape)", label: "data(label)",
            color: "#e2e8f0", "font-size": 10, "text-valign": "bottom", "text-margin-y": 4,
            width: 26, height: 26, "border-width": 1, "border-color": "#0b1220" } },
        { selector: "node[kind = 'Agent']", style: { width: 38, height: 38 } },
        { selector: "node[?unconfirmed]", style: { "border-style": "dashed",
            "border-color": "#fbbf24", "border-width": 2 } },
        { selector: "edge", style: {
            width: 1.2, "line-color": "#334155", "target-arrow-color": "#334155",
            "target-arrow-shape": "triangle", "curve-style": "bezier", opacity: 0.55 } },
        { selector: "edge[?gated]", style: { "line-style": "dashed", "line-color": "#34d399",
            "target-arrow-color": "#34d399", opacity: 0.9 } },
        { selector: "edge[?scoped]", style: { "line-style": "dotted", "line-color": "#34d399",
            "target-arrow-color": "#34d399", opacity: 0.9 } },
        { selector: ".path", style: { "line-color": "#ef4444", "target-arrow-color": "#ef4444",
            width: 3.5, opacity: 1, "z-index": 10 } },
        { selector: "node.path", style: { "border-color": "#ef4444", "border-width": 3 } },
        { selector: ":selected", style: { "border-color": "#fff", "border-width": 3 } },
        { selector: ".dim", style: { opacity: 0.18 } },
      ],
      layout: { name: "breadthfirst", directed: true, spacingFactor: 1.15, padding: 24 },
    });
    cy.current.on("tap", "node", (ev) => onNode?.(ev.target.id()));
    return () => cy.current?.destroy();
  }, [graph]);

  // Highlight the active path and pulse its edges.
  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.elements().removeClass("path dim");
    c.stop(true);
    if (!activePath) return;
    const ids = new Set(activePath.nodes);
    const edgeKeys = new Set(activePath.edges.map((e) => `${e.from}>${e.to}`));
    c.elements().addClass("dim");
    c.nodes().filter((n) => ids.has(n.id())).removeClass("dim").addClass("path");
    const pathEdges = c.edges().filter((e) => edgeKeys.has(`${e.source().id()}>${e.target().id()}`));
    pathEdges.removeClass("dim").addClass("path");
    let up = false;
    const pulse = () => {
      up = !up;
      pathEdges.animate({ style: { width: up ? 6 : 3 } }, { duration: 650, complete: pulse });
    };
    pulse();
    return () => c.stop(true);
  }, [activePath, graph]);

  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.nodes().unselect();
    if (selected) c.getElementById(selected).select();
  }, [selected]);

  return <div ref={ref} className="graph" role="img"
              aria-label="Capability graph of the agent stack" />;
}
