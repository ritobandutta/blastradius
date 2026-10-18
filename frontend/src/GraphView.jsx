import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";

// The design allows white, light gray, gray, blue (active) and green (positive), so severity is
// carried by shape, size and the label text, not by hue. Blue is only ever the active path.
const C = { white: "#ffffff", bright: "#ededed", mute: "#999999", chip: "#1f1f1f", card: "#0a0a0a",
            blue: "#52a8ff", green: "#62c073" };
const MONO = '"Geist Mono", ui-monospace, SFMono-Regular, Menlo, monospace';
const SINK_FILL = { exec: C.white, exfil: C.bright, mutate: C.mute };
const SINK_SIZE = { exec: 38, exfil: 31, mutate: 25 };

function visual(n) {
  switch (n.label) {
    case "DataSource": {
      const color = n.trust === "trusted" ? C.green : n.trust === "internal" ? C.mute : C.bright;
      return { color, shape: "round-rectangle", size: 24, bw: 0, bc: C.card, text: n.name || n.id };
    }
    case "Sink":
      return { color: SINK_FILL[n.kind] || C.bright, shape: "diamond", size: SINK_SIZE[n.kind] || 28, bw: 0,
               bc: C.card, text: `${n.name || n.id} · ${String(n.kind || "").toUpperCase()}` };
    case "Agent":
      return { color: C.white, shape: "hexagon", size: 42, bw: 0, bc: C.card, text: n.id };
    case "MCPServer":
      return { color: C.card, shape: "barrel", size: 22, bw: 1, bc: C.mute, text: n.id };
    case "Secret":
    case "Permission":
      return { color: C.chip, shape: "tag", size: 22, bw: 1.5, bc: C.bright, text: n.name || n.id };
    default:
      return { color: C.chip, shape: "ellipse", size: 26, bw: 1.5, bc: C.mute, text: n.id };
  }
}

export default function GraphView({ graph, activePath, onNode, selected }) {
  const ref = useRef(null);
  const cy = useRef(null);

  useEffect(() => {
    if (!graph || !ref.current) return undefined;
    const elements = [
      ...graph.nodes.map((n) => {
        const v = visual(n);
        return { data: { id: n.id, label: v.text, kind: n.label, color: v.color, shape: v.shape,
                         size: v.size, bw: v.bw, bc: v.bc, unconfirmed: n.confirmed === false } };
      }),
      ...graph.edges.map((e, i) => ({
        data: { id: `e${i}`, source: e.source, target: e.target, type: e.type, gated: e.gated, scoped: e.scoped },
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
            width: "data(size)", height: "data(size)", "border-width": "data(bw)", "border-color": "data(bc)",
            color: C.bright, "font-family": MONO, "font-size": 10, "text-valign": "bottom", "text-margin-y": 5,
            "text-wrap": "ellipsis", "text-max-width": 130, "overlay-opacity": 0 } },
        { selector: "node[?unconfirmed]", style: { "border-style": "dashed", "border-color": C.bright, "border-width": 2 } },
        { selector: "edge", style: {
            width: 1, "line-color": C.mute, "target-arrow-color": C.mute, "target-arrow-shape": "triangle",
            "arrow-scale": 0.8, "curve-style": "bezier", opacity: 0.32 } },
        { selector: "edge[?gated]", style: { "line-style": "dashed", "line-color": C.green,
            "target-arrow-color": C.green, opacity: 0.95, width: 1.6 } },
        { selector: "edge[?scoped]", style: { "line-style": "dotted", "line-color": C.green,
            "target-arrow-color": C.green, opacity: 0.95, width: 1.6 } },
        { selector: "edge.path", style: { "line-color": C.blue, "target-arrow-color": C.blue, width: 3.5,
            opacity: 1, "z-index": 10 } },
        { selector: "node.path", style: { "border-color": C.blue, "border-width": 3, "border-style": "solid" } },
        { selector: "node:selected", style: { "border-color": C.white, "border-width": 3 } },
        { selector: ".dim", style: { opacity: 0.14 } },
      ],
      layout: { name: "breadthfirst", directed: true, spacingFactor: 1.15, padding: 28 },
    });
    cy.current.on("tap", "node", (ev) => onNode?.(ev.target.id()));

    // Re-measure when the card resizes, and re-draw labels once the web fonts have loaded.
    const ro = new ResizeObserver(() => {
      if (!cy.current) return;
      cy.current.resize();
      cy.current.fit(undefined, 28);
    });
    ro.observe(ref.current);
    document.fonts?.ready.then(() => cy.current?.style().update());
    return () => { ro.disconnect(); cy.current?.destroy(); cy.current = null; };
  }, [graph]);

  // Highlight the active path and pulse its edges (blue = active).
  useEffect(() => {
    const c = cy.current;
    if (!c) return undefined;
    c.elements().removeClass("path dim");
    c.stop(true);
    if (!activePath) return undefined;
    const ids = new Set(activePath.nodes);
    const edgeKeys = new Set(activePath.edges.map((e) => `${e.from}>${e.to}`));
    c.elements().addClass("dim");
    c.nodes().filter((n) => ids.has(n.id())).removeClass("dim").addClass("path");
    const pathEdges = c.edges().filter((e) => edgeKeys.has(`${e.source().id()}>${e.target().id()}`));
    pathEdges.removeClass("dim").addClass("path");
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    let up = false;
    const pulse = () => {
      up = !up;
      pathEdges.animate({ style: { width: up ? 6 : 3 } }, { duration: 650, complete: pulse });
    };
    if (!reduce) pulse();
    return () => c.stop(true);
  }, [activePath, graph]);

  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.nodes().unselect();
    if (selected) c.getElementById(selected).select();
  }, [selected]);

  return <div ref={ref} className="graph" role="img"
              aria-label="Capability graph of the agent stack. The highlighted blue path is the selected attack path." />;
}
