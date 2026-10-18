// Decorative hero background: a network with one highlighted path. It is generated from a seeded
// generator, so it is the same on every load, and it carries no data (aria-hidden).
const rng = (seed) => {
  let s = seed >>> 0;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 4294967296);
};
const R = rng(11);
const NODES = Array.from({ length: 40 }, (_, i) => ({
  id: i, x: 40 + R() * 1120, y: 40 + R() * 620, r: 1.6 + R() * 3,
}));
const EDGES = (() => {
  const out = new Set();
  NODES.forEach((a) => {
    NODES.filter((b) => b.id !== a.id)
      .map((b) => [b.id, (a.x - b.x) ** 2 + (a.y - b.y) ** 2])
      .sort((p, q) => p[1] - q[1])
      .slice(0, 2)
      .forEach(([j]) => out.add(a.id < j ? `${a.id}-${j}` : `${j}-${a.id}`));
  });
  return [...out].map((s) => s.split("-").map(Number));
})();
const PATH = (() => {
  const byX = [...NODES].sort((a, b) => a.x - b.x);
  return [0, 0.2, 0.45, 0.7, 0.98].map((q) => byX[Math.min(byX.length - 1, Math.floor(q * byX.length))]);
})();
const PATH_POINTS = PATH.map((n) => `${n.x},${n.y}`).join(" ");

export default function HeroGraph() {
  return (
    <svg className="hero-graph" viewBox="0 0 1200 700" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
      <defs>
        <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="6" />
        </filter>
      </defs>
      {EDGES.map(([a, b]) => (
        <line key={`${a}-${b}`} x1={NODES[a].x} y1={NODES[a].y} x2={NODES[b].x} y2={NODES[b].y}
              stroke="rgba(255,255,255,0.10)" strokeWidth="1" />
      ))}
      {NODES.map((n) => (
        <circle key={n.id} cx={n.x} cy={n.y} r={n.r} fill="rgba(255,255,255,0.22)" />
      ))}
      <polyline points={PATH_POINTS} fill="none" stroke="#52a8ff" strokeWidth="6" opacity="0.5" filter="url(#glow)" />
      <polyline className="hero-path" points={PATH_POINTS} fill="none" stroke="#52a8ff" strokeWidth="2"
                strokeDasharray="7 11" />
      {PATH.map((n) => (
        <g key={n.id}>
          <circle cx={n.x} cy={n.y} r="11" fill="none" stroke="#52a8ff" strokeWidth="1" opacity="0.5" />
          <circle cx={n.x} cy={n.y} r="4.5" fill="#52a8ff" />
        </g>
      ))}
    </svg>
  );
}
