import { useState } from "react";

// ---- formatting ------------------------------------------------------------------------
export const fmt = (n) => {
  if (n === null || n === undefined || Number.isNaN(Number(n))) return "—";
  const v = Number(n);
  return v >= 100 ? String(Math.round(v)) : v >= 10 ? v.toFixed(1) : v.toFixed(2);
};
export const shortModel = (m) => (m || "").split("/").pop().replace(":free", "");

// Guard decisions map onto the three chip tones: PASS (green), WARN (gray), FAIL (light).
export const TONE = { ALLOW: "pass", ESCALATE: "warn", DENY: "fail" };

// ---- icons -----------------------------------------------------------------------------
export function Arrow({ size = 12 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 12 12" fill="none" aria-hidden="true">
      <path d="M2.5 9.5L9.5 2.5M9.5 2.5H4M9.5 2.5V8" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  );
}

// A hexagon (the agent) with three paths leaving it.
export function Logo({ size = 22 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <polygon points="12,5 18,8.5 18,15.5 12,19 6,15.5 6,8.5" stroke="#fff" strokeWidth="1.4" />
      <path d="M12 5V1.5M18 15.5l3.6 2.1M6 15.5l-3.6 2.1" stroke="#fff" strokeWidth="1.4" />
      <circle cx="12" cy="1.5" r="1.3" fill="#fff" />
      <circle cx="21.6" cy="17.6" r="1.3" fill="#fff" />
      <circle cx="2.4" cy="17.6" r="1.3" fill="#fff" />
    </svg>
  );
}

// ---- primitives ------------------------------------------------------------------------
export function Chip({ tone = "warn", children, title }) {
  return (
    <span className="chip" title={title}>
      <i className={`dot ${tone}`} aria-hidden="true" />
      {children}
    </span>
  );
}

export function MockChip({ llm }) {
  if (!llm) return null;
  return llm.mock_mode ? (
    <Chip tone="warn" title={llm.reason || llm.llm_error || "deterministic mock output"}>
      MOCK MODE
    </Chip>
  ) : (
    <Chip tone="pass" title={llm.model}>
      LIVE LLM · {shortModel(llm.model)}
    </Chip>
  );
}

export function Btn({ variant = "ghost", size = "md", arrow = false, className = "", children, ...rest }) {
  return (
    <button className={`btn-square ${variant} ${size} ${className}`} {...rest}>
      {children}
      {arrow && <Arrow size={size === "lg" ? 12 : 10} />}
    </button>
  );
}

export function Card({ className = "", children, ...rest }) {
  return (
    <section className={`card ${className}`} {...rest}>
      {children}
    </section>
  );
}

export function CardHead({ title, sub, children }) {
  return (
    <header className="card-head">
      <div>
        <h3>{title}</h3>
        {sub && <p className="card-sub">{sub}</p>}
      </div>
      <div className="chips">{children}</div>
    </header>
  );
}

export function SectionHead({ id, index, eyebrow, title, sub }) {
  return (
    <header className="section-head" id={id}>
      <div className="eyebrow mono">
        {index} / {eyebrow}
      </div>
      <h2 className="display">{title}</h2>
      {sub && <p className="section-sub">{sub}</p>}
    </header>
  );
}

export function Metric({ value, unit, label, sub, tone }) {
  return (
    <div className="metric">
      <div className="metric-label mono">{label}</div>
      <div className="metric-value">
        <span className={tone ? `t-${tone}` : ""}>{value}</span>
        {unit && <span className="unit mono">{unit}</span>}
      </div>
      <div className="metric-sub mono">{sub}</div>
    </div>
  );
}

// Timeline progress bar: left offset and width are percentages of the row's span.
export function Bar({ start = 0, width = 100, active = false, tone = "" }) {
  return (
    <div className="bar" aria-hidden="true">
      <div
        className={`bar-fill ${active ? "active" : ""} ${tone}`}
        style={{ left: `${Math.min(100, Math.max(0, start))}%`, width: `${Math.max(0.8, width)}%` }}
      />
    </div>
  );
}

export function Empty({ children, action }) {
  return (
    <div className="empty">
      <p className="mono">{children}</p>
      {action}
    </div>
  );
}

export function Err({ error }) {
  if (!error) return null;
  return (
    <div className="err" role="alert">
      <Chip tone="fail">ERROR</Chip>
      <span className="mono">{String(error.message || error)}</span>
    </div>
  );
}

// Run an async action; track busy and error. Failures are shown, never swallowed.
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const run = async (fn) => {
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (e) {
      setError(e);
      return null;
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, run };
}
