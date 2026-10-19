import { useEffect, useState } from "react";
import { Arrow, Chip, LinkBtn, Logo } from "./ui";

export const REPO = "https://github.com/ritobandutta/blastradius";
export const DOCS = `${REPO}/blob/main/docs`;

// In-page scroll (landing only). Hash links are reserved for routes (#/workbench), so section
// links are plain buttons that scroll.
export const scrollToId = (id) => document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });

const SECTIONS = [["Product", "product"], ["How it works", "how"], ["Evidence", "evidence"], ["FAQ", "faq"]];

export function Header({ route, health }) {
  const [menu, setMenu] = useState(false);
  const [solid, setSolid] = useState(false);
  useEffect(() => {
    const onScroll = () => setSolid(window.scrollY > 24);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);
  useEffect(() => setMenu(false), [route]);
  const onHome = route === "home";
  const jump = (id) => {
    setMenu(false);
    if (onHome) scrollToId(id);
    else {
      window.location.hash = "#/";
      setTimeout(() => scrollToId(id), 80);
    }
  };
  return (
    <>
      <header className={`header ${solid || !onHome ? "solid" : ""}`}>
        <a className="brand" href="#/"><Logo /> BlastRadius</a>
        <nav className="nav" aria-label="Primary">
          {SECTIONS.map(([label, id]) => (
            <button key={id} className="navlink" onClick={() => jump(id)}>{label}</button>
          ))}
        </nav>
        <div className="right">
          {route === "workbench" && health?.error && <Chip tone="fail">ENGINE OFFLINE</Chip>}
          {route === "workbench" && health?.falkordb_ping_ms !== undefined && <span className="hide-m"><Chip tone="pass">ENGINE ONLINE</Chip></span>}
          {route === "workbench"
            ? <a className="btn-square ghost hide-m" href="#/">Home</a>
            : <LinkBtn variant="primary" arrow href="#/workbench">Open workbench</LinkBtn>}
        </div>
        <button className="burger" aria-label="Open menu" aria-expanded={menu} onClick={() => setMenu(true)}>MENU</button>
      </header>
      {menu && (
        <div className="mobile-menu" role="dialog" aria-modal="true" aria-label="Menu">
          <div className="top">
            <span className="brand"><Logo /> BlastRadius</span>
            <button className="burger" style={{ display: "block" }} onClick={() => setMenu(false)}>CLOSE</button>
          </div>
          {SECTIONS.map(([label, id]) => (
            <a key={id} href="#/" onClick={(e) => { e.preventDefault(); jump(id); }}>{label}</a>
          ))}
          <a href="#/workbench">Open workbench ↗</a>
        </div>
      )}
    </>
  );
}

export function Footer() {
  return (
    <footer className="footer">
      <div className="foot-brand">
        <span className="brand"><Logo size={18} /> BlastRadius</span>
        <p>Find every path an attacker could take through your AI agent, block the risky calls, and prove the fix.</p>
      </div>
      <div className="foot-col">
        <h4 className="mono">Product</h4>
        <a href="#/workbench">Workbench</a>
        <a href="#/" onClick={(e) => { e.preventDefault(); window.location.hash = "#/"; setTimeout(() => scrollToId("how"), 80); }}>How it works</a>
        <a href="#/" onClick={(e) => { e.preventDefault(); window.location.hash = "#/"; setTimeout(() => scrollToId("faq"), 80); }}>FAQ</a>
      </div>
      <div className="foot-col">
        <h4 className="mono">Resources</h4>
        <a href={`${DOCS}/ARCHITECTURE.md`} target="_blank" rel="noreferrer">Architecture <Arrow size={9} /></a>
        <a href={`${DOCS}/CYPHER.md`} target="_blank" rel="noreferrer">Query reference <Arrow size={9} /></a>
        <a href={REPO} target="_blank" rel="noreferrer">Source code <Arrow size={9} /></a>
      </div>
      <div className="foot-col">
        <h4 className="mono">Notes</h4>
        <span>Powered by FalkorDB.</span>
        <span>The hosted workbench uses synthetic sample data only. Do not load real credentials.</span>
      </div>
    </footer>
  );
}
