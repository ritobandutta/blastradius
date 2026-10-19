import { useEffect, useState } from "react";
import { api } from "./api";
import { Footer, Header } from "./Chrome";
import Landing from "./Landing";
import Workbench from "./Workbench";

// Two pages, hash-routed so they work from any static host: "#/" is the product page and
// "#/workbench" is the tool.
const routeFromHash = () => (window.location.hash.startsWith("#/workbench") ? "workbench" : "home");

export default function App() {
  const [route, setRoute] = useState(routeFromHash);
  const [health, setHealth] = useState(null);

  useEffect(() => {
    const onHash = () => {
      setRoute(routeFromHash());
      window.scrollTo({ top: 0, behavior: "instant" });
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  useEffect(() => {
    api("/health").then(setHealth).catch((e) => setHealth({ error: e.message }));
  }, []);
  useEffect(() => {
    document.title = route === "workbench" ? "Workbench · BlastRadius" : "BlastRadius · Firewall for AI agents";
  }, [route]);

  return (
    <>
      <Header route={route} health={health} />
      {route === "workbench" ? <Workbench health={health} /> : <Landing />}
      <Footer />
    </>
  );
}
