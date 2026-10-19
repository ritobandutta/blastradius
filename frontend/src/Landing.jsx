import HeroGraph from "./HeroGraph";
import { scrollToId } from "./Chrome";
import { Btn, Card, CardHead, Chip, LinkBtn, Metric, SectionHead } from "./ui";

const TRIFECTA = [
  ["01", "Untrusted input", "Anything a stranger can write: an inbound email, a web page, a shared note, a community tool's description."],
  ["02", "Something worth taking", "Private data, secrets or permissions the agent can reach: a customer database, API keys, a shell."],
  ["03", "A way out", "A tool that sends data away or changes things: email, chat, an HTTP request, a shell command, a file write."],
];

const FEATURES = [
  ["Map every path", "Describe your agent's tools and MCP servers, or import an mcp.json. BlastRadius builds a capability graph and lists every path from untrusted input to a dangerous action, scored by severity, with the exact route."],
  ["Guard every call", "A deterministic check on each tool call, as an MCP proxy or an HTTP endpoint. If untrusted data is in play and the call could reach a sink, it blocks the call or asks a human. No model makes this decision."],
  ["Fix it, then prove it", "It finds the cheapest set of changes that severs every path, writes the patched config and a PR description, then re-runs the same query and shows zero paths."],
  ["Remember across stacks", "Findings become named patterns. A new scan reports that a combination was exploited in earlier stacks and which fix held. Confirmed exploits can become Guard rules, armed only after a critic checks them."],
  ["Catch regressions in review", "Diff two configs and get a PR comment listing the attack paths a change introduces or removes. A GitHub Action fails the check when it opens new ones."],
  ["Keep a human in the loop", "Calls that are risky but not clearly harmful wait for an explicit approve or deny. Only a person can approve, and a blocked call can never be turned into an allowed one."],
];

const STEPS = [
  ["Connect", "Load a JSON stack spec or import an mcp.json. Tools are classified from an editable rules file, and anything the tool had to guess is flagged for you to confirm."],
  ["Analyze", "Your stack is stored as a graph. One query returns every path from an untrusted source, through the agent, to a sink, with a score and the time it took."],
  ["Enforce", "Route tool calls through the Guard. Each session is its own graph. Calls made after untrusted data entered are checked against those paths."],
  ["Fix and verify", "Apply the minimum cut. The same query on the patched graph has to return zero paths before anything is called safe."],
];

const INTEGRATIONS = [
  ["MCP proxy", "Wraps any stdio MCP server and checks every tools/call before it reaches the server."],
  ["HTTP check", "POST /guard/check before each tool call, for agents that do not use MCP."],
  ["MCP server", "Lets an agent ask BlastRadius about its own attack surface and precedent."],
  ["Config import", "Reads an mcp.json or Claude Code settings file. Tools are inferred, and guesses are flagged."],
  ["CLI and GitHub Action", "scan, fix, diff and redteam commands, plus a pull-request drift check."],
];

const FAQ = [
  ["Does BlastRadius read my prompts or tool outputs?",
    "No. The Guard decides from the shape of the path: what a tool can reach, whether untrusted data has entered the session, and what the agent is allowed to do. It never inspects the text of a tool result, so rewording an attack does not change the outcome."],
  ["Is an AI model involved in blocking?",
    "No. Allow, escalate and deny come from database queries and fixed rules. A model is optional and only writes advisory text, suggests classifications for unknown tools, and rewrites test attacks. It can never change a decision."],
  ["How is this different from a prompt-injection filter?",
    "A filter tries to recognise malicious wording, and an attacker can rephrase, encode or hide it. In our sandbox test a keyword filter stopped 4 of 20 variants. BlastRadius asks whether the agent could cause harm at all, so it holds however the instruction is worded. They can be used together."],
  ["What does it cost me in false positives?",
    "A structural check cannot tell a legitimate reply from a leak. Reading an email and then replying to it has the same shape as an attack path, so it is blocked or sent to a human. On five recorded benign sessions it blocked one. The approval gate exists for exactly this."],
  ["What is a sink?",
    "A place where damage happens: data leaving (email, chat, an HTTP request), state changing (writes and deletes), or code running (a shell). Every path BlastRadius reports ends at one."],
  ["What happens if the database is down?",
    "The Guard denies every call and the API reports an error. It never falls back to allowing."],
  ["Can it prove my agent is safe?",
    "It can show that no path exists in the model you gave it. If a tool is missing from your description or a data source is mislabelled, the result is only as good as that description. Tools it had to guess are flagged for confirmation."],
  ["Where does my data go?",
    "Stack descriptions and session events are stored in the connected FalkorDB. The hosted workbench is for synthetic sample data only, so do not load real credentials. If you import an mcp.json, remove tokens from the arguments first."],
  ["Is it ready for production?",
    "It is an early-stage project. Tenant isolation is enforced in the application layer and there is no authentication yet. Taint is tracked per session rather than per piece of data, and the hosted demo runs on free tiers. Treat it as a review and guardrail tool, not your only control."],
  ["Does it work with my agent framework?",
    "Anything that calls tools through MCP can use the proxy. Other agents can call the HTTP check endpoint before each tool call."],
];

export default function Landing() {
  return (
    <main>
      {/* ---------------------------------------------------------- hero */}
      <section className="hero" id="overview">
        <HeroGraph />
        <div className="hero-inner">
          <div className="chips"><Chip tone="active">AI AGENT SECURITY</Chip></div>
          <h1 className="headline-fluid">If an attacker controls one thing your agent reads, what can it do?</h1>
          <p className="hero-sub">BlastRadius maps what your AI agent can read, reach and run, finds every path from untrusted input
            to a dangerous action, and blocks risky calls at run time without trying to read the text.</p>
          <div className="hero-cta">
            <LinkBtn variant="primary" size="lg" arrow href="#/workbench">Open workbench</LinkBtn>
            <Btn variant="ghost" size="lg" onClick={() => scrollToId("how")}>How it works</Btn>
          </div>
        </div>
      </section>

      <div className="wrap">
        {/* ---------------------------------------------------------- problem */}
        <section className="section" id="problem">
          <SectionHead eyebrow="The problem" title="Agents read things attackers can write."
            sub="Emails, web pages, tickets, chat messages and even tool descriptions all flow into your agent's context. Any of them can carry instructions." />
          <div className="grid3">
            {TRIFECTA.map(([n, t, d]) => (
              <Card key={n}><div className="card-body stack"><span className="mono muted small">{n}</span><h3 className="big-h">{t}</h3>
                <p className="muted" style={{ margin: 0 }}>{d}</p></div></Card>))}
          </div>
          <p className="callout">When one agent has all three, a single poisoned email can become a data leak. Take away any one and that path closes.
            This combination is often called the{" "}
            <a href="https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/" target="_blank" rel="noreferrer">lethal trifecta</a>.</p>
        </section>

        {/* ---------------------------------------------------------- product */}
        <section className="section" id="product">
          <SectionHead eyebrow="Product" title="From “what could go wrong” to “here is the proof”."
            sub="One graph of your agent's capabilities drives the analysis, the run-time checks and the fix." />
          <div className="features">
            {FEATURES.map(([t, d]) => (
              <Card key={t}><div className="card-body stack"><h3 className="big-h">{t}</h3><p className="muted" style={{ margin: 0 }}>{d}</p></div></Card>))}
          </div>
        </section>

        {/* ---------------------------------------------------------- how */}
        <section className="section" id="how">
          <SectionHead eyebrow="How it works" title="A graph that decides, not a filter that reads."
            sub="The Guard never looks at the text of a tool result. A paraphrased injection and an obvious one produce the same path." />
          <div className="steps">
            {STEPS.map(([t, d], i) => (
              <div className="step" key={t}><span className="mono muted small">0{i + 1}</span><h3 className="big-h">{t}</h3><p className="muted" style={{ margin: 0 }}>{d}</p></div>))}
          </div>
          <div className="grid3" style={{ marginTop: 12 }}>
            <Card>
              <CardHead title="Guard decisions" sub="example sequence"><Chip tone="warn">EXAMPLE</Chip></CardHead>
              <div className="card-body">
                {[["read_email", "ALLOW", "pass", "taints the session"], ["db_query", "ALLOW", "pass", "reaches no sink"],
                  ["send_email", "DENY", "fail", "tainted + toxic agent"], ["slack_post", "ESCALATE", "warn", "gated: a human decides"]].map(([t, d, tone, why]) => (
                  <div className="status-row" key={t}><span>{t}<br /><span className="muted">{why}</span></span><Chip tone={tone}>{d}</Chip><span /></div>))}
              </div>
            </Card>
            <Card>
              <CardHead title="Attack paths" sub="example output"><Chip tone="warn">EXAMPLE</Chip></CardHead>
              <div className="card-body">
                {[["EXEC", "inbound-email → read_email → agent → run_shell → host-shell", 100], ["EXFIL", "web-content → fetch_url → agent → fetch_url → web-egress", 47],
                  ["EXFIL", "inbound-email → read_email → agent → send_email → outbound-email", 40]].map(([k, p, w]) => (
                  <div key={p} style={{ marginBottom: 14 }}><div className="row"><Chip tone={k === "EXEC" ? "fail" : "warn"}>{k}</Chip></div>
                    <div className="mono small muted" style={{ margin: "6px 0 6px" }}>{p}</div>
                    <div className="bar"><div className="bar-fill" style={{ left: 0, width: `${w}%` }} /></div></div>))}
              </div>
            </Card>
            <Card>
              <CardHead title="Proof of absence" sub="same query, patched graph"><Chip tone="warn">EXAMPLE</Chip></CardHead>
              <div className="card-body">
                <div className="diff">
                  <div className="mod">~ CAN_INVOKE agent → run_shell</div><div className="add">+ gated: true</div>
                  <div className="mod">~ CAN_INVOKE agent → send_email</div><div className="add">+ gated: true</div>
                  <div>  … 2 more gates</div><div className="add">paths_to_sinks → 0 rows</div>
                </div>
              </div>
            </Card>
          </div>
        </section>

        {/* ---------------------------------------------------------- integrate */}
        <section className="section" id="integrate">
          <SectionHead eyebrow="Integrations" title="Fits where your agent already runs." />
          <Card>
            <table>
              <tbody>{INTEGRATIONS.map(([n, d]) => (<tr key={n}><td style={{ width: 220, color: "var(--text)" }}>{n}</td><td className="muted">{d}</td></tr>))}</tbody>
            </table>
          </Card>
        </section>

        {/* ---------------------------------------------------------- evidence */}
        <section className="section" id="evidence">
          <SectionHead eyebrow="Evidence" title="What we measured."
            sub="On a simulated agent in a sandbox, using harmless marker strings that stand in for stolen data. This tests the method; it is not a production benchmark." />
          <div className="metrics">
            <Metric label="Attacks stopped" value="20" unit="/ 20" sub="a keyword filter stopped 4 of the same 20" />
            <Metric label="False positives" value="1" unit="/ 5" sub="reading an email and replying is blocked" />
            <Metric label="After the fix" value="0" unit="paths" sub="same query re-run on the patched graph" />
            <Metric label="Guard decision" value="~3" unit="ms" sub="local database; about 125 to 155 ms on the hosted demo" />
          </div>
          <p className="callout">The test agent is a deterministic stand-in for a gullible model, not a real one, and the keyword filter's score depends on how we
            wrote it. The attack variants were direct, paraphrased, zero-width, base64 and tool-description poisoning. Re-run all of it yourself in the workbench.</p>
        </section>

        {/* ---------------------------------------------------------- faq */}
        <section className="section" id="faq">
          <SectionHead eyebrow="FAQ" title="Questions people ask." />
          <div className="faq">
            {FAQ.map(([q, a]) => (<details key={q}><summary>{q}</summary><p>{a}</p></details>))}
          </div>
        </section>

        {/* ---------------------------------------------------------- cta */}
        <section className="section">
          <div className="cta-band">
            <h2 className="display">See your agent's blast radius.</h2>
            <p className="muted" style={{ margin: 0, maxWidth: 520 }}>Load a sample agent, read its attack paths, try the Guard on a live session, and watch a fix prove itself.</p>
            <LinkBtn variant="primary" size="lg" arrow href="#/workbench">Open workbench</LinkBtn>
          </div>
        </section>
      </div>
    </main>
  );
}
