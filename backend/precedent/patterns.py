"""Named steering techniques (Pattern nodes) and the classifier that assigns them to findings.

Like a tutoring system that models each wrong mental model as its own node instead of lumping
students by score, the precedent graph gives every *way an agent gets steered* its own Pattern
node. Findings from different stacks that share a pattern become comparable, and the fix that
held for one is evidence for the next.

OWASP tags use the LLM Top 10 (2025) numbering:
  LLM01 Prompt Injection              LLM02 Sensitive Information Disclosure
  LLM03 Supply Chain                  LLM05 Improper Output Handling
  LLM06 Excessive Agency
"""
from backend.graph.analysis import AttackPath

PATTERNS = [
    {"id": "indirect-injection-via-email", "name": "Indirect injection via email",
     "description": "Instructions hidden in an inbound email the agent is asked to read.",
     "owasp": ["LLM01"]},
    {"id": "indirect-injection-via-web", "name": "Indirect injection via web content",
     "description": "Instructions planted in a web page or document the agent fetches.",
     "owasp": ["LLM01"]},
    {"id": "indirect-injection-via-messages", "name": "Indirect injection via chat messages",
     "description": "Instructions posted in a shared chat channel the agent reads.",
     "owasp": ["LLM01"]},
    {"id": "indirect-injection-via-shared-content", "name": "Indirect injection via shared content",
     "description": "Instructions in user-contributed content (notes, tickets, wikis).",
     "owasp": ["LLM01"]},
    {"id": "tool-description-poisoning", "name": "Tool description poisoning",
     "description": "A malicious MCP server hides instructions in its tool descriptions, which "
                    "the agent reads as trusted configuration.",
     "owasp": ["LLM01", "LLM03"]},
    {"id": "confused-deputy", "name": "Confused deputy",
     "description": "The agent uses its own privileges (secrets, permissions) on behalf of "
                    "whoever wrote the content it read.",
     "owasp": ["LLM06"]},
    {"id": "data-exfiltration-via-egress", "name": "Data exfiltration via an outbound channel",
     "description": "Private data leaves through email, chat, or an HTTP request the agent "
                    "is allowed to make.",
     "owasp": ["LLM02", "LLM06"]},
    {"id": "unrestricted-code-execution", "name": "Unrestricted code execution",
     "description": "Untrusted content reaches a tool that runs commands on the host.",
     "owasp": ["LLM05", "LLM06"]},
    {"id": "unauthorized-state-change", "name": "Unauthorized state change",
     "description": "Untrusted content causes writes or deletes the user never asked for.",
     "owasp": ["LLM06"]},
    {"id": "single-tool-read-write-loop", "name": "Single tool read/write loop",
     "description": "One tool both ingests attacker content and can send data out "
                    "(for example a fetch tool), so a single capability is enough.",
     "owasp": ["LLM06"]},
    {"id": "lethal-trifecta", "name": "Lethal trifecta",
     "description": "One agent can ingest untrusted content, read private data, and reach an "
                    "outbound channel.",
     "owasp": ["LLM02", "LLM06"]},
]
PATTERN_IDS = {p["id"] for p in PATTERNS}


def _source_pattern(path: AttackPath) -> str:
    src = path.source
    if src.endswith("-tool-descriptions"):
        return "tool-description-poisoning"
    low = f"{src} {path.ingest_tool}".lower()
    if "email" in low or "mail" in low:
        return "indirect-injection-via-email"
    if "web" in low or "fetch" in low or "url" in low or "browse" in low:
        return "indirect-injection-via-web"
    if "chat" in low or "slack" in low or "message" in low:
        return "indirect-injection-via-messages"
    return "indirect-injection-via-shared-content"


def classify(path: AttackPath, stack_toxic: bool) -> list[str]:
    """Pattern ids for one attack path. Deterministic and rule-based, so it can be explained."""
    ids = [_source_pattern(path)]
    if path.sink_kind == "exec":
        ids.append("unrestricted-code-execution")
    elif path.sink_kind == "mutate":
        ids.append("unauthorized-state-change")
    else:
        ids.append("data-exfiltration-via-egress")
    if path.secret_sensitivity >= 4:
        ids.append("confused-deputy")
    if path.ingest_tool == path.act_tool:
        ids.append("single-tool-read-write-loop")
    if stack_toxic:
        ids.append("lethal-trifecta")
    return ids


def combo(path: AttackPath) -> str:
    """Stack-independent identity of a path: what is read, by which tool, acted on by which."""
    return f"{path.source}>{path.ingest_tool}>{path.act_tool}>{path.sink}"
