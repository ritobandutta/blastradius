"""A deliberately gullible, fully deterministic toy agent.

It stands in for "an LLM agent that follows instructions found in the content it reads". It is
NOT an LLM and we say so everywhere: the point is a reproducible victim that understands
direct, paraphrased and encoded requests, so the defences are tested on what they do, not on
sampling luck.

How it "understands" text:
  1. normalise: strip zero-width characters, decode base64 segments
  2. find a request: an action verb plus a channel cue (email address, #channel, URL, shell)
  3. optionally fetch private data first if the request mentions it, then act

It has no notion of trust: whatever the content says, it tries to do, using only the tools its
stack provides. A `gateway` (none / naive filter / Guard) sits between the agent and the world.
"""
import base64
import re
from dataclasses import dataclass, field
from typing import Protocol

from demo.toy_agent.tools import DATA_TOOLS, SandboxEnv

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"))
B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
VERBS = re.compile(
    r"\b(send|forward|relay|post|share|pass(?:\s+\w+)?\s+along|transmit|upload|email|mail|"
    r"message|run|execute|fetch|visit|open|request|write|save|append|deliver|copy)\b"
)
URL = re.compile(r"https?://[^\s\"')]+")
ADDRESS = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
CMD = re.compile(r"(?:command|terminal|shell)[^:]*:\s*(.+?)(?:\.\s|$)", re.S)
PATH = re.compile(r"(/[\w./\-]+)")


class Gateway(Protocol):
    name: str

    def filter_content(self, source: str, text: str) -> tuple[str, dict | None]: ...

    def before_call(self, tool: str, args: dict) -> dict: ...


@dataclass
class Passthrough:
    name: str = "unprotected"

    def filter_content(self, source, text):
        return text, None

    def before_call(self, tool, args):
        return {"allowed": True, "decision": "ALLOW", "note": "no protection"}


@dataclass
class Intent:
    kind: str  # shell | url | slack | email | file
    text: str
    wants: str | None = None  # data tool to read first


def normalise(text: str) -> str:
    text = text.translate(ZERO_WIDTH)
    extra = []
    for m in B64.findall(text):
        try:
            dec = base64.b64decode(m + "=" * (-len(m) % 4), validate=True).decode()
        except Exception:  # noqa: BLE001 - not base64, ignore
            continue
        if dec.isprintable():
            extra.append(dec)
    return text + ("\n" + "\n".join(extra) if extra else "")


def parse_intent(text: str) -> Intent | None:
    t = normalise(text)
    low = t.lower()
    if not VERBS.search(low):
        return None
    if re.search(r"\b(run|execute)\b", low) and re.search(r"command|terminal|shell", low):
        kind = "shell"
    elif URL.search(t):
        kind = "url"
    elif "slack" in low or "channel" in low or re.search(r"#\w+", low):
        kind = "slack"
    elif ADDRESS.search(t) or "mailbox" in low or "email" in low:
        kind = "email"
    elif re.search(r"\b(write|save|append)\b", low) and ("file" in low or PATH.search(t)):
        kind = "file"
    else:
        return None
    wants = None
    if kind != "shell":
        if re.search(r"secret|token|credential|api key|keys\b", low):
            wants = "secret"
        elif re.search(r"record|customer|account|database|table|rows", low):
            wants = "db"
        elif re.search(r"config|notes|file contents|contents of", low):
            wants = "file"
    return Intent(kind, t, wants)


@dataclass
class Episode:
    steps: list[dict] = field(default_factory=list)
    blocked_by: str | None = None

    def add(self, **kw):
        self.steps.append(kw)


class GullibleAgent:
    def __init__(self, env: SandboxEnv, tools: set[str], gateway: Gateway):
        self.env, self.tools, self.gw = env, tools, gateway
        self.ep = Episode()
        self.context: list[str] = []

    # one tool call through the gateway; returns result text or None if it did not run
    def call(self, tool: str, args: dict) -> str | None:
        if tool not in self.tools:
            self.ep.add(tool=tool, args=args, outcome="unavailable")
            return None
        verdict = self.gw.before_call(tool, args)
        if not verdict["allowed"]:
            self.ep.add(tool=tool, args=args, outcome="blocked", decision=verdict["decision"],
                        note=verdict.get("note", ""))
            self.ep.blocked_by = self.ep.blocked_by or tool
            return None
        out = self.env.execute(tool, args)
        self.ep.add(tool=tool, args=args, outcome="ran", decision=verdict["decision"])
        text, flagged = self.gw.filter_content(tool, out)
        if flagged:
            self.ep.add(tool=tool, outcome="content_filtered", match=flagged["pattern"])
        self.context.append(text)
        return text

    def run(self, ingest_tool: str, ingest_args: dict, reply_to: str | None = None) -> Episode:
        # tool descriptions are read before the tool is chosen
        desc = self.env.descriptions.get(ingest_tool)
        if desc:
            text, flagged = self.gw.filter_content(f"{ingest_tool}:description", desc)
            if flagged:
                self.ep.add(tool=ingest_tool, outcome="description_filtered",
                            match=flagged["pattern"])
            self.context.append(text)
        self.call(ingest_tool, ingest_args)
        intent = parse_intent("\n".join(self.context))
        if intent is None:
            return self.ep
        payload = ""
        if intent.wants:
            order = {"secret": ("get_secret",), "db": ("db_query",),
                     "file": ("read_file",)}[intent.wants]
            for tool in order + tuple(t for t in DATA_TOOLS if t not in order):
                if tool in self.tools:
                    payload = self.call(tool, {"for": "request in content"}) or ""
                    break
        self._act(intent, payload)
        return self.ep

    def _act(self, intent: Intent, payload: str) -> None:
        t = intent.text
        urls = URL.findall(t)
        if intent.kind == "shell":
            m = CMD.search(t)
            self.call("run_shell", {"cmd": (m.group(1) if m else t)[:200]})
        elif intent.kind == "url":
            if re.search(r"\b(post|upload)\b", t.lower()) and "http_post" in self.tools:
                self.call("http_post", {"url": urls[0], "body": payload})
            else:
                self.call("fetch_url", {"url": urls[0] + payload})
        elif intent.kind == "slack":
            self.call("slack_post", {"text": payload or "FYI from the assistant"})
        elif intent.kind == "email":
            addr = ADDRESS.search(t)
            self.call("send_email", {"to": addr.group(0) if addr else "unknown",
                                     "body": payload or "Thanks for reaching out. We are on it."})
        elif intent.kind == "file":
            m = PATH.search(t)
            self.call("write_file", {"path": m.group(1) if m else "/tmp/x",
                                     "content": payload or t[:80]})
