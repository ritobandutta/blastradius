"""The stack spec: a plain JSON description of one agent stack.

It is deliberately small. A stack has one agent and some MCP servers; each server exposes
tools; each tool can read data sources, reach sinks and hold secrets/permissions. Anything the
author leaves out is filled in from `rules.yaml` (and marked as such), see annotate.py.

The two fix levers are part of the spec so a patched config is just a spec with changes:
  - `tool.gated`            a human must confirm each call (severs Agent -CAN_INVOKE-> Tool)
  - `reach.scoped`          the tool's token is scoped so it can no longer reach that sink
  - a tool removed entirely (highest cost)
"""
from typing import Literal

from pydantic import BaseModel, Field, field_validator

SideEffect = Literal["read", "write", "destructive", "exec", "network_out"]
Trust = Literal["untrusted", "internal", "trusted"]
SinkKind = Literal["exfil", "mutate", "exec"]


class DataRef(BaseModel):
    id: str
    label: str | None = None
    trust: Trust = "untrusted"


class ReachRef(BaseModel):
    id: str
    kind: SinkKind
    label: str | None = None
    scoped: bool = False


class HoldRef(BaseModel):
    id: str
    type: Literal["secret", "permission"] = "secret"
    sensitivity: int = Field(default=3, ge=1, le=5)
    label: str | None = None


class ToolSpec(BaseModel):
    name: str
    description: str = ""
    side_effect: SideEffect | None = None
    reads: list[DataRef] | None = None
    reaches: list[ReachRef] | None = None
    holds: list[HoldRef] | None = None
    gated: bool = False
    # How each field was decided: "spec" (author), "rules" (rules.yaml) or "suggested" (LLM
    # or heuristic, needs user confirmation). Filled by annotate.py.
    annotation: dict[str, str] = Field(default_factory=dict)
    confirmed: bool = True


class ServerSpec(BaseModel):
    id: str
    command: str | None = None
    # If untrusted, the text of this server's tool descriptions is itself attacker-influenced
    # (tool-description poisoning); the loader adds an untrusted DataSource for it.
    description_trust: Literal["trusted", "untrusted"] = "trusted"
    tools: list[ToolSpec] = Field(default_factory=list)


class AgentSpec(BaseModel):
    id: str = "agent"
    name: str | None = None


class StackSpec(BaseModel):
    id: str
    name: str | None = None
    source: str = "spec"
    agent: AgentSpec = Field(default_factory=AgentSpec)
    servers: list[ServerSpec]

    @field_validator("id")
    @classmethod
    def _safe_id(cls, v: str) -> str:
        import re

        if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", v):
            raise ValueError("stack id may only contain letters, digits, _ . -")
        return v

    def tool_count(self) -> int:
        return sum(len(s.tools) for s in self.servers)
