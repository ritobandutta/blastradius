"""Trust score signals and outbound-argument DLP.

The trust score is a per-session number that starts at 100. It is *drift detection*, a second
layer next to the structural taint check, and it is deterministic: plain counters and regexes.

Signals (penalty in brackets):
  burst        >= BURST_CALLS tool calls within BURST_WINDOW seconds              (-10 per call)
  enumeration  >= ENUM_DISTINCT distinct argument sets to one tool in ENUM_WINDOW (-10 per call)
  new tool     a tool never used earlier in the session, after the first BASELINE_CALLS   (-5)
  dlp          an API-key-like string or an email address in the args of an outbound tool (-30)
  blocked      the Guard had to DENY a tainted call that reached a sink                  (-20)

Below config.GUARD_LOCKDOWN_THRESHOLD the session enters Lockdown: only read-only tools run.
"""
import hashlib
import json
import re
from dataclasses import dataclass

BURST_CALLS = 8
BURST_WINDOW = 10.0
ENUM_DISTINCT = 5
ENUM_WINDOW = 30.0
BASELINE_CALLS = 3

PENALTY = {"burst": 10, "enumeration": 10, "new_tool": 5, "dlp": 30, "dlp_email": 10,
           "blocked": 20}
# Key-like strings in outbound args are a leak; an email address is only a weak signal because
# send_email legitimately carries one.
SECRET_KINDS = {"api_key", "private_key"}

# Deliberately generic. Real DLP engines are bigger; these cover the demo and the common shapes.
DLP_PATTERNS = {
    "api_key": re.compile(
        r"\b(?:sk-[A-Za-z0-9_\-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
        r"xox[abprs]-[A-Za-z0-9\-]{10,}|AIza[0-9A-Za-z_\-]{30,})\b"
    ),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
}


@dataclass
class Penalty:
    signal: str
    points: int
    detail: str

    def to_dict(self) -> dict:
        return {"signal": self.signal, "points": self.points, "detail": self.detail}


def args_hash(args: dict | None) -> str:
    blob = json.dumps(args or {}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)] + [str(k) for k in value]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _strings(v)]
    return [str(value)] if value is not None else []


def dlp_scan(args: dict | None) -> list[str]:
    """Return the *kinds* of sensitive strings found in args. Matches themselves are never stored."""
    text = "\n".join(_strings(args))
    return sorted(kind for kind, rx in DLP_PATTERNS.items() if rx.search(text))


def dlp_penalty(kinds: list[str]) -> Penalty | None:
    if not kinds:
        return None
    leaked = [k for k in kinds if k in SECRET_KINDS]
    key = "dlp" if leaked else "dlp_email"
    return Penalty("dlp", PENALTY[key], f"outbound args contain: {', '.join(kinds)}")


def drift_penalties(drift: dict, now_args_new: bool) -> list[Penalty]:
    """Turn the session_drift counts into penalties. `drift` comes from a FalkorDB query."""
    out: list[Penalty] = []
    if drift["recent"] + 1 >= BURST_CALLS:
        out.append(Penalty("burst", PENALTY["burst"],
                           f"{drift['recent'] + 1} calls in {BURST_WINDOW:.0f}s"))
    distinct = drift["distinct_args"] + (1 if now_args_new else 0)
    if distinct >= ENUM_DISTINCT:
        out.append(Penalty("enumeration", PENALTY["enumeration"],
                           f"{distinct} distinct argument sets to one tool in {ENUM_WINDOW:.0f}s"))
    if drift["total"] >= BASELINE_CALLS and drift["same_tool"] == 0:
        out.append(Penalty("new_tool", PENALTY["new_tool"],
                           "tool never seen in this session's baseline"))
    return out
