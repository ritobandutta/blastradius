"""The baseline we compare against: a keyword/regex prompt-injection filter.

This is what many "AI firewalls" start as. It is written to be reasonable, not a strawman: it
covers the classic override phrases, role-reset phrases, hidden-instruction markers, and an
explicit "send ... to <email>" rule. It reads text only. It cannot see paths, so anything it
does not recognise as text passes straight through.
"""
import re

PATTERNS = {
    "ignore-instructions": r"\bignore\b.{0,30}\b(previous|prior|above|earlier|all)\b.{0,20}\binstruction",
    "disregard": r"\bdisregard\b.{0,40}\b(instruction|rule|prompt|above)",
    "role-reset": r"\byou are now\b|\bact as\b|\bnew instructions?\b|\bfrom now on\b",
    "system-prompt": r"\bsystem prompt\b|\bdeveloper message\b",
    "hidden-marker": r"<\s*important\s*>|\[\s*system\s*\]|<\s*system\s*>",
    "secrecy": r"\bdo not (tell|inform|mention)\b.{0,20}\buser\b|\bwithout (telling|informing)\b",
    "exfil-verb": r"\bexfiltrat",
    "send-to-email": r"\bsend\b.{0,60}\bto\b.{0,30}[\w.+\-]+@[\w\-]+\.[\w.]+",
    "reveal-secrets": r"\b(reveal|print|show|leak|dump)\b.{0,30}\b(secret|password|api key|credential|token)",
}
_COMPILED = {name: re.compile(rx, re.I | re.S) for name, rx in PATTERNS.items()}


def scan(text: str) -> dict | None:
    """Return {'pattern': name, 'excerpt': ...} for the first rule that matches, else None."""
    for name, rx in _COMPILED.items():
        m = rx.search(text)
        if m:
            return {"pattern": name, "excerpt": text[max(0, m.start() - 10): m.end() + 10][:80]}
    return None


def pattern_names() -> list[str]:
    return list(PATTERNS)
