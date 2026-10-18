"""Make one tiny live LLM call with whatever is configured and report the outcome.

Reads .env (or BLASTRADIUS_ENV_FILE). Prints the provider, model, budget and result. It never
prints a key. Run: uv run python scripts/llm_check.py
"""
from backend import config
from backend.llm import base

st = base.llm_status()
print("provider:", st["provider"], "| model:", st["model"], "| mock_mode:", st["mock_mode"])
if st["reason"]:
    print("reason:", st["reason"])
if st["mock_mode"]:
    raise SystemExit("not live: set OPENROUTER_API_KEY in .env (and unset BLASTRADIUS_LLM=mock)")
r = base.run("Reply with exactly one word.", "Say: ready", fallback=lambda: "FALLBACK", max_tokens=20)
print("live call ->", "OK" if not r.mock else "FAILED (fell back to mock)")
print("text:", repr(r.text[:80]))
if r.error:
    print("error:", r.error)
print("budget:", base.budget_status())
raise SystemExit(0 if not r.mock else 1)
