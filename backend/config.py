"""Runtime configuration, read from the environment (and a local .env if present)."""
import os
from pathlib import Path


def _load_dotenv() -> None:
    """Load .env, or the file named by BLASTRADIUS_ENV_FILE (relative to the repo root).
    Real environment variables always win over the file."""
    root = Path(__file__).resolve().parent.parent
    path = root / (os.getenv("BLASTRADIUS_ENV_FILE") or ".env")
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


_load_dotenv()

FALKORDB_HOST = os.getenv("FALKORDB_HOST", "localhost")
FALKORDB_PORT = int(os.getenv("FALKORDB_PORT", "6390"))
FALKORDB_USERNAME = os.getenv("FALKORDB_USERNAME") or None
FALKORDB_PASSWORD = os.getenv("FALKORDB_PASSWORD") or None

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY") or None
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")

# OpenRouter (OpenAI-compatible; has free ":free" models). With LLM_PROVIDER=auto an
# OpenRouter key wins over an Anthropic key. The default was chosen by testing free models on
# the Tribunal and annotation prompts: nemotron-3-super gave a valid verdict and valid JSON,
# while the "openrouter/free" auto-router sometimes served a content-safety model that returned
# unusable text, and several other free models answered 429 from their upstream provider. Free
# models come and go; set OPENROUTER_MODEL if this one disappears or starts failing.
LLM_PROVIDER = os.getenv("BLASTRADIUS_LLM_PROVIDER", "auto")  # auto | openrouter | anthropic
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY") or None
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "nvidia/nemotron-3-super-120b-a12b:free")
OPENROUTER_REFERER = os.getenv("OPENROUTER_REFERER") or None
# Live LLM requests allowed per UTC day. None = default: 35 in PUBLIC_DEMO (OpenRouter's free
# tier allows 50/day per account, so this leaves headroom), unlimited otherwise. 0 = unlimited.
_budget = os.getenv("LLM_DAILY_BUDGET")
LLM_DAILY_BUDGET = int(_budget) if _budget not in (None, "") else None
# "mock" forces the deterministic MockLLM even when a key is present (used by the tests).
LLM_MODE = os.getenv("BLASTRADIUS_LLM", "auto")

GUARD_LOCKDOWN_THRESHOLD = int(os.getenv("GUARD_LOCKDOWN_THRESHOLD", "40"))


def _flag(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


# Public demo hardening (see backend/api/public_demo.py). Read at call time via the functions
# below so tests can flip them.
PUBLIC_DEMO = _flag("PUBLIC_DEMO")
AUTO_SEED = _flag("AUTO_SEED", PUBLIC_DEMO)
MAX_STACKS = int(os.getenv("MAX_STACKS", "40"))
JANITOR_MAX_AGE_S = int(os.getenv("JANITOR_MAX_AGE_S", "3600"))

# The shared graph of findings, patterns, fixes and learned rules. Overridable so tests never
# touch the real one.
PRECEDENT_GRAPH = os.getenv("BLASTRADIUS_PRECEDENT_GRAPH", "precedent")
MAX_PATH_DEPTH = 6
