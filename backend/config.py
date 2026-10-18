"""Runtime configuration, read from the environment (and a local .env if present)."""
import os
from pathlib import Path


def _load_dotenv() -> None:
    path = Path(__file__).resolve().parent.parent / ".env"
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
# "mock" forces the deterministic MockLLM even when a key is present (used by the tests).
LLM_MODE = os.getenv("BLASTRADIUS_LLM", "auto")

GUARD_LOCKDOWN_THRESHOLD = int(os.getenv("GUARD_LOCKDOWN_THRESHOLD", "40"))

# The shared graph of findings, patterns, fixes and learned rules. Overridable so tests never
# touch the real one.
PRECEDENT_GRAPH = os.getenv("BLASTRADIUS_PRECEDENT_GRAPH", "precedent")
MAX_PATH_DEPTH = 6
