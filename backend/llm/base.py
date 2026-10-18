"""LLM access with a loud mock mode.

Rule from the brief: never silently fall back to canned output. Every caller goes through
`run()`, which returns an `LLMResult` that says whether the text is mock output and why.
The API and CLI surface that flag as a MOCK MODE badge.
"""
from dataclasses import dataclass
from typing import Callable

from backend import config

MOCK_MODEL = "mock-deterministic"


class LLMError(RuntimeError):
    pass


@dataclass
class LLMResult:
    text: str
    mock: bool
    model: str
    error: str | None = None  # set when a live call failed and the mock answered instead

    def badge(self) -> dict:
        return {"mock_mode": self.mock, "model": self.model, "llm_error": self.error}


def mock_mode() -> bool:
    # PUBLIC_DEMO forces mock so a visitor can never spend the owner's API credits.
    return config.PUBLIC_DEMO or config.LLM_MODE == "mock" or not config.ANTHROPIC_API_KEY


def llm_status() -> dict:
    mock = mock_mode()
    reason = None
    if mock:
        reason = (
            "PUBLIC_DEMO forces mock so visitors cannot spend API credits" if config.PUBLIC_DEMO
            else "BLASTRADIUS_LLM=mock" if config.LLM_MODE == "mock"
            else "ANTHROPIC_API_KEY not set"
        )
    return {
        "mock_mode": mock,
        "model": MOCK_MODEL if mock else config.ANTHROPIC_MODEL,
        "reason": reason,
    }


def _live_complete(system: str, prompt: str, max_tokens: int) -> str:
    import anthropic

    client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
    try:
        msg = client.messages.create(
            model=config.ANTHROPIC_MODEL,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as e:  # noqa: BLE001 - surfaced to the caller, never swallowed
        raise LLMError(f"{type(e).__name__}: {e}") from e
    return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")


def run(
    system: str,
    prompt: str,
    fallback: Callable[[], str],
    max_tokens: int = 1024,
) -> LLMResult:
    """Ask the LLM; use `fallback` (deterministic) in mock mode or when the live call fails.

    The result always carries `mock` and, on a failed live call, the error text.
    """
    if mock_mode():
        return LLMResult(text=fallback(), mock=True, model=MOCK_MODEL)
    try:
        text = _live_complete(system, prompt, max_tokens)
        return LLMResult(text=text, mock=False, model=config.ANTHROPIC_MODEL)
    except LLMError as e:
        return LLMResult(text=fallback(), mock=True, model=MOCK_MODEL, error=str(e))
