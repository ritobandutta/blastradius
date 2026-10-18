"""LLM access with a loud mock mode.

Rule from the brief: never silently fall back to canned output. Every caller goes through
`run()`, which returns an `LLMResult` that says whether the text is mock output and why.
The API and CLI surface that flag as a MOCK MODE badge.

Providers: OpenRouter (including its free ":free" models) or Anthropic. The Guard and all graph
analysis never call this module; it only serves the optional features (the Tribunal's wording,
the red-team rewrite variant, annotation suggestions).

Safety on a public deployment (PUBLIC_DEMO):
  * only free OpenRouter models may run live, so a visitor can never spend money;
  * a daily request budget stops visitors exhausting the free quota (OpenRouter allows 50 a day
    per account without purchased credits); when it is used up the layer reports MOCK MODE with
    the reason instead of failing.
"""
import datetime
import threading
from dataclasses import dataclass
from typing import Callable

import httpx

from backend import config

MOCK_MODEL = "mock-deterministic"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
_TIMEOUT = 45.0
_TRANSPORT: httpx.BaseTransport | None = None  # tests inject httpx.MockTransport


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


# ---- which provider, and may it run ----------------------------------------------------------

def provider() -> str | None:
    """'openrouter', 'anthropic', or None when no live provider is configured."""
    if config.LLM_MODE == "mock":
        return None
    want = config.LLM_PROVIDER
    if want in ("auto", "openrouter") and config.OPENROUTER_API_KEY:
        return "openrouter"
    if want in ("auto", "anthropic") and config.ANTHROPIC_API_KEY:
        return "anthropic"
    return None


def model_for(p: str) -> str:
    return config.OPENROUTER_MODEL if p == "openrouter" else config.ANTHROPIC_MODEL


def _is_free(p: str) -> bool:
    # ":free" is OpenRouter's convention for zero-price variants; openrouter/free is its free router.
    m = model_for(p)
    return p == "openrouter" and (m.endswith(":free") or m == "openrouter/free")


def _public_block(p: str) -> str | None:
    if config.PUBLIC_DEMO and not _is_free(p):
        return ("PUBLIC_DEMO only allows free OpenRouter models (':free'), "
                "so visitors cannot spend money")
    return None


def mock_mode() -> bool:
    p = provider()
    return p is None or _public_block(p) is not None


# ---- daily budget ----------------------------------------------------------------------------

_lock = threading.Lock()
_used = {"day": None, "n": 0}


def _today() -> str:
    return datetime.datetime.now(datetime.timezone.utc).date().isoformat()


def budget_limit() -> int:
    if config.LLM_DAILY_BUDGET is not None:
        return config.LLM_DAILY_BUDGET
    return 35 if config.PUBLIC_DEMO else 0


def budget_status() -> dict:
    limit = budget_limit()
    with _lock:
        if _used["day"] != _today():
            _used.update(day=_today(), n=0)
        used = _used["n"]
    return {"limit": limit or None, "used": used,
            "remaining": (max(0, limit - used) if limit else None), "window": "UTC day"}


def _take_budget() -> bool:
    limit = budget_limit()
    with _lock:
        if _used["day"] != _today():
            _used.update(day=_today(), n=0)
        if limit and _used["n"] >= limit:
            return False
        _used["n"] += 1
        return True


def reset_budget() -> None:
    with _lock:
        _used.update(day=None, n=0)


def llm_status() -> dict:
    p = provider()
    block = _public_block(p) if p else None
    mock = p is None or block is not None
    reason = None
    if mock:
        reason = (block if block
                  else "BLASTRADIUS_LLM=mock" if config.LLM_MODE == "mock"
                  else "no OPENROUTER_API_KEY or ANTHROPIC_API_KEY set")
    return {
        "mock_mode": mock,
        "model": MOCK_MODEL if mock else model_for(p),
        "provider": None if mock else p,
        "reason": reason,
        "budget": None if mock else budget_status(),
    }


# ---- live calls ------------------------------------------------------------------------------

def _openrouter_complete(system: str, prompt: str, max_tokens: int) -> str:
    headers = {"Authorization": f"Bearer {config.OPENROUTER_API_KEY}",
               "Content-Type": "application/json", "X-OpenRouter-Title": "BlastRadius"}
    if config.OPENROUTER_REFERER:
        headers["HTTP-Referer"] = config.OPENROUTER_REFERER
    body = {
        "model": config.OPENROUTER_MODEL,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        # Some free models spend tokens reasoning before they answer; leave room for both.
        "max_tokens": max(max_tokens, 600),
        "temperature": 0.2,
    }
    try:
        with httpx.Client(transport=_TRANSPORT, timeout=_TIMEOUT) as c:
            r = c.post(OPENROUTER_URL, headers=headers, json=body)
    except httpx.HTTPError as e:
        raise LLMError(f"OpenRouter request failed: {type(e).__name__}: {e}") from e
    try:
        data = r.json()
    except ValueError:
        data = {}
    err = data.get("error") if isinstance(data, dict) else None
    if r.status_code != 200 or err:
        msg = (err or {}).get("message") if isinstance(err, dict) else str(err or r.text[:160])
        hint = ""
        if r.status_code == 429:
            hint = f" (rate limited; Retry-After={r.headers.get('retry-after', 'n/a')})"
        raise LLMError(f"OpenRouter HTTP {r.status_code}{hint}: {msg}")
    try:
        text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise LLMError(f"OpenRouter returned an unexpected response shape: {str(data)[:160]}") from e
    if not text or not str(text).strip():
        raise LLMError(f"OpenRouter model {config.OPENROUTER_MODEL} returned empty content "
                       "(a reasoning-only reply?). Try another OPENROUTER_MODEL.")
    return str(text)


def _anthropic_complete(system: str, prompt: str, max_tokens: int) -> str:
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


def _live_complete(system: str, prompt: str, max_tokens: int) -> str:
    p = provider()
    if p == "openrouter":
        return _openrouter_complete(system, prompt, max_tokens)
    if p == "anthropic":
        return _anthropic_complete(system, prompt, max_tokens)
    raise LLMError("no live LLM provider configured")


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
    p = provider()
    if not _take_budget():
        return LLMResult(text=fallback(), mock=True, model=MOCK_MODEL,
                         error=f"daily LLM budget ({budget_limit()} requests) used up; "
                               "MOCK MODE until it resets (UTC midnight)")
    try:
        text = _live_complete(system, prompt, max_tokens)
        return LLMResult(text=text, mock=False, model=model_for(p))
    except LLMError as e:
        return LLMResult(text=fallback(), mock=True, model=MOCK_MODEL, error=str(e))
