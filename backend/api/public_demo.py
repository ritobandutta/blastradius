"""Hardening for a public, unauthenticated deployment (PUBLIC_DEMO=true).

The API has no login. On the open internet that would let any visitor wipe the shared memory,
delete other people's stacks, fill the database, or spend the owner's API credits. In PUBLIC_DEMO
mode this module:

  * lets the LLM layer run live only on free OpenRouter models, within a daily request
    budget (see llm/base.py), so no visitor can spend money or exhaust the quota; anything
    else is forced to MOCK MODE
  * blocks the destructive routes (seed reset, deleting a stack)
  * caps the number of stacks, and a janitor deletes old stacks and sessions
  * rate-limits requests per client, with a tighter limit on the expensive routes
  * seeds the precedent memory at startup, because the free FalkorDB tier has no backups and
    can be wiped, then re-seeds on its own if that happens

None of this is authentication. It limits damage; it does not identify anyone. Off by default,
so local development and the tests are unaffected unless they switch it on.
"""
import threading
import time
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse

from backend import config
from backend.graph import client, schema
from backend.graph.client import Graph, GraphQueryError, GraphUnavailable, session_graph_name, \
    stack_graph_name

# (requests, window seconds) per client address
LIMIT_DEFAULT = (240, 60)
LIMIT_EXPENSIVE = (12, 60)
EXPENSIVE = ("/redteam", "/defense/verify", "/precedent/scan", "/precedent/seed", "/diff")
BLOCKED = [
    ("POST", "/precedent/seed", "rebuilding the shared memory"),
]

_hits: dict[tuple[str, str], deque] = defaultdict(deque)
_lock = threading.Lock()


def _client_ip(request: Request) -> str:
    # Behind a proxy (Render) the real address is the first X-Forwarded-For entry.
    fwd = request.headers.get("x-forwarded-for", "")
    return (fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "?"))


def _over_limit(ip: str, bucket: str, limit: tuple[int, int]) -> int | None:
    """Seconds until the caller may retry, or None if under the limit."""
    n, window = limit
    now = time.monotonic()
    with _lock:
        q = _hits[(ip, bucket)]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= n:
            return max(1, int(window - (now - q[0])))
        q.append(now)
    return None


def reset_rate_limits() -> None:
    with _lock:
        _hits.clear()


async def guard_middleware(request: Request, call_next):
    if not config.PUBLIC_DEMO:
        return await call_next(request)
    path, method = request.url.path, request.method

    for m, suffix, what in BLOCKED:
        if method == m and path.endswith(suffix):
            return JSONResponse(status_code=403, content={
                "error": "disabled_in_public_demo",
                "detail": f"{what} is disabled on the public demo. Run it locally for the full API."})
    if method == "DELETE" and path.startswith("/stacks/"):
        return JSONResponse(status_code=403, content={
            "error": "disabled_in_public_demo",
            "detail": "deleting stacks is disabled on the public demo (old stacks expire on their own)"})

    if path.startswith("/health") or not path.startswith(
            ("/stacks", "/guard", "/precedent", "/diff", "/demo", "/tenancy", "/llm")):
        return await call_next(request)  # static UI files and health checks are not limited

    ip = _client_ip(request)
    expensive = method == "POST" and any(path.endswith(s) or s in path for s in EXPENSIVE)
    retry = _over_limit(ip, "expensive" if expensive else "default",
                        LIMIT_EXPENSIVE if expensive else LIMIT_DEFAULT)
    if retry is not None:
        return JSONResponse(status_code=429, headers={"Retry-After": str(retry)}, content={
            "error": "rate_limited", "detail": f"too many requests, retry in {retry}s"})
    return await call_next(request)


def check_capacity() -> None:
    """Refuse a new stack when the demo is full (PUBLIC_DEMO only)."""
    if not config.PUBLIC_DEMO:
        return
    n = len(schema.stack_ids())
    if n >= config.MAX_STACKS:
        raise CapacityError(
            f"the demo is full ({n} stacks). Old stacks expire after "
            f"{config.JANITOR_MAX_AGE_S // 60} minutes; try again shortly.")


class CapacityError(RuntimeError):
    pass


# ---- janitor ----------------------------------------------------------------------------

def sweep() -> dict:
    """Delete session graphs and stack graphs older than JANITOR_MAX_AGE_S.

    Only graphs with a recorded age are touched, so stacks created before ages were recorded,
    the shared `precedent` graph and the `tenants` graph are never deleted.
    """
    cutoff = time.time() - config.JANITOR_MAX_AGE_S
    removed = {"sessions": 0, "stacks": 0}
    for name in client.list_graphs():
        if name.startswith("session:"):
            q, key = "housekeeping_session_age", "sessions"
        elif name.startswith("stack:"):
            q, key = "housekeeping_stack_age", "stacks"
        else:
            continue
        try:
            rows = Graph(name).named(q).dicts()
        except GraphQueryError:
            continue
        created = rows[0]["created"] if rows else None
        if created is not None and created < cutoff:
            Graph(name).delete()
            if key == "stacks":
                from backend.graph import tenancy
                tenancy.release(name)
            removed[key] += 1
    return removed


def start_background(app_state: dict) -> None:
    """Janitor + keep-alive + self-healing seed, in one daemon thread. Never raises."""
    if app_state.get("bg_started"):
        return
    app_state["bg_started"] = True

    def loop():
        from backend.precedent import seed, store
        app_state["seed"] = "pending"
        while True:
            try:
                if config.AUTO_SEED:
                    # Re-seed if the (free, unbacked-up) database was wiped or never seeded.
                    counts = {r["label"]: r["count"] for r in store.read("precedent_stats")}
                    if counts.get("Stack", 0) < 5:
                        t0 = time.time()
                        seed.build()
                        app_state["seed_ms"] = round((time.time() - t0) * 1000)
                    app_state["seed"] = "ready"
                app_state["last_sweep"] = sweep() if config.PUBLIC_DEMO else None
                app_state["last_ok"] = time.time()
                app_state.pop("bg_error", None)
            except GraphUnavailable as e:
                app_state["bg_error"] = f"FalkorDB unavailable: {e}"
            except Exception as e:  # noqa: BLE001 - background work must never take the app down
                app_state["bg_error"] = f"{type(e).__name__}: {e}"
            time.sleep(300)  # every 5 minutes; the query also keeps a free instance from idling

    threading.Thread(target=loop, daemon=True, name="blastradius-background").start()
