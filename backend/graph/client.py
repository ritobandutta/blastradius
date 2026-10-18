"""The single FalkorDB access layer.

Every Cypher statement in the product goes through `Graph.query` / `Graph.ro_query`.
There is no in-memory copy of any graph: decisions re-query FalkorDB each time.
If the database is down we raise `GraphUnavailable`, and callers (the Guard) fail closed.
"""
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import redis
from falkordb import FalkorDB

from backend import config

QUERY_DIR = Path(__file__).parent / "queries"
_NAME_RE = re.compile(r"^[A-Za-z0-9_:.\-]{1,128}$")


class GraphUnavailable(RuntimeError):
    """FalkorDB cannot be reached. The Guard treats this as DENY."""


class GraphQueryError(RuntimeError):
    def __init__(self, graph: str, query: str, message: str):
        super().__init__(f"[{graph}] {message}\n--- query ---\n{query.strip()}")
        self.graph = graph
        self.message = message


@dataclass
class Result:
    rows: list[list]
    header: list[str]
    run_time_ms: float  # time FalkorDB spent executing the query
    wall_ms: float  # round trip as seen by the app
    stats: dict = field(default_factory=dict)

    def dicts(self) -> list[dict]:
        return [dict(zip(self.header, row)) for row in self.rows]


@lru_cache(maxsize=1)
def _db() -> FalkorDB:
    # The client connects eagerly, so a dead database fails here, before any query wrapper
    # runs. lru_cache does not cache exceptions, so the next call retries the connection.
    try:
        return FalkorDB(
            host=config.FALKORDB_HOST,
            port=config.FALKORDB_PORT,
            username=config.FALKORDB_USERNAME,
            password=config.FALKORDB_PASSWORD,
        )
    except redis.exceptions.AuthenticationError as e:
        # Reachable but refused: say so, or a wrong password looks like a network outage.
        # Still a GraphUnavailable, so the Guard fails closed either way.
        raise GraphUnavailable(
            f"FalkorDB rejected the credentials for {config.FALKORDB_HOST}:"
            f"{config.FALKORDB_PORT} (check FALKORDB_USERNAME / FALKORDB_PASSWORD): {e}"
        ) from e
    except redis.exceptions.RedisError as e:
        raise GraphUnavailable(f"FalkorDB unreachable: {e}") from e


@lru_cache(maxsize=None)
def load_query(name: str) -> str:
    """Read backend/graph/queries/<name>.cypher, dropping `//` comment lines."""
    text = (QUERY_DIR / f"{name}.cypher").read_text()
    return "\n".join(l for l in text.splitlines() if not l.strip().startswith("//")).strip()


def query_names() -> list[str]:
    return sorted(p.stem for p in QUERY_DIR.glob("*.cypher"))


def list_graphs() -> list[str]:
    try:
        return list(_db().list_graphs())
    except redis.exceptions.RedisError as e:
        raise GraphUnavailable(f"FalkorDB unreachable: {e}") from e


def ping() -> float:
    """Round-trip time in ms; raises GraphUnavailable when the DB is down."""
    t0 = time.perf_counter()
    list_graphs()
    return round((time.perf_counter() - t0) * 1000, 2)


_POOL = ThreadPoolExecutor(max_workers=16, thread_name_prefix="graph")


def parallel(*thunks):
    """Run independent reads side by side and return their results in order.

    Against a remote FalkorDB each query costs a network round trip, so a decision that needs
    several independent facts is much faster when they travel together. Only for queries that
    do not depend on each other. If any raises, the first error is re-raised after all finish.
    """
    futures = [_POOL.submit(t) for t in thunks]
    results, first_error = [], None
    for f in futures:
        try:
            results.append(f.result())
        except Exception as e:  # noqa: BLE001 - re-raised below
            first_error = first_error or e
            results.append(None)
    if first_error:
        raise first_error
    return results


class Graph:
    """A handle bound to exactly one named graph (one tenant, stack or session)."""

    def __init__(self, name: str):
        if not _NAME_RE.match(name):
            raise ValueError(f"invalid graph name: {name!r}")
        self.name = name
        self._g = _db().select_graph(name)

    def _run(self, fn, q: str, params: dict | None) -> Result:
        t0 = time.perf_counter()
        try:
            res = fn(q, params or {})
        except redis.exceptions.ConnectionError as e:
            raise GraphUnavailable(f"FalkorDB unreachable: {e}") from e
        except redis.exceptions.TimeoutError as e:
            raise GraphUnavailable(f"FalkorDB timed out: {e}") from e
        except redis.exceptions.ResponseError as e:
            raise GraphQueryError(self.name, q, str(e)) from e
        wall = (time.perf_counter() - t0) * 1000
        return Result(
            rows=res.result_set,
            header=[h[1] for h in res.header],
            run_time_ms=round(float(res.run_time_ms), 3),
            wall_ms=round(wall, 3),
            stats={
                "nodes_created": res.nodes_created,
                "relationships_created": res.relationships_created,
                "properties_set": res.properties_set,
            },
        )

    def ro_query(self, q: str, params: dict | None = None) -> Result:
        return self._run(self._g.ro_query, q, params)

    def query(self, q: str, params: dict | None = None) -> Result:
        return self._run(self._g.query, q, params)

    def named(self, name: str, params: dict | None = None, write: bool = False) -> Result:
        q = load_query(name)
        return self.query(q, params) if write else self.ro_query(q, params)

    def exists(self) -> bool:
        return self.name in list_graphs()

    def delete(self) -> None:
        if self.exists():
            try:
                self._g.delete()
            except redis.exceptions.ConnectionError as e:
                raise GraphUnavailable(f"FalkorDB unreachable: {e}") from e

    def copy_to(self, new_name: str) -> "Graph":
        if not _NAME_RE.match(new_name):
            raise ValueError(f"invalid graph name: {new_name!r}")
        Graph(new_name).delete()
        try:
            self._g.copy(new_name)
        except redis.exceptions.RedisError as e:
            raise GraphUnavailable(f"FalkorDB copy failed: {e}") from e
        return Graph(new_name)


def graph(name: str) -> Graph:
    return Graph(name)


def stack_graph_name(stack_id: str) -> str:
    return f"stack:{stack_id}"


def session_graph_name(session_id: str) -> str:
    return f"session:{session_id}"
