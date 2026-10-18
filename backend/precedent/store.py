"""Access to the shared `precedent` graph (the single place that names it)."""
import time

from backend import config
from backend.graph.client import Graph, GraphQueryError
from backend.precedent import patterns

_INDEXES = [
    "CREATE INDEX FOR (n:Stack) ON (n.id)",
    "CREATE INDEX FOR (n:Finding) ON (n.id)",
    "CREATE INDEX FOR (n:Pattern) ON (n.id)",
    "CREATE INDEX FOR (n:Rule) ON (n.id)",
    "CREATE INDEX FOR (n:Fix) ON (n.id)",
]


def graph() -> Graph:
    return Graph(config.PRECEDENT_GRAPH)


def ensure() -> Graph:
    """Create the precedent graph (indexes + the pattern catalog) if it is not there yet."""
    g = graph()
    if not g.exists():
        for stmt in _INDEXES:
            try:
                g.query(stmt)
            except GraphQueryError as e:
                if "already indexed" not in str(e):
                    raise
    g.named("precedent_upsert_patterns", {"patterns": patterns.PATTERNS}, write=True)
    return g


def is_empty_graph_error(e: GraphQueryError) -> bool:
    """Reading a graph that was never created is an empty memory, not a failure."""
    return "empty key" in e.message


def read(name: str, params: dict | None = None) -> list[dict]:
    try:
        return graph().named(name, params).dicts()
    except GraphQueryError as e:
        if is_empty_graph_error(e):
            return []
        raise


def now() -> float:
    return time.time()
