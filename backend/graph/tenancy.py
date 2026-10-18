"""Per-tenant isolation.

Physical isolation: every stack is its own FalkorDB graph (`stack:<id>`), every runtime session
its own graph (`session:<id>`). A query is always sent to exactly one named graph, so a query
written for stack A cannot even name a node of stack B.

Logical isolation: a small graph `tenants` records (Tenant)-[:OWNS]->(GraphRef). Every API call
carries a tenant (header `X-Tenant`, default `public`) and `check()` refuses a graph the caller
does not own. Foreign graphs are reported as "not found", so the API is not an existence oracle.
Session graphs carry their tenant on the Session node instead (see guard/decide.py).

What this is not: database-level ACLs. Isolation is enforced by this application layer. A
deployment that needs defence in depth should also give each tenant its own FalkorDB user.
"""
from backend.graph.client import Graph, GraphQueryError

TENANTS_GRAPH = "tenants"
PUBLIC = "public"


class TenantError(PermissionError):
    """The graph exists but belongs to another tenant."""


def _owner(graph_name: str) -> str | None:
    try:
        rows = Graph(TENANTS_GRAPH).named("tenant_owner", {"graph": graph_name}).dicts()
    except GraphQueryError:  # the tenants graph does not exist yet
        return None
    return rows[0]["owner"] if rows else None


def owner_of(graph_name: str) -> str:
    """Graphs created before ownership tracking (or by internal callers) belong to PUBLIC."""
    return _owner(graph_name) or PUBLIC


def check(tenant: str, graph_name: str) -> None:
    if owner_of(graph_name) != tenant:
        raise TenantError(f"graph {graph_name!r} is not owned by tenant {tenant!r}")


def claim(tenant: str, graph_name: str) -> None:
    """Take ownership of a graph name. Refuses if another tenant owns a graph that still exists."""
    owner = _owner(graph_name)
    if owner and owner != tenant and Graph(graph_name).exists():
        raise TenantError(f"graph name {graph_name!r} is already used by another tenant")
    g = Graph(TENANTS_GRAPH)
    g.named("tenant_release", {"graph": graph_name}, write=True)
    g.named("tenant_set_owner", {"tenant": tenant, "graph": graph_name}, write=True)


def release(graph_name: str) -> None:
    try:
        Graph(TENANTS_GRAPH).named("tenant_release", {"graph": graph_name}, write=True)
    except GraphQueryError:
        pass


def owners() -> dict[str, str]:
    try:
        rows = Graph(TENANTS_GRAPH).named("tenant_owners").dicts()
    except GraphQueryError:
        return {}
    return {r["name"]: r["owner"] for r in rows}
