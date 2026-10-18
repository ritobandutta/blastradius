"""Shared request dependencies: the calling tenant and stack ownership checks.

The tenant comes from the `X-Tenant` header (default `public`). This is identification, not
authentication: a real deployment puts an API gateway in front that sets the header from a
verified credential. What this layer guarantees is that, given a tenant, no route will read or
change a stack graph that tenant does not own.
"""
import re
from typing import Annotated

from fastapi import Header, HTTPException

from backend.graph import schema, tenancy
from backend.graph.client import stack_graph_name

_TENANT_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,48}$")


def tenant_dep(x_tenant: Annotated[str, Header()] = tenancy.PUBLIC) -> str:
    if not _TENANT_RE.match(x_tenant):
        raise HTTPException(422, "X-Tenant may only contain letters, digits, _ . -")
    if x_tenant == "seed":
        raise HTTPException(403, "tenant 'seed' is reserved for the shared synthetic corpus")
    return x_tenant


Tenant = Annotated[str, "tenant"]


def require_stack(stack_id: str, tenant: str) -> None:
    """404 if the stack does not exist OR belongs to another tenant (no existence oracle)."""
    if stack_id not in schema.stack_ids() or \
            tenancy.owner_of(stack_graph_name(stack_id)) != tenant:
        raise HTTPException(404, f"unknown stack {stack_id!r}")
