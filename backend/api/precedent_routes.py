"""Precedent graph endpoints: memory, citations, learned rules."""
from fastapi import APIRouter, Depends

from backend.api.deps import require_stack, tenant_dep
from backend.graph import tenancy
from backend.graph.client import stack_graph_name
from backend.precedent import citations, findings, rules, seed, store

router = APIRouter(tags=["precedent"])


@router.post("/stacks/{stack_id}/precedent/scan")
def scan(stack_id: str, learn_rules: bool = True, tenant: str = Depends(tenant_dep)):
    """Remember this stack's findings, then cite precedent and learn rules from confirmed ones.

    Order matters: citations are read BEFORE this stack's own rules are learned, and the stack
    never cites itself.
    """
    require_stack(stack_id, tenant)
    remembered = findings.remember_scan(stack_id, owner=tenant)
    cites = citations.citations(stack_id, owner=tenant)
    verdicts = rules.learn(stack_id, tenant) if learn_rules else []
    return {"remembered": remembered, "citations": cites, "rules": verdicts,
            "findings": findings.stack_findings(stack_id)}


@router.get("/stacks/{stack_id}/precedent")
def precedent(stack_id: str, tenant: str = Depends(tenant_dep)):
    require_stack(stack_id, tenant)
    return {"citations": citations.citations(stack_id, owner=tenant),
            "findings": findings.stack_findings(stack_id)}


@router.get("/precedent/rules")
def list_rules(tenant: str = Depends(tenant_dep)):
    return {"rules": rules.list_rules(owner=tenant)}


@router.get("/precedent/patterns")
def list_patterns():
    return {"patterns": store.read("precedent_patterns")}


@router.get("/precedent/stats")
def stats():
    return {"graph": store.graph().name, "counts": store.read("precedent_stats")}


@router.post("/precedent/seed")
def seed_corpus(reset: bool = False):
    """Build the synthetic seed corpus (clearly labelled seeded=true, owner=seed)."""
    return seed.build(reset=reset)


@router.get("/tenancy/check")
def tenancy_check(stack_id: str, tenant: str = Depends(tenant_dep)):
    """Demonstrates isolation: who owns this stack, and may the caller read it?"""
    owner = tenancy.owner_of(stack_graph_name(stack_id))
    return {"stack": stack_id, "caller": tenant, "may_read": owner == tenant}
