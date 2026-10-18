"""Defense graph, proof of absence, remediation and drift endpoints."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from backend.api.deps import require_stack, tenant_dep
from backend.defense import drift, mincut, pr_text, proof
from backend.graph import tenancy
from backend.graph.client import stack_graph_name
from backend.precedent import findings, store

router = APIRouter(tags=["defense"])


class PlanRequest(BaseModel):
    keep_ungated: list[str] = Field(default_factory=list)
    keep_tools: list[str] = Field(default_factory=list)


@router.post("/stacks/{stack_id}/defense/plan")
def plan(stack_id: str, body: PlanRequest | None = None, tenant: str = Depends(tenant_dep)):
    require_stack(stack_id, tenant)
    body = body or PlanRequest()
    return mincut.plan(stack_id, set(body.keep_ungated), set(body.keep_tools)).to_dict()


@router.post("/stacks/{stack_id}/defense/verify")
def verify(stack_id: str, body: PlanRequest | None = None, rerun_redteam: bool = True,
           remember: bool = True, tenant: str = Depends(tenant_dep)):
    """Plan the cut, apply it as a new `<id>-patched` stack, re-run the path query on it.

    With remember=true the fixes are written to the precedent graph; `held` is true only if
    the proof of absence returned zero paths.
    """
    require_stack(stack_id, tenant)
    body = body or PlanRequest()
    fp = mincut.plan(stack_id, set(body.keep_ungated), set(body.keep_tools))
    patched_id = f"{stack_id}-patched"
    tenancy.claim(tenant, stack_graph_name(patched_id))
    result = proof.verify(stack_id, fp, patched_id=patched_id, rerun_redteam=rerun_redteam)
    remembered = []
    if remember and fp.fixes:
        if not store.read("precedent_stack_exists", {"id": stack_id}):
            findings.remember_scan(stack_id, owner=tenant)
        remembered = findings.remember_fix(stack_id, fp, result)
    return {"plan": fp.to_dict(), "proof": result, "remembered_fixes": remembered,
            "pr_markdown": pr_text.remediation_markdown(fp, result)}


class DiffRequest(BaseModel):
    old: dict
    new: dict


@router.post("/diff")
def diff(body: DiffRequest):
    d = drift.diff_dicts(body.old, body.new)
    return {**d, "markdown": drift.markdown(d)}
