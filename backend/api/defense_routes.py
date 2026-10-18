"""Defense graph, proof of absence, remediation and drift endpoints."""
from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.defense import drift, mincut, pr_text, proof
from backend.graph import schema

router = APIRouter(tags=["defense"])


def _require(stack_id: str) -> None:
    if stack_id not in schema.stack_ids():
        raise KeyError(f"unknown stack {stack_id!r}")


class PlanRequest(BaseModel):
    keep_ungated: list[str] = Field(default_factory=list)
    keep_tools: list[str] = Field(default_factory=list)


@router.post("/stacks/{stack_id}/defense/plan")
def plan(stack_id: str, body: PlanRequest | None = None):
    _require(stack_id)
    body = body or PlanRequest()
    return mincut.plan(stack_id, set(body.keep_ungated), set(body.keep_tools)).to_dict()


@router.post("/stacks/{stack_id}/defense/verify")
def verify(stack_id: str, body: PlanRequest | None = None, rerun_redteam: bool = True):
    """Plan the cut, apply it as a new `<id>-patched` stack, re-run the path query on it."""
    _require(stack_id)
    body = body or PlanRequest()
    fp = mincut.plan(stack_id, set(body.keep_ungated), set(body.keep_tools))
    result = proof.verify(stack_id, fp, rerun_redteam=rerun_redteam)
    return {"plan": fp.to_dict(), "proof": result,
            "pr_markdown": pr_text.remediation_markdown(fp, result)}


class DiffRequest(BaseModel):
    old: dict
    new: dict


@router.post("/diff")
def diff(body: DiffRequest):
    d = drift.diff_dicts(body.old, body.new)
    return {**d, "markdown": drift.markdown(d)}
