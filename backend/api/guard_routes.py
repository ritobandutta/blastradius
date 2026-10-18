"""HTTP surface of the Guard: POST /guard/check for non-MCP agents, plus the approval queue."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from backend import config
from backend.api.deps import tenant_dep
from backend.graph import tenancy
from backend.graph.client import stack_graph_name
from backend.guard import approvals, decide, taint

router = APIRouter(prefix="/guard", tags=["guard"])


class CheckRequest(BaseModel):
    session: str = Field(pattern=r"^[A-Za-z0-9_.\-]{1,64}$")
    stack: str = Field(pattern=r"^[A-Za-z0-9_.\-]{1,64}$")
    tool: str
    args: dict | None = None
    # If set, an ESCALATE blocks up to this many seconds waiting for a human click.
    wait_seconds: float = Field(default=0, ge=0, le=300)


class ResolveRequest(BaseModel):
    approve: bool


def _own_session(session_id: str, tenant: str) -> dict:
    """The session's stack decides who may see it. A foreign session is reported as missing."""
    view = taint.session_view(session_id)  # KeyError -> 404
    if tenancy.owner_of(stack_graph_name(view["stack"])) != tenant:
        raise KeyError(session_id)
    return view


@router.post("/check")
def guard_check(req: CheckRequest, tenant: str = Depends(tenant_dep)):
    d = decide.check(req.session, req.stack, req.tool, req.args, tenant=tenant)
    body = d.to_dict()
    if d.decision == decide.ESCALATE and req.wait_seconds > 0:
        outcome = approvals.wait_for_resolution(req.session, d.seq, req.wait_seconds)
        body["status"] = outcome
        body["human_outcome"] = outcome
        body["allowed_to_run"] = outcome == "approved"
    else:
        body["allowed_to_run"] = d.decision == decide.ALLOW
    return body


@router.get("/pending")
def pending(tenant: str = Depends(tenant_dep)):
    owners = tenancy.owners()
    return {"pending": [
        p for p in approvals.pending()
        if owners.get(stack_graph_name(p["stack"]), tenancy.PUBLIC) == tenant
    ]}


@router.post("/sessions/{session_id}/events/{seq}/resolve")
def resolve(session_id: str, seq: int, body: ResolveRequest, tenant: str = Depends(tenant_dep)):
    _own_session(session_id, tenant)
    try:
        return approvals.resolve(session_id, seq, body.approve)
    except approvals.ApprovalError as e:
        raise HTTPException(409, str(e)) from e


@router.get("/sessions")
def sessions(tenant: str = Depends(tenant_dep)):
    owners = tenancy.owners()
    mine = []
    for sid in approvals.session_ids():
        try:
            stack = taint.session_view(sid)["stack"]
        except KeyError:
            continue
        if owners.get(stack_graph_name(stack), tenancy.PUBLIC) == tenant:
            mine.append(sid)
    return {"sessions": mine}


@router.get("/sessions/{session_id}")
def session(session_id: str, tenant: str = Depends(tenant_dep)):
    return _own_session(session_id, tenant)


@router.get("/config")
def guard_config():
    from backend.guard import trust

    return {
        "lockdown_threshold": config.GUARD_LOCKDOWN_THRESHOLD,
        "penalties": trust.PENALTY,
        "burst": {"calls": trust.BURST_CALLS, "window_s": trust.BURST_WINDOW},
        "enumeration": {"distinct": trust.ENUM_DISTINCT, "window_s": trust.ENUM_WINDOW},
        "baseline_calls": trust.BASELINE_CALLS,
    }
