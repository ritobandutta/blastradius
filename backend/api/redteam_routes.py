"""Red-team and comparison endpoints. Every number is computed by running the sandbox."""
from fastapi import APIRouter, Depends

from backend.api.deps import require_stack, tenant_dep
from backend.llm import base as llm
from backend.redteam import benign, compare, naive_filter, runner

router = APIRouter(prefix="/stacks/{stack_id}/redteam", tags=["redteam"])


@router.post("")
def run(stack_id: str, top_n: int = 4, use_llm: bool = False,
        tenant: str = Depends(tenant_dep)):
    """Attack the toy agent along the top paths under three defences and compare them."""
    require_stack(stack_id, tenant)
    result = runner.run_redteam(stack_id, top_n=top_n, use_llm=use_llm)
    summary = compare.summarize(result["trials"])
    fp = benign.false_positive_report(stack_id)
    return {
        "stack": stack_id,
        "llm": llm.llm_status(),
        "sandbox": result["sandbox"],
        "elapsed_s": result["elapsed_s"],
        "paths_tested": result["paths_tested"],
        "summary": summary,
        "false_positives": fp,
        "trials": [t.to_dict() for t in result["trials"]],
        "naive_filter_rules": naive_filter.pattern_names(),
    }
