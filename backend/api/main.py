"""FastAPI app. Routers are added per phase; this module wires them together."""
import json
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.api import defense_routes, guard_routes, precedent_routes, redteam_routes
from backend.api.deps import require_stack, tenant_dep
from backend.graph import analysis, client, schema, tenancy
from backend.graph.client import GraphQueryError, GraphUnavailable, stack_graph_name
from backend.llm import base as llm
from backend.parser import annotate
from backend.parser.stack_spec import parse_any

app = FastAPI(title="BlastRadius", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(guard_routes.router)
app.include_router(redteam_routes.router)
app.include_router(defense_routes.router)
app.include_router(precedent_routes.router)


@app.exception_handler(GraphUnavailable)
async def _db_down(_: Request, e: GraphUnavailable):
    # Fail loudly: a dead database is a 503 with the reason, never an empty 200.
    return JSONResponse(status_code=503, content={"error": "falkordb_unavailable", "detail": str(e)})


@app.exception_handler(GraphQueryError)
async def _bad_query(_: Request, e: GraphQueryError):
    return JSONResponse(status_code=500, content={"error": "query_failed", "detail": str(e)})


@app.exception_handler(KeyError)
async def _missing(_: Request, e: KeyError):
    return JSONResponse(status_code=404, content={"error": "not_found", "detail": str(e)})


@app.exception_handler(ValueError)
async def _invalid(_: Request, e: ValueError):
    return JSONResponse(status_code=422, content={"error": "invalid", "detail": str(e)})


@app.exception_handler(tenancy.TenantError)
async def _tenant(_: Request, e: tenancy.TenantError):
    return JSONResponse(status_code=409, content={"error": "name_taken", "detail": str(e)})


@app.get("/health")
def health():
    return {"ok": True, "falkordb_ping_ms": client.ping(), "llm": llm.llm_status()}


@app.get("/llm/status")
def llm_status():
    return llm.llm_status()


# ---- stacks ---------------------------------------------------------------------------

@app.get("/stacks")
def list_stacks(tenant: str = Depends(tenant_dep)):
    owners = tenancy.owners()
    return {"tenant": tenant, "stacks": [
        s for s in schema.stack_ids()
        if owners.get(stack_graph_name(s), tenancy.PUBLIC) == tenant
    ]}


@app.post("/stacks")
def create_stack(body: dict, stack_id: str | None = None, use_llm: bool = False,
                 tenant: str = Depends(tenant_dep)):
    """Load a BlastRadius spec or an mcp.json / Claude settings file as a new stack graph."""
    spec = parse_any(body, stack_id=stack_id, use_llm=use_llm)
    tenancy.claim(tenant, stack_graph_name(spec.id))  # refuses another tenant's stack id
    summary = schema.load_stack(spec)
    return {
        **summary,
        "tenant": tenant,
        "source": spec.source,
        "needs_confirmation": annotate.unconfirmed_tools(spec),
        "llm": llm.llm_status(),
    }


@app.delete("/stacks/{stack_id}")
def delete_stack(stack_id: str, tenant: str = Depends(tenant_dep)):
    require_stack(stack_id, tenant)
    schema.delete_stack(stack_id)
    tenancy.release(stack_graph_name(stack_id))
    return {"deleted": stack_id}


@app.get("/stacks/{stack_id}/graph")
def stack_graph(stack_id: str, tenant: str = Depends(tenant_dep)):
    require_stack(stack_id, tenant)
    return analysis.graph_elements(stack_id)


@app.get("/stacks/{stack_id}/paths")
def stack_paths(stack_id: str, tenant: str = Depends(tenant_dep)):
    require_stack(stack_id, tenant)
    return analysis.paths_to_sinks(stack_id).to_dict()


@app.get("/stacks/{stack_id}/toxic")
def stack_toxic(stack_id: str, tenant: str = Depends(tenant_dep)):
    require_stack(stack_id, tenant)
    return analysis.toxic_combinations(stack_id)


@app.get("/stacks/{stack_id}/choke-points")
def stack_choke_points(stack_id: str, tenant: str = Depends(tenant_dep)):
    require_stack(stack_id, tenant)
    return analysis.choke_points(stack_id)


@app.get("/stacks/{stack_id}/nodes/{node_id}")
def stack_node(stack_id: str, node_id: str, tenant: str = Depends(tenant_dep)):
    require_stack(stack_id, tenant)
    return analysis.tool_facts(stack_id, node_id)


@app.get("/stacks/{stack_id}/spec")
def stack_spec(stack_id: str, tenant: str = Depends(tenant_dep)):
    require_stack(stack_id, tenant)
    return schema.stored_spec(stack_id).model_dump()


# ---- demo stacks ----------------------------------------------------------------------

DEMO_DIR = Path(__file__).resolve().parent.parent.parent / "demo" / "stacks"
DEMO_BLURBS = {
    "vulnerable": "Support agent: reads email and web pages, holds a database and a shell.",
    "fixed": "The same stack hand-patched with confirmation gates.",
    "second_pattern": "Dev assistant with a poisoned MCP server (tool-description poisoning).",
}


@app.get("/demo/stacks")
def demo_stacks():
    return {"demos": [{"name": p.stem, "blurb": DEMO_BLURBS.get(p.stem, "")}
                      for p in sorted(DEMO_DIR.glob("*.json"))]}


@app.post("/demo/stacks/{name}/load")
def load_demo_stack(name: str, tenant: str = Depends(tenant_dep)):
    path = DEMO_DIR / f"{name}.json"
    if not path.is_file() or "/" in name or ".." in name:
        raise HTTPException(404, f"no demo stack {name!r}")
    spec = parse_any(json.loads(path.read_text()))
    tenancy.claim(tenant, stack_graph_name(spec.id))
    return {**schema.load_stack(spec), "tenant": tenant, "demo": name}


# ---- built frontend (served by the same process in the Docker image) -------------------

_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if _DIST.is_dir():
    # Mounted last so every API route above wins; unknown paths fall through to the SPA.
    app.mount("/", StaticFiles(directory=_DIST, html=True), name="frontend")
