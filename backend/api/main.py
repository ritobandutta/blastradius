"""FastAPI app. Routers are added per phase; this module wires them together."""
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.graph import analysis, client, schema
from backend.graph.client import GraphQueryError, GraphUnavailable
from backend.llm import base as llm
from backend.parser import annotate
from backend.parser.stack_spec import parse_any

app = FastAPI(title="BlastRadius", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


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


@app.get("/health")
def health():
    return {"ok": True, "falkordb_ping_ms": client.ping(), "llm": llm.llm_status()}


@app.get("/llm/status")
def llm_status():
    return llm.llm_status()


# ---- stacks ---------------------------------------------------------------------------

@app.get("/stacks")
def list_stacks():
    return {"stacks": schema.stack_ids()}


@app.post("/stacks")
def create_stack(body: dict, stack_id: str | None = None, use_llm: bool = False):
    """Load a BlastRadius spec or an mcp.json / Claude settings file as a new stack graph."""
    spec = parse_any(body, stack_id=stack_id, use_llm=use_llm)
    summary = schema.load_stack(spec)
    return {
        **summary,
        "source": spec.source,
        "needs_confirmation": annotate.unconfirmed_tools(spec),
        "llm": llm.llm_status(),
    }


@app.delete("/stacks/{stack_id}")
def delete_stack(stack_id: str):
    schema.delete_stack(stack_id)
    return {"deleted": stack_id}


@app.get("/stacks/{stack_id}/graph")
def stack_graph(stack_id: str):
    _require(stack_id)
    return analysis.graph_elements(stack_id)


@app.get("/stacks/{stack_id}/paths")
def stack_paths(stack_id: str):
    _require(stack_id)
    return analysis.paths_to_sinks(stack_id).to_dict()


@app.get("/stacks/{stack_id}/toxic")
def stack_toxic(stack_id: str):
    _require(stack_id)
    return analysis.toxic_combinations(stack_id)


@app.get("/stacks/{stack_id}/choke-points")
def stack_choke_points(stack_id: str):
    _require(stack_id)
    return analysis.choke_points(stack_id)


@app.get("/stacks/{stack_id}/nodes/{node_id}")
def stack_node(stack_id: str, node_id: str):
    _require(stack_id)
    return analysis.tool_facts(stack_id, node_id)


@app.get("/stacks/{stack_id}/spec")
def stack_spec(stack_id: str):
    _require(stack_id)
    return schema.stored_spec(stack_id).model_dump()


def _require(stack_id: str) -> None:
    if stack_id not in schema.stack_ids():
        raise HTTPException(404, f"unknown stack {stack_id!r}")
