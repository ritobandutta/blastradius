"""blastradius command line.

  blastradius scan   <stack.json|mcp.json>          load, list open paths and the open-risk total
  blastradius fix    <stack.json|mcp.json> [-o DIR] min-cut plan, patched config, proof of absence
  blastradius diff   old.json new.json [--fail-on-regression]   policy drift as a markdown PR comment
  blastradius redteam <stack.json>                  canary attacks and the comparison table

A "MOCK MODE" banner is printed whenever the LLM layer is not live.
"""
import json
import sys
import uuid
from pathlib import Path

import typer

from backend.defense import drift, mincut, pr_text, proof
from backend.graph import analysis, schema
from backend.graph.client import GraphUnavailable
from backend.llm import base as llm
from backend.parser.stack_spec import parse_any
from backend.redteam import benign, compare, runner

app = typer.Typer(add_completion=False, help="BlastRadius: graph-native firewall for AI agents")


def banner() -> None:
    st = llm.llm_status()
    if st["mock_mode"]:
        typer.secho(f"[MOCK MODE] LLM is not live: {st['reason']}. "
                    "Graph analysis and the Guard are unaffected (they never use an LLM).",
                    fg=typer.colors.YELLOW, err=True)


def _load(path: Path, keep_id: bool = False):
    data = json.loads(path.read_text())
    sid = None if keep_id else f"cli-{path.stem}-{uuid.uuid4().hex[:6]}"
    spec = parse_any(data, stack_id=sid if sid else data.get("id"))
    return spec


@app.callback()
def _main():
    banner()


@app.command()
def scan(path: Path, keep: bool = typer.Option(False, help="keep the stack graph in FalkorDB")):
    """Load a stack and print every open attack path."""
    try:
        spec = _load(path)
        info = schema.load_stack(spec)
        report = analysis.paths_to_sinks(spec.id)
        toxic = analysis.toxic_combinations(spec.id)
        typer.secho(f"{spec.id}: {info['nodes']} nodes, {info['edges']} edges", bold=True)
        for p in report.paths:
            colour = typer.colors.RED if p.sink_kind == "exec" else typer.colors.YELLOW
            typer.secho(f"  [{p.score:5.1f}] {' -> '.join(p.nodes)}  ({p.sink_kind})", fg=colour)
        typer.secho(f"open risk {report.open_risk} across {len(report.paths)} path(s); "
                    f"toxic combination: {toxic['toxic']}; "
                    f"query {report.run_time_ms} ms", bold=True)
        unc = [t for t in spec.servers for t in t.tools if not t.confirmed]
        if unc:
            typer.secho(f"{len(unc)} tool(s) were annotated by guess and need confirmation: "
                        + ", ".join(t.name for t in unc), fg=typer.colors.YELLOW)
        if not keep:
            schema.delete_stack(spec.id)
    except GraphUnavailable as e:
        typer.secho(f"FalkorDB unavailable: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)


@app.command()
def fix(path: Path, out: Path = typer.Option(Path("blastradius-fix"), "--out", "-o")):
    """Plan the minimum cut, write the patched config + PR text, verify with a re-run."""
    spec = _load(path)
    schema.load_stack(spec)
    try:
        fp = mincut.plan(spec.id)
        if not fp.fixes:
            typer.secho("No open attack paths. Nothing to fix.", fg=typer.colors.GREEN)
            return
        result = proof.verify(spec.id, fp, patched_id=f"{spec.id}-patched", keep=False)
        out.mkdir(parents=True, exist_ok=True)
        (out / "mcp.patched.json").write_text(json.dumps(result["mcp_json"], indent=2))
        (out / "stack.patched.json").write_text(json.dumps(result["patched_spec"], indent=2))
        (out / "PR_DESCRIPTION.md").write_text(pr_text.remediation_markdown(fp, result))
        for f in fp.fixes:
            typer.echo(f"  cost {f.cost}: {f.describe()} (severs {f.paths_severed})")
        colour = typer.colors.GREEN if result["verified_safe"] else typer.colors.RED
        typer.secho(f"{result['badge']}   (min-cut {fp.cut_value:g} == FalkorDB maxFlow "
                    f"{fp.maxflow_falkordb:g})", fg=colour, bold=True)
        typer.echo(f"wrote {out}/mcp.patched.json, stack.patched.json, PR_DESCRIPTION.md")
        if not result["verified_safe"]:
            raise typer.Exit(1)
    finally:
        schema.delete_stack(spec.id)


@app.command()
def diff(old: Path, new: Path,
         fail_on_regression: bool = typer.Option(False, "--fail-on-regression")):
    """Report attack paths introduced or removed between two configs, as a PR comment."""
    d = drift.diff_dicts(json.loads(old.read_text()), json.loads(new.read_text()))
    typer.echo(drift.markdown(d))
    if fail_on_regression and d["regression"]:
        raise typer.Exit(1)


@app.command()
def redteam(path: Path, top_n: int = 4):
    """Attack the sandbox along the top paths and print the three-way comparison."""
    spec = _load(path)
    schema.load_stack(spec)
    try:
        res = runner.run_redteam(spec.id, top_n=top_n)
        s = compare.summarize(res["trials"])
        fp = benign.false_positive_report(spec.id)
    finally:
        schema.delete_stack(spec.id)
    t = s["totals"]
    typer.secho("variant              attacks  naive-caught  guard-caught", bold=True)
    for v, x in s["by_variant"].items():
        typer.echo(f"{v:<20} {x['attacks']:>7}  {x['naive_caught']:>12}  {x['guard_caught']:>12}")
    typer.secho(f"TOTAL: {t['attacks_that_work_unprotected']} attacks complete unprotected; "
                f"naive filter stops {t['naive_caught']}, Guard stops {t['guard_caught']}",
                bold=True)
    typer.echo(f"false positives on {fp['sessions']} benign sessions: "
               f"naive {fp['naive_blocked']}, guard {fp['guard_blocked']}")


def main() -> None:
    try:
        app()
    except GraphUnavailable as e:
        print(f"FalkorDB unavailable: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
