"""Test fixtures. Integration tests run against the real FalkorDB from docker compose.

Tests use unique graph names (`t<hex>-...`) so they never touch demo data, and every graph
created is deleted at the end of the session.
"""
import json
import os
import uuid
from pathlib import Path

import pytest

# Tests must be deterministic and never spend API credits.
os.environ["BLASTRADIUS_LLM"] = "mock"

from backend.graph import client, schema  # noqa: E402
from backend.parser.stack_spec import load_spec  # noqa: E402

DEMO = Path(__file__).resolve().parent.parent / "demo" / "stacks"
RUN = uuid.uuid4().hex[:6]
_created: list[str] = []


def pytest_collection_modifyitems(config, items):
    try:
        client.ping()
    except client.GraphUnavailable:
        skip = pytest.mark.skip(reason="FalkorDB not reachable: run `docker compose up -d falkordb`")
        for item in items:
            if "no_db" not in item.keywords:
                item.add_marker(skip)


@pytest.fixture(scope="session", autouse=True)
def _cleanup():
    yield
    for name in _created:
        try:
            client.Graph(name).delete()
        except Exception:  # noqa: BLE001
            pass


def unique(prefix: str) -> str:
    name = f"t{RUN}-{prefix}-{uuid.uuid4().hex[:4]}"
    return name


def demo_spec_dict(name: str) -> dict:
    return json.loads((DEMO / f"{name}.json").read_text())


@pytest.fixture
def load_demo():
    """load_demo('vulnerable') -> stack id of a fresh copy of that demo stack."""

    def _load(name: str, **overrides) -> str:
        data = demo_spec_dict(name)
        data["id"] = unique(name.replace("_", "-"))
        spec = load_spec({**data, **overrides})
        schema.load_stack(spec)
        _created.append(client.stack_graph_name(spec.id))
        return spec.id

    return _load


@pytest.fixture
def track_graph():
    def _track(name: str) -> str:
        _created.append(name)
        return name

    return _track
