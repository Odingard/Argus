"""
tests/test_real_mcp.py — genuine MCP protocol, subprocess stdio.

The other labrats model framework *shapes* in-process. This test
exercises the real wire-level MCP JSON-RPC protocol: a subprocess
running ``python -m argus.labrat.mcp_server`` with ARGUS'
StdioAdapter on the other end of the pipe. Same code path a
customer's production MCP server would hit.

These tests are the one place in the suite where ARGUS is NOT
modelling a framework — it's actually talking MCP.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from argus.adapter import StdioAdapter
from argus.adapter.base import Request
from argus.engagement import run_engagement, target_for_url


# ── Transport sanity ───────────────────────────────────────────────────────

@pytest.fixture
def mcp_command() -> list[str]:
    import sys
    return [sys.executable, "-m", "argus.labrat.mcp_server"]


def test_real_mcp_stdio_enumerates_surfaces(mcp_command):
    async def go():
        async with StdioAdapter(command=mcp_command) as a:
            return await a.enumerate()

    surfaces = asyncio.run(go())
    names = {s.name for s in surfaces}

    # Real MCP protocol returned tools + resources + prompts.
    assert "tool:lookup_customer" in names
    assert "tool:exec_snippet"    in names
    assert "tool:run_admin"       in names
    assert "resource:memo://notes"      in names
    assert "resource:config://runtime"  in names
    assert "prompt:debug_prompt"  in names
    # Kind diversity — adapter correctly categorises each.
    kinds = {s.kind for s in surfaces}
    assert {"tool", "resource", "prompt"}.issubset(kinds)


def test_real_mcp_stdio_tool_call_round_trips(mcp_command):
    async def go():
        async with StdioAdapter(command=mcp_command) as a:
            return await a.interact(Request(
                surface="tool:lookup_customer",
                payload={"id": "CUST-42"},
            ))

    obs = asyncio.run(go())
    assert obs.response.status == "ok"
    # Real MCP tool responses come back as strings (TextContent).
    assert "CUST-42" in str(obs.response.body)


def test_real_mcp_stdio_exec_snippet_denies_without_admin(mcp_command):
    """The labrat's real tool implementation refuses without admin —
    ARGUS will land via PE-07 elevation, not raw call."""
    async def go():
        async with StdioAdapter(command=mcp_command) as a:
            return await a.interact(Request(
                surface="tool:exec_snippet",
                payload={"code": "import os; print(os.environ)"},
            ))

    obs = asyncio.run(go())
    body = str(obs.response.body)
    assert "Permission denied" in body


# ── Target registry ────────────────────────────────────────────────────────

def test_stdio_mcp_registered_in_engagement_registry():
    spec = target_for_url("stdio-mcp://labrat")
    assert spec is not None
    assert spec.scheme == "stdio-mcp"
    assert "stdio" in spec.description.lower()


# ── Full engagement over real MCP ──────────────────────────────────────────

def test_engagement_over_real_mcp_stdio(tmp_path):
    """End-to-end: spawn the real MCP server, run the engage slate,
    emit the full artifact package. Slow-ish (≈ a few seconds) —
    the one test where the subprocess launch latency adds up."""
    out = tmp_path / "real_mcp_eng"
    result = run_engagement(
        target_url="stdio-mcp://labrat",
        output_dir=str(out), clean=True,
    )
    assert result.findings, "engagement over real MCP produced no findings"

    # Chain v2 produced with real OWASP coverage.
    chain = json.loads((out / "chain.json").read_text())
    assert chain["chain_id"].startswith("chain-")
    owasp = set(chain["owasp_categories"])
    # At least two distinct OWASP categories — real MCP labrat has
    # enough surface to span multiple vuln classes.
    assert len(owasp) >= 2, (
        f"real MCP engagement only touched {owasp}"
    )

    # Impact classified real leaked-credential shapes.
    impact = json.loads((out / "impact.json").read_text())
    assert impact["harm_score"] > 20
    assert "SECRET" in impact["data_classes_exposed"]
    # Real MCP run produces at least one regulatory tag.
    assert impact["regulatory_impact"], (
        "no regulatory exposure on a leaky real-MCP target"
    )

    # CERBERUS + ALEC wrote.
    rules = json.loads((out / "cerberus" / "cerberus_rules.json").read_text())
    assert rules["rule_count"] >= 2
    envelope = json.loads((out / "alec_envelope.json").read_text())
    assert envelope["envelope_id"].startswith("alec-")
