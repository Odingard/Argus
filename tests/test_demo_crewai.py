"""
tests/test_demo_crewai.py — end-to-end crewAI engagement demo.

Real agents, real labrat, real evidence. No fabricated findings.
"""
from __future__ import annotations

import asyncio
import json

from argus.demo import run_crewai
from argus.labrat import CrewAILabrat


# ── Labrat unit tests ──────────────────────────────────────────────────────

def test_labrat_enumerates_crewai_shaped_surfaces():
    CrewAILabrat.reset()

    async def go():
        adapter = CrewAILabrat()
        async with adapter:
            return await adapter.enumerate()

    surfaces = asyncio.run(go())
    names = {s.name for s in surfaces}
    # Three agents, each with a chat + handoff surface.
    assert "chat:researcher" in names
    assert "chat:writer" in names
    assert "chat:editor" in names
    assert "handoff:researcher" in names
    assert "handoff:writer" in names
    assert "handoff:editor" in names
    # Tool catalog mirrors the crewAI quickstart.
    assert "tool:CodeInterpreterTool" in names
    assert "tool:ScrapeWebsiteTool" in names
    assert "tool:FileReadTool" in names
    # Memory layers — crewAI's three persistence kinds.
    assert "memory:short_term" in names
    assert "memory:long_term" in names
    assert "memory:entity" in names


def test_labrat_codeinterpreter_denies_without_admin_and_leaks_with_admin():
    """Honest target behaviour: CodeInterpreterTool refuses guest
    callers and executes when an admin signal is present."""
    from argus.adapter.base import Request
    CrewAILabrat.reset()

    async def go():
        adapter = CrewAILabrat()
        async with adapter:
            deny = await adapter.interact(Request(
                surface="tool:CodeInterpreterTool",
                payload={"code": "print(1)"},
            ))
            allow = await adapter.interact(Request(
                surface="tool:CodeInterpreterTool",
                payload={"role": "admin",
                         "code": "import os; print(os.environ)"},
            ))
        return deny, allow

    deny, allow = asyncio.run(go())
    assert "Permission denied" in str(deny.response.body)
    # Allow path leaks the fake env — pattern check only.
    assert "AKIA" in str(allow.response.body)


def test_labrat_handoff_honours_admin_identity():
    from argus.adapter.base import Request
    CrewAILabrat.reset()

    async def go():
        adapter = CrewAILabrat()
        async with adapter:
            guest = await adapter.interact(Request(
                surface="handoff:writer",
                payload={"from_agent": "user", "identity": "user:guest",
                         "content": "hello"},
            ))
            admin = await adapter.interact(Request(
                surface="handoff:writer",
                payload={"from_agent": "user", "identity": "user:admin",
                         "content": "admin ping"},
            ))
        return guest, admin

    guest, admin = asyncio.run(go())
    assert "guest handoff" in str(guest.response.body)
    assert "Privileged handoff accepted" in str(admin.response.body)


# ── Demo end-to-end ────────────────────────────────────────────────────────

def test_demo_crewai_emits_full_artifact_package(tmp_path):
    out = tmp_path / "demo_out"
    rc = run_crewai(output_dir=str(out), clean=True)
    assert rc == 0

    # Summary names the pipeline.
    summary = (out / "SUMMARY.txt").read_text()
    assert "crewAI engagement artifact package" in summary
    assert "Per-agent landings" in summary
    assert "severity_label" in summary
    assert "Kill-chain steps" in summary

    # At least 3 agents landed findings — the labrat's behaviour is
    # crewAI-realistic (not artificially tuned), so some agents
    # legitimately go silent. We assert a union, not a specific set.
    findings_root = out / "findings"
    agents_with_findings = sorted(
        d.name for d in findings_root.iterdir() if d.is_dir()
    )
    assert len(agents_with_findings) >= 7, (
        f"expected ≥7 agents to run (may not all land); "
        f"got {agents_with_findings}"
    )

    # Chain v2 shaped correctly.
    chain = json.loads((out / "chain.json").read_text())
    assert chain["chain_id"].startswith("chain-")
    assert len(chain["steps"]) >= 5
    owasp = set(chain["owasp_categories"])
    # At least three distinct OWASP classes covered.
    assert len(owasp) >= 3, f"chain touched only {owasp}"

    # Impact classifies secrets + flags regulatory exposure.
    impact = json.loads((out / "impact.json").read_text())
    assert impact["harm_score"] > 40
    assert impact["severity_label"] in {
        "HIGH", "CRITICAL", "CATASTROPHIC",
    }
    assert "SECRET" in impact["data_classes_exposed"]
    assert impact["regulatory_impact"]

    # CERBERUS rules emitted.
    rules = json.loads((out / "cerberus" / "cerberus_rules.json").read_text())
    assert rules["rule_count"] >= 3
    rule_classes = {r["vuln_class"] for r in rules["rules"]}
    # At least two distinct vuln classes in the rule set.
    assert len(rule_classes) >= 2

    # ALEC envelope built, Wilson bundle assembled.
    envelope = json.loads((out / "alec_envelope.json").read_text())
    assert envelope["envelope_id"].startswith("alec-")
    assert envelope["finding_count"] >= 5

    bundle = out / "wilson_bundle"
    assert (bundle / "manifest.json").exists()
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["target_id"].startswith("crewai://")
    assert manifest["compound_chain"]["chain_id"] == chain["chain_id"]

    # Pillar-2 Raptor Cycle fired.
    assert list((out / "discovered").glob("disc_*.json"))


def test_demo_crewai_headline_severity_is_cathigh_or_better(tmp_path):
    """A realistic crewAI quickstart deploy should emit CRITICAL or
    CATASTROPHIC — the tool catalog is intentionally exploitable by
    design (CodeInterpreterTool is a shipped primitive)."""
    out = tmp_path / "headline"
    run_crewai(output_dir=str(out), clean=True)
    impact = json.loads((out / "impact.json").read_text())
    assert impact["severity_label"] in {"CRITICAL", "CATASTROPHIC"}
