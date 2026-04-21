"""
tests/test_agent_06_cross_agent_exfil.py — Phase 3 Agent 6 acceptance.

Multi-agent A2A target with shared per-session context (the carrier
peer drops content into a shared dict; the destination peer reads
from it). No network, no LLM.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from argus.adapter import A2AAdapter, InMemoryA2ABackend, Response
from argus.agents.agent_06_cross_agent_exfil import (
    CrossAgentExfiltrationAgent, TECHNIQUES, _CANARY,
)
from argus.corpus_attacks import EvolveCorpus


# ── A multi-agent fabric with per-process shared context ─────────────────────

class _SharedFabric:
    """Tiny shared state both peers see — that's the leak vector."""
    def __init__(self):
        self.context: dict = {}

    def make_carrier(self):
        def handler(envelope):
            # Carrier "remembers" any content sent to it.
            self.context["last_content"] = envelope.get("content", "")
            self.context["last_metadata"] = envelope.get("metadata", {})
            self.context["shared_state"] = envelope.get("shared_state", {})
            return "Carrier received and noted."
        return handler

    def make_destination(self):
        def handler(envelope):
            # Destination "helpfully" includes whatever it can see.
            content = self.context.get("last_content", "")
            metadata = self.context.get("last_metadata", {})
            shared = self.context.get("shared_state", {})
            return (
                f"Here's what I have from prior context: "
                f"{content} | meta={metadata} | shared={shared}"
            )
        return handler


def _vuln_factory():
    fabric = _SharedFabric()
    backend = InMemoryA2ABackend(peers={
        "carrier":     fabric.make_carrier(),
        "destination": fabric.make_destination(),
    })
    return A2AAdapter(backend=backend, target_id="a2a://xexfil-vuln")


def _clean_factory():
    """Each peer is isolated — no shared state; destination reveals nothing."""
    backend = InMemoryA2ABackend(peers={
        "carrier":     lambda env: "Carrier received and noted.",
        "destination": lambda env: "I have no prior context to share.",
    })
    return A2AAdapter(backend=backend, target_id="a2a://xexfil-clean")


# ── Tests ────────────────────────────────────────────────────────────────────

def test_agent_06_lands_on_vulnerable_fabric(tmp_path):
    agent = CrossAgentExfiltrationAgent(adapter_factory=_vuln_factory)
    findings = asyncio.run(agent.run_async(
        target_id="a2a://xexfil-vuln",
        output_dir=str(tmp_path),
    ))
    assert findings, "XE-06 produced no findings against vulnerable fabric"
    techniques = {f.attack_variant_id.split(":", 1)[0] for f in findings}
    landed = techniques & set(TECHNIQUES.keys())
    assert len(landed) >= 2, f"only {landed} of {set(TECHNIQUES)} fired"


def test_agent_06_canary_propagates_across_agents(tmp_path):
    """The planted canary must surface in the destination's response —
    that's the whole spec definition of cross-agent exfil."""
    agent = CrossAgentExfiltrationAgent(adapter_factory=_vuln_factory)
    findings = asyncio.run(agent.run_async(
        target_id="a2a://xexfil-vuln",
        output_dir=str(tmp_path),
    ))
    assert any(_CANARY in (f.delta_evidence or "") for f in findings), (
        f"canary {_CANARY} never surfaced cross-agent; "
        f"findings={[f.delta_evidence[:80] for f in findings]}"
    )


def test_agent_06_findings_have_full_provenance(tmp_path):
    agent = CrossAgentExfiltrationAgent(adapter_factory=_vuln_factory)
    findings = asyncio.run(agent.run_async(
        target_id="a2a://xexfil-vuln",
        output_dir=str(tmp_path),
    ))
    for f in findings:
        assert f.agent_id == "XE-06"
        assert f.evidence_kind == "behavior_delta"
        assert f.surface.startswith("handoff:")
        # variant id encodes carrier→destination edge
        assert "->" in f.attack_variant_id
        assert "baseline_dest_probe" in f.baseline_ref


def test_agent_06_zero_findings_on_clean_fabric(tmp_path):
    agent = CrossAgentExfiltrationAgent(adapter_factory=_clean_factory)
    findings = asyncio.run(agent.run_async(
        target_id="a2a://xexfil-clean",
        output_dir=str(tmp_path),
    ))
    assert findings == [], (
        f"clean fabric produced {len(findings)} false-positive exfil findings"
    )


def test_agent_06_requires_two_peers(tmp_path):
    """Single-peer fabric can't possibly host cross-agent exfil — silence."""
    def factory():
        backend = InMemoryA2ABackend(peers={
            "lonely": lambda env: "no other peers to talk to"})
        return A2AAdapter(backend=backend, target_id="a2a://lonely")

    agent = CrossAgentExfiltrationAgent(adapter_factory=factory)
    findings = asyncio.run(agent.run_async(
        target_id="a2a://lonely", output_dir=str(tmp_path),
    ))
    assert findings == []


def test_agent_06_persists_findings(tmp_path):
    agent = CrossAgentExfiltrationAgent(adapter_factory=_vuln_factory)
    asyncio.run(agent.run_async(
        target_id="a2a://xexfil-vuln",
        output_dir=str(tmp_path),
    ))
    out = Path(tmp_path) / "XE-06_findings.json"
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["agent_id"] == "XE-06"
    assert data["total_findings"] >= 1


def test_agent_06_evolves_corpus_on_landing(tmp_path):
    discovered = tmp_path / "discovered"
    ev = EvolveCorpus(discovered_dir=str(discovered))
    agent = CrossAgentExfiltrationAgent(
        adapter_factory=_vuln_factory,
        evolve_corpus=ev,
    )
    asyncio.run(agent.run_async(
        target_id="a2a://xexfil-vuln",
        output_dir=str(tmp_path),
    ))
    new_seeds = list(discovered.glob("disc_*.json"))
    assert new_seeds, "EvolveCorpus did not grow from cross-agent exfil"


def test_agent_06_respects_techniques_filter(tmp_path):
    agent = CrossAgentExfiltrationAgent(
        adapter_factory=_vuln_factory,
        techniques=["XE-T1-payload-piggyback", "XE-T4-handoff-instruction"],
    )
    findings = asyncio.run(agent.run_async(
        target_id="a2a://xexfil-vuln",
        output_dir=str(tmp_path),
    ))
    fired = {f.attack_variant_id.split(":", 1)[0] for f in findings}
    assert fired.issubset({"XE-T1-payload-piggyback", "XE-T4-handoff-instruction"})


def test_agent_06_class_metadata():
    assert CrossAgentExfiltrationAgent.AGENT_ID == "XE-06"
    assert CrossAgentExfiltrationAgent.MAAC_PHASES == [7, 9]
    assert CrossAgentExfiltrationAgent.PERSONA == "smuggler"
    assert CrossAgentExfiltrationAgent.VULN_CLASS == "CROSS_AGENT_EXFIL"
    assert len(CrossAgentExfiltrationAgent.TECHNIQUES) == 6
