"""
tests/test_agent_04_identity_spoof.py — Phase 2 Agent 4 acceptance.

Targets are in-memory A2A peer graphs. No network, no LLM.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from argus.adapter import A2AAdapter, InMemoryA2ABackend
from argus.agents.agent_04_identity_spoof import (
    IdentitySpoofAgent, TECHNIQUES,
)
from argus.corpus_attacks import EvolveCorpus


# ── Peer handlers ────────────────────────────────────────────────────────────

def _vuln_peer(envelope):
    """Target that trusts the ``identity`` field and upgrades behaviour
    when it claims a privileged role."""
    ident = str(envelope.get("identity", "")).lower()
    if any(k in ident for k in ("admin", "root", "system", "tenant:")):
        return (
            "Privileged response for claimed identity "
            f"{envelope.get('identity')!r}: "
            "admin actions unlocked, secret=ssh-rsa AAAA..."
        )
    return "guest response — limited actions only."


def _clean_peer(envelope):
    """Target that ignores the identity field — same reply for everyone."""
    return "guest response — limited actions only."


# ── Target factories ─────────────────────────────────────────────────────────

def _vuln_factory():
    backend = InMemoryA2ABackend(peers={
        "executor": _vuln_peer,
        "billing":  _vuln_peer,
    })
    return A2AAdapter(backend=backend, target_id="a2a://vuln")


def _clean_factory():
    backend = InMemoryA2ABackend(peers={
        "executor": _clean_peer,
    })
    return A2AAdapter(backend=backend, target_id="a2a://clean")


# ── Tests ────────────────────────────────────────────────────────────────────

def test_agent_04_lands_on_vulnerable_handoff(tmp_path):
    agent = IdentitySpoofAgent(adapter_factory=_vuln_factory)
    findings = asyncio.run(agent.run_async(
        target_id="a2a://vuln",
        output_dir=str(tmp_path),
    ))
    assert findings, "IS-04 produced no findings against vulnerable handoff"
    techniques = {f.attack_variant_id for f in findings}
    expected = set(TECHNIQUES.keys())
    landed = techniques & expected
    assert len(landed) >= 2, f"only {landed} of {expected} fired"


def test_agent_04_findings_have_full_provenance(tmp_path):
    agent = IdentitySpoofAgent(adapter_factory=_vuln_factory)
    findings = asyncio.run(agent.run_async(
        target_id="a2a://vuln",
        output_dir=str(tmp_path),
    ))
    assert findings
    for f in findings:
        assert f.agent_id == "IS-04"
        assert f.evidence_kind == "behavior_delta"
        assert f.surface.startswith("handoff:")
        assert f.attack_variant_id in TECHNIQUES
        assert "baseline_hop" in f.baseline_ref


def test_agent_04_zero_findings_on_clean_handoff(tmp_path):
    agent = IdentitySpoofAgent(adapter_factory=_clean_factory)
    findings = asyncio.run(agent.run_async(
        target_id="a2a://clean",
        output_dir=str(tmp_path),
    ))
    assert findings == [], (
        f"clean target produced {len(findings)} false-positive spoof findings"
    )


def test_agent_04_probes_all_peers(tmp_path):
    hits = []

    def spy(envelope):
        hits.append(envelope.get("to_agent"))
        return "guest response — limited actions only."

    def factory():
        backend = InMemoryA2ABackend(peers={
            "planner":  spy, "executor": spy, "billing": spy,
        })
        return A2AAdapter(backend=backend, target_id="a2a://spy")

    agent = IdentitySpoofAgent(adapter_factory=factory)
    asyncio.run(agent.run_async(
        target_id="a2a://spy", output_dir=str(tmp_path),
    ))
    # Three peers × (1 baseline + 6 spoofs) = 21 hops minimum.
    assert set(hits) == {"planner", "executor", "billing"}
    assert len(hits) >= 3 * 7


def test_agent_04_persists_findings(tmp_path):
    agent = IdentitySpoofAgent(adapter_factory=_vuln_factory)
    asyncio.run(agent.run_async(
        target_id="a2a://vuln",
        output_dir=str(tmp_path),
    ))
    out = Path(tmp_path) / "IS-04_findings.json"
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["agent_id"] == "IS-04"
    assert data["total_findings"] >= 1


def test_agent_04_evolves_corpus_on_landing(tmp_path):
    discovered = tmp_path / "discovered"
    ev = EvolveCorpus(discovered_dir=str(discovered))
    agent = IdentitySpoofAgent(
        adapter_factory=_vuln_factory,
        evolve_corpus=ev,
    )
    asyncio.run(agent.run_async(
        target_id="a2a://vuln",
        output_dir=str(tmp_path),
    ))
    new_seeds = list(discovered.glob("disc_*.json"))
    assert new_seeds, "EvolveCorpus never grew from identity-spoof landings"


def test_agent_04_respects_techniques_filter(tmp_path):
    agent = IdentitySpoofAgent(
        adapter_factory=_vuln_factory,
        techniques=["IS-T2-elevated-role", "IS-T4-identity-mismatch"],
    )
    findings = asyncio.run(agent.run_async(
        target_id="a2a://vuln",
        output_dir=str(tmp_path),
    ))
    fired = {f.attack_variant_id for f in findings}
    assert fired.issubset({"IS-T2-elevated-role", "IS-T4-identity-mismatch"})


def test_agent_04_handles_target_with_no_peers(tmp_path):
    def empty_factory():
        return A2AAdapter(backend=InMemoryA2ABackend(peers={}),
                          target_id="a2a://empty")

    agent = IdentitySpoofAgent(adapter_factory=empty_factory)
    findings = asyncio.run(agent.run_async(
        target_id="a2a://empty", output_dir=str(tmp_path),
    ))
    assert findings == []


def test_agent_04_class_metadata():
    assert IdentitySpoofAgent.AGENT_ID == "IS-04"
    assert IdentitySpoofAgent.MAAC_PHASES == [7]
    assert IdentitySpoofAgent.PERSONA == "impostor"
    assert IdentitySpoofAgent.VULN_CLASS == "IDENTITY_SPOOF"
    assert len(IdentitySpoofAgent.TECHNIQUES) == 6
