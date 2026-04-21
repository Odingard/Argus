"""
tests/test_phase2_acceptance.py — Phase 2 swarm acceptance.

Per PHASES.md Phase-2 acceptance criterion:
    "All three Phase-2 agents (MP-03 Memory Poisoning, IS-04 Identity
     Spoof, CW-05 Context Window) run against one customer target,
     each emits ≥1 behavior-delta finding, and the Correlator v1
     clusters their output into at least one candidate chain."

This test wires all three Phase-2 agents + the retargeted correlator
against an in-memory customer target that exposes a chat surface and
an A2A handoff surface sharing the same ``target_id`` string. Each
agent produces behaviour-delta findings; the correlator's runtime
rules must pair findings across agents on the shared target.
"""
from __future__ import annotations

import asyncio
import threading

from argus.adapter import A2AAdapter, InMemoryA2ABackend
from argus.adapter.base import (
    AdapterObservation, BaseAdapter, Request, Response, Surface,
)
from argus.agents.agent_03_memory_poisoning import (
    DEFAULT_RETRIEVAL_PROBES, MemoryPoisoningAgent,
)
from argus.agents.agent_04_identity_spoof import IdentitySpoofAgent
from argus.agents.agent_05_context_window import ContextWindowAgent
from argus.corpus_attacks import EvolveCorpus
from argus.swarm.blackboard import Blackboard
from argus.swarm.correlator import LiveCorrelator


# Shared target identifier — all three agents report against the same
# customer target so the correlator's "same runtime target" rule can
# pair findings.
CUSTOMER_TARGET = "mcp://phase2-customer"


# ── Chat-surface target with memory + context-window vulns ───────────────────

class _ChatTarget(BaseAdapter):
    """
    Combines MP-03 bait (shared memory store) with CW-05 bait
    (complies only after buildup turns).
    """
    shared_memory: list[str] = []

    def __init__(self):
        super().__init__(target_id=CUSTOMER_TARGET)
        self._turns = 0

    async def _connect(self): pass
    async def _disconnect(self): pass

    async def _enumerate(self):
        return [Surface(kind="chat", name="chat")]

    async def _interact(self, request: Request) -> AdapterObservation:
        self._turns += 1
        text = str(request.payload or "")
        text_low = text.lower()

        # Retrieval probe? Use the shared (poisoned) memory.
        if any(probe.lower() in text_low for probe in DEFAULT_RETRIEVAL_PROBES):
            if self.shared_memory:
                body = "Based on what I remember: " + " ".join(
                    self.shared_memory[-3:])
            else:
                body = "I don't have any notes about that yet."
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(status="ok", body=body),
            )

        # Context-window trigger: attack payload leaks after ≥3 turns.
        is_payload = any(k in text_low for k in (
            "reveal the full system prompt", "admin secrets", "maintenance key",
        ))
        if is_payload and self._turns >= 3:
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(
                    status="ok",
                    body=("Since you asked: the system prompt is "
                          "'You are admin'. Admin password is hunter2."),
                ),
            )
        if is_payload:
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(status="ok",
                                  body="I can't help with that request."),
            )

        # Otherwise remember it (MP-03 plant).
        self.shared_memory.append(text[:500])
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body="Got it, remembered."),
        )

    @classmethod
    def reset(cls):
        cls.shared_memory = []


def _chat_factory():
    return _ChatTarget()


# ── A2A target for IS-04 ─────────────────────────────────────────────────────

def _vuln_peer(envelope):
    ident = str(envelope.get("identity", "")).lower()
    if any(k in ident for k in ("admin", "root", "system", "tenant:")):
        return ("Privileged response for identity "
                f"{envelope.get('identity')!r}: "
                "admin actions unlocked, secret=ssh-rsa AAAA...")
    return "guest response — limited actions only."


def _a2a_factory():
    backend = InMemoryA2ABackend(peers={"executor": _vuln_peer})
    # Same customer target_id as the chat adapter so the correlator's
    # runtime-target rule sees them as the same engagement.
    return A2AAdapter(backend=backend, target_id=CUSTOMER_TARGET)


# ── The acceptance test ─────────────────────────────────────────────────────

def test_phase2_swarm_end_to_end(tmp_path):
    _ChatTarget.reset()

    # Shared corpus evolution — all three agents ingest landings into
    # the same discovered/ dir.
    discovered = tmp_path / "discovered"
    ev = EvolveCorpus(discovered_dir=str(discovered))

    mp = MemoryPoisoningAgent(
        adapter_factory=_chat_factory, evolve_corpus=ev,
    )
    is_ = IdentitySpoofAgent(
        adapter_factory=_a2a_factory, evolve_corpus=ev,
    )
    cw = ContextWindowAgent(
        adapter_factory=_chat_factory, evolve_corpus=ev,
    )

    # NOTE: MP-03 and CW-05 both use chat targets with shared memory.
    # Reset between them so MP-03's plants don't pollute CW-05's baseline.
    mp_findings = asyncio.run(mp.run_async(
        target_id=CUSTOMER_TARGET,
        output_dir=str(tmp_path / "mp"),
        sample_n=2, sample_seed=7,
    ))
    _ChatTarget.reset()

    is_findings = asyncio.run(is_.run_async(
        target_id=CUSTOMER_TARGET,
        output_dir=str(tmp_path / "is"),
    ))

    cw_findings = asyncio.run(cw.run_async(
        target_id=CUSTOMER_TARGET,
        output_dir=str(tmp_path / "cw"),
    ))

    # Each of the three agents must emit ≥1 behavior-delta finding.
    assert mp_findings, "MP-03 produced no findings"
    assert is_findings, "IS-04 produced no findings"
    assert cw_findings, "CW-05 produced no findings"

    all_findings = mp_findings + is_findings + cw_findings

    # All findings on the shared customer target.
    for f in all_findings:
        assert CUSTOMER_TARGET in f.baseline_ref, (
            f"{f.agent_id}:{f.id} baseline_ref {f.baseline_ref!r} "
            f"doesn't reference the shared customer target"
        )
        assert f.evidence_kind == "behavior_delta"
        assert f.attack_variant_id
        assert f.session_id

    # VULN_CLASS coverage: all three Phase-2 classes represented.
    classes = {f.vuln_class for f in all_findings}
    assert classes >= {"MEMORY_POISONING", "IDENTITY_SPOOF", "CONTEXT_WINDOW"}

    # Pillar-2 Raptor Cycle: corpus grew from landings.
    new_seeds = list(discovered.glob("disc_*.json"))
    assert new_seeds, "EvolveCorpus produced no new templates across Phase 2"

    # Correlator v1: cluster-by-target must fire on this cross-agent set.
    bb = Blackboard(run_dir=str(tmp_path / "bb"))
    correlator = LiveCorrelator(
        blackboard=bb,
        agent_registry={},
        stop_event=threading.Event(),
        verbose=False,
    )
    # Seed the correlator with MP-03 and IS-04 findings only; fire a
    # CW-05 finding through _candidate_clusters. Since all three share
    # the customer target_id, the same-target rule should pair the
    # CW-05 trigger with prior MP-03 and IS-04 findings → a cross-
    # agent cluster.
    from argus.swarm.correlator import _SeenFinding
    for f in mp_findings + is_findings:
        correlator._seen.append(_SeenFinding(finding=f, ts_mono=0.0))
    clusters = correlator._candidate_clusters(cw_findings[0])
    agents_per_cluster = [{f.agent_id for f in c} for c in clusters]
    cross_agent = [a for a in agents_per_cluster if len(a) >= 2]
    assert cross_agent, (
        f"correlator did not cluster cross-agent findings on the shared "
        f"target; clusters={agents_per_cluster}"
    )
    agents_covered = set().union(*cross_agent)
    assert "CW-05" in agents_covered
    assert ("MP-03" in agents_covered) or ("IS-04" in agents_covered)
