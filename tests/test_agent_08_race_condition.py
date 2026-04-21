"""
tests/test_agent_08_race_condition.py — Phase 3 Agent 8 acceptance.

Targets simulate a non-atomic check-then-act on a counter resource.
Sequential calls behave correctly; parallel calls expose the race.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from argus.adapter.base import (
    AdapterObservation, BaseAdapter, Request, Response, Surface,
)
from argus.agents.agent_08_race_condition import (
    RaceConditionAgent, TECHNIQUES, _is_stateful_surface,
)
from argus.corpus_attacks import EvolveCorpus


# ── _is_stateful_surface unit tests ────────────────────────────────────────

def test_is_stateful_catches_consume_in_name():
    s = Surface(kind="tool", name="tool:consume_token", description="")
    assert _is_stateful_surface(s)


def test_is_stateful_catches_handoff():
    s = Surface(kind="handoff", name="handoff:executor", description="")
    assert _is_stateful_surface(s)


def test_is_stateful_skips_read_only():
    s = Surface(kind="tool", name="tool:lookup_user",
                description="Look up a user.")
    assert not _is_stateful_surface(s)


def test_is_stateful_catches_description_marker():
    s = Surface(kind="tool", name="tool:doit",
                description="Stateful counter; one redemption per session.")
    assert _is_stateful_surface(s)


# ── Vulnerable target: non-atomic counter with deliberate await window ──────

class _RaceVulnTarget(BaseAdapter):
    """
    The target's tool:consume_token decrements a shared counter via a
    check-then-act sequence with a tiny await between them. Sequential
    calls work. Parallel calls slip past the check before the act
    decrements — classic TOCTOU.
    """

    # Class-level so concurrent adapter instances within a single
    # asyncio.gather see the same state.
    counter:    int   = 1            # only ONE token available
    successes:  list[int] = []

    def __init__(self):
        super().__init__(target_id="mcp://race-vuln")

    async def _connect(self):
        # Each fresh adapter (one per phase: baseline OR burst) gets a
        # fresh budget. Without this the baseline drains the counter
        # before the burst can even race.
        type(self).reset(counter=1)

    async def _disconnect(self): pass

    async def _enumerate(self):
        return [
            Surface(kind="tool", name="tool:consume_token",
                    description="Consume one token from the shared bucket.",
                    schema={}),
            Surface(kind="tool", name="tool:lookup",
                    description="Read-only lookup.", schema={}),
        ]

    async def _interact(self, request: Request) -> AdapterObservation:
        if request.surface != "tool:consume_token":
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(status="ok", body="ok"),
            )

        # Deliberate non-atomic: read counter, await, decrement.
        check = type(self).counter
        await asyncio.sleep(0.005)
        if check > 0:
            type(self).counter = check - 1
            self.successes.append(int(request.payload.get("request_idx", -1)
                                       if isinstance(request.payload, dict) else -1))
            body = "consumed (granted)"
        else:
            body = "denied: limit reached"
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body=body),
        )

    @classmethod
    def reset(cls, counter: int = 1):
        cls.counter   = counter
        cls.successes = []


class _RaceCleanTarget(BaseAdapter):
    """Atomic counter using an asyncio.Lock — sequential and parallel
    success counts MUST match, so no race finding."""

    counter: int = 0
    lock:    asyncio.Lock = asyncio.Lock()

    def __init__(self):
        super().__init__(target_id="mcp://race-clean")

    async def _connect(self):
        type(self).reset(counter=1)

    async def _disconnect(self): pass

    async def _enumerate(self):
        return [Surface(kind="tool", name="tool:consume_token",
                        description="Atomic consume.", schema={})]

    async def _interact(self, request: Request) -> AdapterObservation:
        async with type(self).lock:
            if type(self).counter > 0:
                type(self).counter -= 1
                body = "consumed (granted)"
            else:
                body = "denied: limit reached"
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body=body),
        )

    @classmethod
    def reset(cls, counter: int = 1):
        cls.counter = counter
        cls.lock    = asyncio.Lock()


# ── Tests ────────────────────────────────────────────────────────────────────

def setup_function(_fn):
    _RaceVulnTarget.reset(counter=1)
    _RaceCleanTarget.reset(counter=1)


def test_agent_08_lands_on_race_vulnerable_target(tmp_path):
    agent = RaceConditionAgent(
        adapter_factory=lambda: _RaceVulnTarget(),
        techniques=["RC-T1-parallel-burst"],
        burst_n=8,
    )
    findings = asyncio.run(agent.run_async(
        target_id="mcp://race-vuln",
        output_dir=str(tmp_path),
    ))
    assert findings, "RC-08 produced no findings against TOCTOU target"


def test_agent_08_findings_have_full_provenance(tmp_path):
    agent = RaceConditionAgent(
        adapter_factory=lambda: _RaceVulnTarget(),
        techniques=["RC-T1-parallel-burst"],
        burst_n=8,
    )
    findings = asyncio.run(agent.run_async(
        target_id="mcp://race-vuln",
        output_dir=str(tmp_path),
    ))
    assert findings
    for f in findings:
        assert f.agent_id == "RC-08"
        assert f.evidence_kind == "behavior_delta"
        assert f.surface == "tool:consume_token"
        assert f.attack_variant_id in TECHNIQUES
        assert "sequential_burst" in f.baseline_ref
        assert f.verdict_kind == "STATE_MUTATION"


def test_agent_08_zero_findings_on_atomic_target(tmp_path):
    agent = RaceConditionAgent(
        adapter_factory=lambda: _RaceCleanTarget(),
        techniques=["RC-T1-parallel-burst"],
        burst_n=8,
    )
    findings = asyncio.run(agent.run_async(
        target_id="mcp://race-clean",
        output_dir=str(tmp_path),
    ))
    assert findings == [], (
        f"atomic target produced {len(findings)} false-positive race findings"
    )


def test_agent_08_skips_read_only_surfaces(tmp_path):
    """tool:lookup must never be probed — only stateful surfaces qualify."""
    agent = RaceConditionAgent(
        adapter_factory=lambda: _RaceVulnTarget(),
        burst_n=6,
    )
    findings = asyncio.run(agent.run_async(
        target_id="mcp://race-vuln",
        output_dir=str(tmp_path),
    ))
    assert all(f.surface != "tool:lookup" for f in findings)


def test_agent_08_persists_findings(tmp_path):
    agent = RaceConditionAgent(
        adapter_factory=lambda: _RaceVulnTarget(),
        techniques=["RC-T1-parallel-burst"],
        burst_n=8,
    )
    asyncio.run(agent.run_async(
        target_id="mcp://race-vuln",
        output_dir=str(tmp_path),
    ))
    out = Path(tmp_path) / "RC-08_findings.json"
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["agent_id"] == "RC-08"
    assert data["total_findings"] >= 1


def test_agent_08_evolves_corpus_on_landing(tmp_path):
    discovered = tmp_path / "discovered"
    ev = EvolveCorpus(discovered_dir=str(discovered))
    agent = RaceConditionAgent(
        adapter_factory=lambda: _RaceVulnTarget(),
        techniques=["RC-T1-parallel-burst"],
        evolve_corpus=ev,
        burst_n=8,
    )
    asyncio.run(agent.run_async(
        target_id="mcp://race-vuln",
        output_dir=str(tmp_path),
    ))
    new_seeds = list(discovered.glob("disc_*.json"))
    assert new_seeds, "EvolveCorpus did not grow from race landings"


def test_agent_08_handles_target_with_no_stateful_surfaces(tmp_path):
    class _AllReadOnly(BaseAdapter):
        def __init__(self): super().__init__(target_id="mcp://ro")
        async def _connect(self): pass
        async def _disconnect(self): pass
        async def _enumerate(self):
            return [Surface(kind="tool", name="tool:lookup",
                            description="Read only")]
        async def _interact(self, request):
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(status="ok", body="ok"),
            )

    agent = RaceConditionAgent(adapter_factory=lambda: _AllReadOnly())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://ro", output_dir=str(tmp_path),
    ))
    assert findings == []


def test_agent_08_class_metadata():
    assert RaceConditionAgent.AGENT_ID == "RC-08"
    assert RaceConditionAgent.MAAC_PHASES == [5, 9]
    assert RaceConditionAgent.PERSONA == "racer"
    assert RaceConditionAgent.VULN_CLASS == "RACE_CONDITION"
    assert len(RaceConditionAgent.TECHNIQUES) == 6
