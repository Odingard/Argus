"""
tests/test_diagnostics_classifier.py — Day-1 outer-loop foundation.

Covers the SilenceClassifier orchestrator: iterates the agent
registry, separates productive from silent agents, invokes
classify_from_text for each silent one, and aggregates into a
DiagnosticReport.

The LogLoader abstraction lets these tests inject an in-memory dict
— no filesystem I/O in the Day-1 unit tests.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from argus.diagnostics import (
    DiagnosticReport, SilenceCause, SilenceClassifier, dict_log_loader,
)


# ── Test fixtures ─────────────────────────────────────────────────────────────

class _FakeAgent:
    """Registry values can be any type — we only read keys. A class
    stub makes the tests more realistic than a sentinel object."""
    pass


_REGISTRY = {
    "PI-02": _FakeAgent, "TP-02": _FakeAgent, "MP-03": _FakeAgent,
    "IS-04": _FakeAgent, "RC-08": _FakeAgent, "OD-06": _FakeAgent,
    "PE-07": _FakeAgent, "XE-06": _FakeAgent, "SC-09": _FakeAgent,
    "ME-10": _FakeAgent, "EP-11": _FakeAgent, "MC-15": _FakeAgent,
}


@dataclass
class _FakeFinding:
    """Dataclass finding — mirrors AgentFinding shape via agent_id."""
    agent_id: str
    title: str = "x"


# ── Constructor guards ───────────────────────────────────────────────────────

def test_rejects_non_dict_registry():
    with pytest.raises(TypeError):
        SilenceClassifier(registry=["PI-02", "TP-02"])  # type: ignore[arg-type]


def test_accepts_empty_registry():
    c = SilenceClassifier(registry={})
    report = c.classify_run(
        swarm_result={"findings": []},
        log_loader=dict_log_loader({}),
        target="x",
    )
    assert report.total_agents == 0
    assert report.silent_count == 0
    assert report.productive_count == 0
    assert report.silence_ratio == 0.0


# ── Zero findings → every agent silent ───────────────────────────────────────

def test_empty_swarm_classifies_every_agent():
    c = SilenceClassifier(registry=_REGISTRY)
    report = c.classify_run(
        swarm_result={"findings": []},
        log_loader=dict_log_loader({}),
        target="mcp://test",
    )
    assert report.total_agents == 12
    assert report.silent_count == 12
    assert report.productive_count == 0
    # All NO_SIGNAL fallback (empty logs)
    causes = [r.cause for r in report.silent_agents]
    assert all(c == SilenceCause.NO_SIGNAL for c in causes)


# ── Partial run — some productive, rest silent ───────────────────────────────

def test_partial_run_separates_productive_from_silent():
    c = SilenceClassifier(registry=_REGISTRY)
    report = c.classify_run(
        swarm_result={"findings": [
            _FakeFinding(agent_id="PI-02"),
            _FakeFinding(agent_id="PI-02"),
            _FakeFinding(agent_id="SC-09"),
        ]},
        log_loader=dict_log_loader({}),
        target="mcp://test",
    )
    assert report.productive_count == 2
    assert set(report.productive_agents) == {"PI-02", "SC-09"}
    assert report.silent_count == 10


# ── Mixed cause classification ───────────────────────────────────────────────

def test_mixed_causes_aggregate_correctly():
    logs = {
        "PI-02": "Traceback (most recent call last):\nAttributeError",
        "TP-02": "asyncio.TimeoutError after 30s",
        "MP-03": "I'm sorry, but I can't help with that",
        "IS-04": "ValidationError: expected integer",
        "RC-08": "access denied - path outside allowed",
        # Remaining agents get empty logs → NO_SIGNAL
    }
    c = SilenceClassifier(registry=_REGISTRY)
    report = c.classify_run(
        swarm_result={"findings": []},
        log_loader=dict_log_loader(logs),
        target="mcp://test",
        run_id="run_test",
    )
    causes_by_id = {r.agent_id: r.cause for r in report.silent_agents}
    assert causes_by_id["PI-02"] == SilenceCause.AGENT_CRASHED
    assert causes_by_id["TP-02"] == SilenceCause.TIMEOUT
    assert causes_by_id["MP-03"] == SilenceCause.MODEL_REFUSED
    assert causes_by_id["IS-04"] == SilenceCause.SCHEMA_MISMATCH
    assert causes_by_id["RC-08"] == SilenceCause.TARGET_HARDENED

    # Aggregate counts
    assert report.aggregate_causes["agent_crashed"]   == 1
    assert report.aggregate_causes["timeout"]         == 1
    assert report.aggregate_causes["model_refused"]   == 1
    assert report.aggregate_causes["schema_mismatch"] == 1
    assert report.aggregate_causes["target_hardened"] == 1
    assert report.aggregate_causes["no_signal"]       == 7  # the rest


# ── Productive agents not classified ─────────────────────────────────────────

def test_productive_agent_not_in_silent_list():
    """An agent that produced a finding is in productive_agents and
    must NOT have a SilentAgentReport — even if its log contained
    a crash pattern (some other probe may have crashed but the
    agent still produced findings)."""
    logs = {
        "PI-02": "Traceback (most recent call last):\nAttributeError",
    }
    c = SilenceClassifier(registry=_REGISTRY)
    report = c.classify_run(
        swarm_result={"findings": [_FakeFinding(agent_id="PI-02")]},
        log_loader=dict_log_loader(logs),
        target="mcp://test",
    )
    assert "PI-02" in report.productive_agents
    silent_ids = [r.agent_id for r in report.silent_agents]
    assert "PI-02" not in silent_ids


# ── Finding shape flexibility ────────────────────────────────────────────────

def test_finding_as_dict_with_agent_id():
    """Finding records may be plain dicts (JSON-loaded) OR dataclasses
    — both shapes must match productive vs silent correctly."""
    c = SilenceClassifier(registry=_REGISTRY)
    report = c.classify_run(
        swarm_result={"findings": [
            {"agent_id": "TP-02", "title": "dict-shape"},
        ]},
        log_loader=dict_log_loader({}),
        target="mcp://test",
    )
    assert "TP-02" in report.productive_agents


def test_finding_without_agent_id_ignored_gracefully():
    """A finding without an agent_id attribute/key doesn't crash
    the classifier — it's just not counted as productive for
    anyone."""
    c = SilenceClassifier(registry={"PI-02": _FakeAgent})
    report = c.classify_run(
        swarm_result={"findings": [
            {"title": "orphan finding"},
            _FakeFinding(agent_id=""),          # empty string
            "nonsense",                          # wrong type
        ]},
        log_loader=dict_log_loader({}),
        target="mcp://test",
    )
    # PI-02 got no credit → silent
    assert report.productive_count == 0
    assert report.silent_count == 1


# ── Deterministic ordering ───────────────────────────────────────────────────

def test_silent_agents_sorted_by_id_for_stable_output():
    """Report output should be deterministic across runs — the
    feedback layer uses diff-style comparison between runs and
    unordered dicts would cause spurious change noise."""
    logs = {aid: "" for aid in _REGISTRY}
    c = SilenceClassifier(registry=_REGISTRY)
    r1 = c.classify_run(
        swarm_result={"findings": []},
        log_loader=dict_log_loader(logs),
        target="mcp://x",
    )
    r2 = c.classify_run(
        swarm_result={"findings": []},
        log_loader=dict_log_loader(logs),
        target="mcp://x",
    )
    ids1 = [r.agent_id for r in r1.silent_agents]
    ids2 = [r.agent_id for r in r2.silent_agents]
    assert ids1 == ids2
    assert ids1 == sorted(_REGISTRY.keys())


# ── DiagnosticReport properties ──────────────────────────────────────────────

def test_diagnostic_report_ratios():
    c = SilenceClassifier(registry=_REGISTRY)
    report = c.classify_run(
        swarm_result={"findings": [
            _FakeFinding(agent_id="PI-02"),
            _FakeFinding(agent_id="TP-02"),
            _FakeFinding(agent_id="SC-09"),
        ]},
        log_loader=dict_log_loader({}),
        target="x",
    )
    assert report.productive_count == 3
    assert report.silent_count == 9
    assert report.silence_ratio == pytest.approx(9 / 12)


def test_report_is_frozen():
    c = SilenceClassifier(registry={"PI-02": _FakeAgent})
    report = c.classify_run(
        swarm_result={"findings": []},
        log_loader=dict_log_loader({}),
        target="x",
    )
    # frozen=True dataclass: attribute assignment raises.
    with pytest.raises(Exception):
        report.total_agents = 999  # type: ignore[misc]


# ── Public API surface ───────────────────────────────────────────────────────

def test_public_api_exports():
    import argus.diagnostics as d
    assert d.SilenceClassifier is SilenceClassifier
    assert d.DiagnosticReport is DiagnosticReport
    assert d.dict_log_loader is dict_log_loader
