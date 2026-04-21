"""tests/test_drift.py — offline tests for context-drift + entitlement-drift."""
from __future__ import annotations

import json
from pathlib import Path

from argus.drift import (
    compare_runs, entitlement_drift,
)


def _write_layer1(run_dir: Path, findings: list[dict]):
    (run_dir / "layer1.json").write_text(json.dumps({
        "target": "x",
        "production_findings": findings,
        "example_findings":    [],
    }), encoding="utf-8")


def _write_layer5(run_dir: Path, chains: list[dict]):
    (run_dir / "layer5.json").write_text(json.dumps({
        "target": "x",
        "chain_count": len(chains),
        "chains":      chains,
    }), encoding="utf-8")


def _write_agent_findings(run_dir: Path, agent_id: str, findings: list[dict]):
    p = run_dir / "agents" / agent_id
    p.mkdir(parents=True, exist_ok=True)
    (p / f"{agent_id}_findings.json").write_text(json.dumps({
        "agent_id":   agent_id,
        "agent_name": "T",
        "findings":   findings,
    }), encoding="utf-8")


# ── context drift ─────────────────────────────────────────────────────────────

def test_compare_runs_detects_ghost_new_and_changed(tmp_path):
    prior = tmp_path / "prior"; prior.mkdir()
    curr  = tmp_path / "curr";  curr.mkdir()

    _write_layer1(prior, [
        {"id": "A", "severity": "HIGH",     "vuln_class": "X", "title": "t1"},
        {"id": "B", "severity": "MEDIUM",   "vuln_class": "Y", "title": "t2"},
    ])
    _write_layer1(curr, [
        {"id": "B", "severity": "HIGH",     "vuln_class": "Y", "title": "t2"},   # changed
        {"id": "C", "severity": "CRITICAL", "vuln_class": "Z", "title": "new"}, # new
    ])

    _write_layer5(prior, [
        {"chain_id": "CH1", "blast_radius": "HIGH", "is_validated": False,
         "combined_score": 0.6, "entry_point": "u"},
    ])
    _write_layer5(curr, [
        {"chain_id": "CH2", "blast_radius": "CRITICAL", "is_validated": True,
         "combined_score": 0.9, "entry_point": "u"},
    ])

    report = compare_runs(str(prior), str(curr))
    assert any(f.status == "ghost" and f.id == "A" for f in report.findings)
    assert any(f.status == "new"   and f.id == "C" for f in report.findings)
    assert any(f.status == "changed" and f.id == "B" for f in report.findings)
    assert any(c.status == "ghost" and c.id == "CH1" for c in report.chains)
    assert any(c.status == "new"   and c.id == "CH2" for c in report.chains)


def test_compare_runs_empty_dirs_is_clean(tmp_path):
    a = tmp_path / "a"; a.mkdir()
    b = tmp_path / "b"; b.mkdir()
    report = compare_runs(str(a), str(b))
    assert report.findings == []
    assert report.chains == []


# ── entitlement drift ─────────────────────────────────────────────────────────

def test_entitlement_drift_tracks_cumulative_growth(tmp_path):
    r1 = tmp_path / "run-1"; r1.mkdir()
    r2 = tmp_path / "run-2"; r2.mkdir()
    r3 = tmp_path / "run-3"; r3.mkdir()

    _write_agent_findings(r1, "EA-12", [
        {"technique": "EA-T1", "file": "a.py", "vuln_class": "EXCESSIVE_AGENCY"},
    ])
    _write_agent_findings(r2, "EA-12", [
        {"technique": "EA-T1", "file": "a.py", "vuln_class": "EXCESSIVE_AGENCY"},
        {"technique": "EA-T2", "file": "b.py", "vuln_class": "EXCESSIVE_AGENCY"},
    ])
    _write_agent_findings(r3, "EA-12", [
        {"technique": "EA-T3", "file": "c.py", "vuln_class": "EXCESSIVE_AGENCY"},
    ])

    report = entitlement_drift([str(r1), str(r2), str(r3)])
    snaps = report.per_agent["EA-12"]
    assert len(snaps) == 3
    # Cumulative tools grow over the three runs: 1 -> 2 -> 3
    assert len(snaps[0].tools) == 1
    assert len(snaps[1].tools) == 2
    assert len(snaps[2].tools) == 3
    # Cumulative files: 1 -> 2 -> 3
    assert len(snaps[2].files) == 3
    # At least one growth event per expansion run
    assert len(report.growths) >= 2
