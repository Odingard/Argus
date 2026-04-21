"""
tests/test_swarm_wilson_ars.py

Contract tests for the swarm runtime, Wilson bundle packager, and ARS
composite scorer. Offline — no API calls, no Docker, no network.
"""
from __future__ import annotations


from argus.shared.ars import score_chain, score_finding, band
from argus.shared.models import ExploitChain, ExploitStep
from argus.swarm.blackboard import Blackboard, ChainHypothesis
from argus.wilson.bundle import build_bundle_for_chain, verify_bundle


# ── Swarm: Blackboard ─────────────────────────────────────────────────────────

def test_blackboard_hot_file_pheromone_accumulates(tmp_path):
    bb = Blackboard(str(tmp_path))
    bb.mark_hot("a.py", reason="one",   posted_by="X", weight=0.5)
    bb.mark_hot("a.py", reason="two",   posted_by="Y", weight=0.7)
    bb.mark_hot("a.py", reason="three", posted_by="Z", weight=0.6)
    hots = bb.hot_files(limit=5)
    assert len(hots) == 1
    assert hots[0].path == "a.py"
    # Weight accumulates above the initial 0.5 as peers reinforce.
    assert hots[0].weight >= 0.7


def test_blackboard_pheromone_capped_at_one(tmp_path):
    bb = Blackboard(str(tmp_path))
    for _ in range(20):
        bb.mark_hot("b.py", reason="repeated", posted_by="X", weight=1.0)
    hots = bb.hot_files(limit=5)
    assert hots[0].weight <= 1.0


def test_blackboard_jsonl_log_is_append_only(tmp_path):
    bb = Blackboard(str(tmp_path))
    bb.mark_hot("x.py", "r", "id", weight=0.4)
    hyp = ChainHypothesis(hypothesis_id="h1", title="t", confidence=0.6)
    bb.post_hypothesis(hyp)
    log = (tmp_path / "swarm_blackboard.jsonl").read_text(encoding="utf-8")
    lines = [ln for ln in log.splitlines() if ln.strip()]
    assert len(lines) >= 2
    kinds = {line.split('"kind":')[1].split(",")[0].strip().strip('"') for line in lines}
    assert "hot_file" in kinds
    assert "hypothesis" in kinds


# ── Wilson bundle ─────────────────────────────────────────────────────────────

def _stub_chain(validated: bool = True) -> ExploitChain:
    return ExploitChain(
        chain_id="CHAIN-TEST",
        title="Test chain",
        component_deviations=["dev-1", "dev-2"],
        steps=[ExploitStep(step=1, action="a", payload="p", achieves="x")],
        poc_code="print('ARGUS_POC_LANDED:test')",
        cvss_estimate="8.1",
        mitre_atlas_ttps=["AML.T0001"],
        owasp_llm_categories=["LLM01"],
        preconditions=["none"],
        blast_radius="HIGH",
        entry_point="unauthenticated",
        combined_score=0.85,
        is_validated=validated,
        validation_output="ARGUS_POC_LANDED:test\n",
    )


def test_wilson_bundle_produces_expected_files(tmp_path):
    chain = _stub_chain()
    bundle = build_bundle_for_chain(chain, str(tmp_path))
    expected = {
        "chain.json", "poc.py", "sandbox_stdout.txt",
        "fingerprint.json", "pheromone.jsonl",
        "rationale.md", "README.md", "manifest.json",
    }
    assert expected.issubset(set(bundle.files))


def test_wilson_bundle_verifies_clean(tmp_path):
    chain = _stub_chain()
    bundle = build_bundle_for_chain(chain, str(tmp_path))
    ok, msg = verify_bundle(bundle.bundle_dir)
    assert ok, msg


def test_wilson_bundle_detects_tampering(tmp_path):
    chain = _stub_chain()
    bundle = build_bundle_for_chain(chain, str(tmp_path))
    # Tamper with the PoC after signing.
    (bundle.bundle_dir / "poc.py").write_text(
        "print('TAMPERED')", encoding="utf-8",
    )
    ok, msg = verify_bundle(bundle.bundle_dir)
    assert not ok
    assert "mismatch" in msg.lower()


def test_wilson_bundle_includes_ars_in_rationale(tmp_path):
    chain = _stub_chain()
    bundle = build_bundle_for_chain(chain, str(tmp_path))
    rationale = (bundle.bundle_dir / "rationale.md").read_text(encoding="utf-8")
    assert "ARS" in rationale
    assert "breakdown" in rationale.lower()


# ── ARS scorer ────────────────────────────────────────────────────────────────

def test_ars_critical_validated_unauth_is_near_max():
    b = score_chain(
        blast_radius="CRITICAL", is_validated=True,
        combined_score=0.95, entry_point="unauthenticated",
        preconditions_count=1,
    )
    assert b.score >= 95
    assert band(b.score) == "CRITICAL"


def test_ars_medium_unvalidated_drops_below_50():
    b = score_chain(
        blast_radius="MEDIUM", is_validated=False,
        combined_score=0.5, entry_point="low_priv",
        preconditions_count=3,
    )
    assert b.score < 50


def test_ars_is_bounded_zero_to_hundred():
    # Extreme values shouldn't blow past 100 or below 0.
    high = score_chain(
        blast_radius="CRITICAL", is_validated=True,
        combined_score=1.0, entry_point="unauthenticated",
        preconditions_count=0, asset_multiplier=1.5,
    )
    low = score_chain(
        blast_radius="LOW", is_validated=False,
        combined_score=0.0, entry_point="authenticated",
        preconditions_count=10, asset_multiplier=0.5,
    )
    assert 0 <= low.score <= 100
    assert 0 <= high.score <= 100


def test_ars_reproducibility_boosts_score():
    a = score_chain(blast_radius="HIGH", is_validated=False,
                    combined_score=0.7, entry_point="unauthenticated")
    b = score_chain(blast_radius="HIGH", is_validated=True,
                    combined_score=0.7, entry_point="unauthenticated")
    assert b.score > a.score
    # Reproducibility is exactly 15 points of the budget.
    assert b.reproducibility - a.reproducibility == 15


def test_ars_finding_scoring_works():
    b = score_finding("HIGH", is_validated=False,
                      confidence=0.8, entry_point="unauthenticated",
                      preconditions_count=1)
    assert b.score > 0
    assert "HIGH" in b.rationale[0]
