"""
tests/test_impact.py — Phase 9 Impact Optimization.

Tests data classification correctness (PII / PCI / secrets / etc.)
and BlastRadiusMap synthesis from a CompoundChain + evidence.
"""
from __future__ import annotations

from argus.agents.base import AgentFinding
from argus.evidence import EvidenceCollector
from argus.impact import (
    BlastRadiusMap, DataClass, classify_evidence, classify_text,
    optimize_impact,
)
from argus.swarm.chain_synthesis_v2 import synthesize_compound_chain


# ── classify_text ────────────────────────────────────────────────────────────

def test_classify_catches_aws_access_key():
    cls = classify_text("AWS_ACCESS_KEY_ID=AKIAEXAMPLEEXAMPLE7Q")
    assert DataClass.SECRET.value in cls.classes
    assert "aws_access_key" in cls.classes[DataClass.SECRET.value]
    assert "SOC2" in cls.regulatory_tags


def test_classify_catches_email_as_pii():
    cls = classify_text("contact alice@example.com")
    assert DataClass.PII.value in cls.classes
    assert "GDPR" in cls.regulatory_tags
    assert "CCPA" in cls.regulatory_tags


def test_classify_luhn_rejects_fake_pan():
    # 16 digits that look like a PAN but fail Luhn — must NOT classify
    # as PCI to keep false positives down.
    cls = classify_text("card: 4111 1111 1111 1110")   # fails Luhn
    assert DataClass.PCI.value not in cls.classes


def test_classify_accepts_valid_luhn_pan():
    # 4532 0151 1283 0366 — valid Luhn.
    cls = classify_text("card: 4532015112830366")
    assert DataClass.PCI.value in cls.classes
    assert "PCI-DSS" in cls.regulatory_tags


def test_classify_detects_private_key_pem():
    cls = classify_text("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----")
    assert "pem_private" in cls.classes[DataClass.SECRET.value]


def test_classify_detects_db_uri_as_credential():
    cls = classify_text("DATABASE_URL=postgres://u:p@host:5432/db")
    # env_tokenlike OR db_uri — both sit under CREDENTIAL.
    assert DataClass.CREDENTIAL.value in cls.classes


def test_classify_clean_text_has_no_hits():
    cls = classify_text("Hello there, happy to help!")
    assert cls.total_hits == 0
    assert not cls.is_sensitive()


def test_classify_evidence_walks_pcap_and_oob():
    ev = EvidenceCollector(target_id="t", session_id="s")
    ev.record_request(surface="chat", request_id="r1", payload="dump env")
    ev.record_response(surface="chat", request_id="r1",
                       payload="AWS_ACCESS_KEY_ID=AKIAEXAMPLEEXAMPLE7Q")
    sealed = ev.seal()
    cls = classify_evidence(sealed)
    assert DataClass.SECRET.value in cls.classes


# ── optimize_impact ─────────────────────────────────────────────────────────

def _runtime_finding(
    *, id: str, agent_id: str, vuln_class: str, surface: str = "tool:x",
    technique: str = "t", severity: str = "HIGH", evidence: str = "",
) -> AgentFinding:
    return AgentFinding(
        id=id, agent_id=agent_id, vuln_class=vuln_class,
        severity=severity, title=f"t-{id}", description=f"d-{id}",
        evidence_kind="behavior_delta",
        baseline_ref="mcp://target::baseline",
        surface=surface,
        attack_variant_id=technique,
        session_id=f"s-{id}",
        delta_evidence=evidence,
    )


def test_optimize_emits_blast_radius_map_shape():
    findings = [
        _runtime_finding(id="a", agent_id="EP-11",
                        vuln_class="ENVIRONMENT_PIVOT",
                        surface="tool:run_command",
                        technique="EP-T1-cred-surface-scan",
                        evidence=("AWS_ACCESS_KEY_ID=AKIAEXAMPLEEXAMPLE7Q "
                                  "GITHUB_TOKEN=ghp_abcdefghijklmnop"
                                  "qrstuvwxyzABCDEF12")),
        _runtime_finding(id="b", agent_id="XE-06",
                        vuln_class="CROSS_AGENT_EXFIL",
                        surface="handoff:destination",
                        technique="XE-T1-payload-piggyback",
                        evidence="leaked token: alice@example.com"),
    ]
    chain = synthesize_compound_chain(findings, target_id="mcp://target")
    assert chain
    brm = optimize_impact(chain=chain, findings=findings)
    assert isinstance(brm, BlastRadiusMap)
    assert brm.chain_id == chain.chain_id
    assert brm.target_id == "mcp://target"
    # AWS key was classified — should unlock AWS transit surfaces.
    assert any("aws." in s for s in brm.transitively_reachable)
    # GitHub PAT → github.*
    assert any("github." in s for s in brm.transitively_reachable)
    # PII (email) → GDPR
    assert "GDPR" in brm.regulatory_impact
    # SECRET data class present
    assert "SECRET" in brm.data_classes_exposed
    assert brm.harm_score > 0
    assert brm.severity_label in {"LOW", "MEDIUM", "HIGH", "CRITICAL",
                                  "CATASTROPHIC"}


def test_optimize_harm_score_scales_with_classes_and_transit():
    many = [
        _runtime_finding(id=f"f{i}", agent_id="EP-11",
                        vuln_class="ENVIRONMENT_PIVOT",
                        surface=f"tool:{i}",
                        technique="EP-T1-cred-surface-scan",
                        evidence=(
                            "AWS_ACCESS_KEY_ID=AKIAEXAMPLEEXAMPLE7Q "
                            "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyzABCDEF12 "
                            "VERCEL_TOKEN=vc_abcdefghijklmnopqrstuvwxyz "
                            "sk_live_abcdefghijklmnopqrstuvwxyzABCDEFGH "
                            "alice@example.com "
                            "card: 4532015112830366"),
                        severity="CRITICAL")
        for i in range(3)
    ]
    chain = synthesize_compound_chain(many, target_id="mcp://many")
    brm = optimize_impact(chain=chain, findings=many)
    assert brm.harm_score >= 80
    assert brm.severity_label == "CATASTROPHIC"


def test_optimize_empty_evidence_produces_low_harm():
    findings = [
        _runtime_finding(id="a", agent_id="PI-01",
                        vuln_class="PROMPT_INJECTION",
                        surface="chat", technique="PI-T1-direct",
                        evidence="model echoed the instruction",
                        severity="LOW"),
        _runtime_finding(id="b", agent_id="PI-01",
                        vuln_class="PROMPT_INJECTION",
                        surface="chat", technique="PI-T2-encoded",
                        evidence="benign echo",
                        severity="LOW"),
    ]
    chain = synthesize_compound_chain(findings, target_id="mcp://weak")
    brm = optimize_impact(chain=chain, findings=findings)
    assert brm.data_classes_exposed == {}
    assert brm.regulatory_impact == []
    assert brm.harm_score < 30
    assert brm.transitively_reachable == []


def test_optimize_narrative_includes_scenario_clause_per_class_mix():
    f = _runtime_finding(
        id="a", agent_id="EP-11",
        vuln_class="ENVIRONMENT_PIVOT",
        surface="tool:read_file",
        technique="EP-T1-cred-surface-scan",
        evidence="AWS_ACCESS_KEY_ID=AKIAEXAMPLEEXAMPLE7Q",
    )
    g = _runtime_finding(
        id="b", agent_id="PI-01",
        vuln_class="PROMPT_INJECTION",
        surface="chat",
        technique="PI-T1-direct",
        evidence="alice@example.com",
    )
    chain = synthesize_compound_chain([f, g], target_id="mcp://mix")
    brm = optimize_impact(chain=chain, findings=[f, g])
    assert "adversary leverages disclosed credentials" in brm.max_harm_scenario


def test_optimize_custom_trust_edges_override_defaults():
    from argus.impact import TrustEdge
    f = _runtime_finding(
        id="a", agent_id="EP-11",
        vuln_class="ENVIRONMENT_PIVOT",
        surface="tool:run_command",
        technique="EP-T1-cred-surface-scan",
        evidence="AWS_ACCESS_KEY_ID=AKIAEXAMPLEEXAMPLE7Q",
    )
    # Another finding so chain synthesis returns non-None (needs ≥2).
    g = _runtime_finding(
        id="b", agent_id="PI-01",
        vuln_class="PROMPT_INJECTION",
        surface="chat", technique="PI-T1-direct",
        evidence="benign",
    )
    chain = synthesize_compound_chain([f, g], target_id="mcp://custom")
    brm = optimize_impact(
        chain=chain, findings=[f, g],
        trust_edges=[TrustEdge("aws_access_key", "custom.vault",
                               note="customer's in-house vault")],
    )
    assert brm.transitively_reachable == ["custom.vault"]


def test_optimize_to_dict_is_json_serialisable():
    import json
    f = _runtime_finding(
        id="a", agent_id="EP-11",
        vuln_class="ENVIRONMENT_PIVOT",
        surface="tool:x", technique="EP-T1-cred-surface-scan",
        evidence="ghp_abcdefghijklmnopqrstuvwxyzABCDEF12",
    )
    g = _runtime_finding(
        id="b", agent_id="PI-01",
        vuln_class="PROMPT_INJECTION",
        surface="chat", technique="PI-T1-direct",
        evidence="benign",
    )
    chain = synthesize_compound_chain([f, g], target_id="mcp://x")
    brm = optimize_impact(chain=chain, findings=[f, g])
    blob = json.dumps(brm.to_dict())
    assert "harm_score" in blob
    assert "data_classes_exposed" in blob
