"""Tests for ALEC evidence package export."""

import json

from argus.models.findings import (
    AttackChainStep,
    CompoundAttackPath,
    Finding,
    FindingSeverity,
    FindingStatus,
    OWASPAgenticCategory,
    RemediationGuidance,
    ReproductionStep,
    ValidationResult,
)
from argus.orchestrator.engine import ScanResult
from argus.reporting.alec_export import ALECEvidenceExporter


def _make_finding(
    agent_type: str = "prompt_injection_hunter",
    technique: str = "role_hijack",
    target_surface: str = "http://target:8080/chat",
    severity: FindingSeverity = FindingSeverity.CRITICAL,
    title: str = "Test injection finding",
    validated: bool = False,
    with_remediation: bool = False,
) -> Finding:
    f = Finding(
        agent_type=agent_type,
        agent_instance_id="test-inst-001",
        scan_id="scan-alec-001",
        title=title,
        description=f"Test finding for {agent_type}",
        severity=severity,
        target_surface=target_surface,
        technique=technique,
        attack_chain=[
            AttackChainStep(
                step_number=1,
                agent_type=agent_type,
                technique=technique,
                description="Execute attack",
                target_surface=target_surface,
            )
        ],
        reproduction_steps=[
            ReproductionStep(
                step_number=1,
                action="Send payload",
                input_data="test payload",
                expected_result="Rejected",
                actual_result="Accepted",
            )
        ],
        owasp_agentic=OWASPAgenticCategory.PROMPT_INJECTION,
    )
    if validated:
        f.status = FindingStatus.VALIDATED
        f.validation = ValidationResult(
            validated=True,
            validation_method="replay",
            proof_of_exploitation="Canary token leaked",
            reproducible=True,
            attempts=1,
        )
    if with_remediation:
        f.remediation = RemediationGuidance(
            summary="Apply input filtering",
            detailed_steps=["Step 1: Add filter", "Step 2: Test filter"],
            cerberus_detection_rule="CERB-PI-001",
            references=["https://owasp.org/example"],
        )
    return f


def _make_scan_result(
    findings: list[Finding] | None = None,
    compound_paths: list[CompoundAttackPath] | None = None,
) -> ScanResult:
    result = ScanResult(scan_id="scan-alec-001")
    from datetime import UTC, datetime

    result.started_at = datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC)
    result.completed_at = datetime(2025, 1, 1, 0, 5, 0, tzinfo=UTC)
    result.findings = findings or []
    result.compound_paths = compound_paths or []
    return result


# ---------- Basic export tests ----------


def test_export_empty_scan():
    exporter = ALECEvidenceExporter()
    result = _make_scan_result()
    package = exporter.export_evidence_package(result)

    assert package["alec_schema_version"] == "1.0.0"
    assert package["evidence_format"] == "argus-alec-bridge"
    assert package["generator"] == "ARGUS Autonomous AI Red Team"
    assert package["evidence_entries"] == []
    assert package["compound_attack_paths"] == []
    assert "package_integrity_hash" in package
    assert len(package["package_integrity_hash"]) == 64  # SHA-256 hex


def test_export_with_validated_findings():
    findings = [
        _make_finding(validated=True, with_remediation=True),
        _make_finding(
            agent_type="tool_poisoning",
            technique="hidden_instructions",
            validated=True,
        ),
    ]
    exporter = ALECEvidenceExporter()
    result = _make_scan_result(findings=findings)
    package = exporter.export_evidence_package(result)

    assert len(package["evidence_entries"]) == 2
    entry = package["evidence_entries"][0]
    assert entry["evidence_id"] == "ARGUS-EV-0001"
    assert entry["classification"]["severity"] == "CRITICAL"
    assert entry["proof_of_exploitation"]["validated"] is True
    assert entry["remediation"]["summary"] == "Apply input filtering"
    assert "integrity_hash" in entry


def test_export_unvalidated_findings_excluded():
    """Only validated findings appear in evidence entries."""
    findings = [
        _make_finding(validated=False),
        _make_finding(validated=True),
    ]
    exporter = ALECEvidenceExporter()
    result = _make_scan_result(findings=findings)
    package = exporter.export_evidence_package(result)

    # Only validated findings are in evidence entries
    assert len(package["evidence_entries"]) == 1


def test_export_with_compound_paths():
    findings = [_make_finding(validated=True)]
    path = CompoundAttackPath(
        scan_id="scan-alec-001",
        title="Compound: injection + tool misuse",
        description="Chained attack",
        severity=FindingSeverity.CRITICAL,
        finding_ids=[findings[0].id],
        attack_path_steps=[
            AttackChainStep(
                step_number=1,
                agent_type="prompt_injection_hunter",
                technique="role_hijack",
                description="Stage 1",
                target_surface="http://target:8080/chat",
            )
        ],
        compound_impact="End-to-end exploit",
        exploitability_score=8.0,
        detectability_score=6.5,
        owasp_agentic=[OWASPAgenticCategory.PROMPT_INJECTION],
        remediation=RemediationGuidance(
            summary="Break the chain",
            detailed_steps=["Fix injection", "Fix tool access"],
        ),
    )
    result = _make_scan_result(findings=findings, compound_paths=[path])
    exporter = ALECEvidenceExporter()
    package = exporter.export_evidence_package(result)

    assert len(package["compound_attack_paths"]) == 1
    cp = package["compound_attack_paths"][0]
    assert cp["evidence_id"] == "ARGUS-CP-0001"
    assert cp["severity"] == "CRITICAL"
    assert cp["remediation"]["summary"] == "Break the chain"
    assert "integrity_hash" in cp


def test_export_chain_of_custody():
    exporter = ALECEvidenceExporter()
    result = _make_scan_result()
    package = exporter.export_evidence_package(result)

    coc = package["chain_of_custody"]
    assert coc["integrity_method"] == "SHA-256"
    assert "ARGUS" in coc["notes"]
    assert coc["created_by"] == "ARGUS automated scan"


def test_export_scan_metadata():
    findings = [_make_finding(validated=True)]
    result = _make_scan_result(findings=findings)
    exporter = ALECEvidenceExporter()
    package = exporter.export_evidence_package(result)

    meta = package["scan_metadata"]
    assert meta["scan_id"] == "scan-alec-001"
    assert meta["duration_seconds"] == 300.0
    assert meta["total_findings"] == 1
    assert meta["validated_findings"] == 1


def test_export_executive_summary():
    findings = [_make_finding(validated=True)]
    result = _make_scan_result(findings=findings)
    exporter = ALECEvidenceExporter()
    package = exporter.export_evidence_package(result)

    summary = package["executive_summary"]
    assert "ARGUS" in summary["product"]
    assert "risk_narrative" in summary
    assert len(summary["risk_narrative"]) > 0


def test_export_cerberus_cross_references():
    findings = [_make_finding(validated=True)]
    result = _make_scan_result(findings=findings)
    exporter = ALECEvidenceExporter()
    package = exporter.export_evidence_package(result)

    cerb = package["cerberus_cross_references"]
    assert cerb["total_rules_generated"] >= 1
    assert len(cerb["rules"]) >= 1


def test_export_json_valid():
    findings = [_make_finding(validated=True, with_remediation=True)]
    result = _make_scan_result(findings=findings)
    exporter = ALECEvidenceExporter()
    json_str = exporter.export_json(result)

    # Should parse as valid JSON
    parsed = json.loads(json_str)
    assert parsed["alec_schema_version"] == "1.0.0"
    assert len(parsed["evidence_entries"]) == 1


def test_export_risk_narrative_no_findings():
    result = _make_scan_result()
    exporter = ALECEvidenceExporter()
    package = exporter.export_evidence_package(result)

    narrative = package["executive_summary"]["risk_narrative"]
    assert "no validated findings" in narrative.lower()


def test_export_risk_narrative_with_findings():
    findings = [_make_finding(validated=True)]
    result = _make_scan_result(findings=findings)
    exporter = ALECEvidenceExporter()
    package = exporter.export_evidence_package(result)

    narrative = package["executive_summary"]["risk_narrative"]
    assert "1 validated" in narrative.lower()


def test_integrity_hash_deterministic():
    """Same input should produce same hash."""
    exporter = ALECEvidenceExporter()
    h1 = exporter._compute_hash("test content")
    h2 = exporter._compute_hash("test content")
    assert h1 == h2
    assert len(h1) == 64


def test_integrity_hash_changes_with_content():
    exporter = ALECEvidenceExporter()
    h1 = exporter._compute_hash("content A")
    h2 = exporter._compute_hash("content B")
    assert h1 != h2
