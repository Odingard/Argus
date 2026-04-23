"""
tests/test_mcp_attacker_calibration.py

Post-phase calibration — the pass that collapses 40 raw LLM-graded
findings into the handful of distinct issues a human operator can
actually triage.

The three sub-passes under test:

  1. Scope-enforcement guard — findings graded HIGH/CRIT in the
     TRACE_LATERAL / AUTH_BYPASS / SSRF families get downgraded to
     MEDIUM when the server's raw_response shows scope enforcement
     ("access denied", "outside allowed", etc.). The real concern
     becomes "adversarial payload echoed in rejection error",
     which is what the retitled finding reports.

  2. SCHEMA severity cap — SCHEMA-phase verdicts from a single
     Haiku judge are capped at MEDIUM unless another phase
     corroborated a finding on the same tool.

  3. Dedupe — findings with the same (vuln_class,
     normalised-response-fingerprint) collapse to one representative
     with occurrences metadata.

Deterministic end-to-end; no LLM calls, no network.
"""
from __future__ import annotations

from argus.mcp_attacker.mcp_live_attacker import (
    MCPFinding, _calibrate_findings, _scope_enforced,
    _fingerprint_response,
)


def _mk(**kw) -> MCPFinding:
    base = dict(
        id="f00", phase="SCHEMA", severity="HIGH",
        vuln_class="TRACE_LATERAL",
        title="Path Traversal",
        tool_name="read_file", payload_used="p",
        observed_behavior="", expected_behavior="",
        poc=None, cvss_estimate=None, remediation=None,
        raw_response="",
    )
    base.update(kw)
    return MCPFinding(**base)


# ── scope-enforcement guard ──────────────────────────────────────────────────

def test_scope_enforced_recognises_access_denied():
    assert _scope_enforced(
        "Access denied - path outside allowed directories"
    )


def test_scope_enforced_recognises_not_allowed_variants():
    assert _scope_enforced("Error: not allowed")
    assert _scope_enforced("permission denied writing path")
    assert _scope_enforced("path is not within allowed scope")


def test_scope_enforced_does_not_fire_on_bland_responses():
    assert not _scope_enforced("")
    assert not _scope_enforced(None)
    assert not _scope_enforced("ok")
    assert not _scope_enforced("success, file read")


def test_high_traversal_with_access_denied_downgrades_to_medium():
    f = _mk(
        severity="HIGH",
        vuln_class="TRACE_LATERAL",
        raw_response=("Access denied - path outside allowed "
                      "directories: /etc/passwd"),
    )
    out = _calibrate_findings([f])
    assert len(out) == 1
    assert out[0].severity == "MEDIUM"
    assert "reflection_only" in out[0].observed_behavior
    assert "prompt-injection" in out[0].title.lower()


def test_critical_authbypass_with_denial_downgrades_and_retitles():
    f = _mk(
        severity="CRITICAL",
        vuln_class="AUTH_BYPASS",
        raw_response="permission denied: user lacks scope",
        title="Unauthorised privileged action",
    )
    out = _calibrate_findings([f])
    assert out[0].severity == "MEDIUM"


def test_high_traversal_WITHOUT_denial_stays_high_if_corroborated():
    """A HIGH traversal finding on a tool that ALSO produced a
    non-SCHEMA finding (i.e., runtime corroboration) must survive at
    HIGH. Without that corroboration, the SCHEMA cap brings it to
    MEDIUM anyway."""
    f_schema = _mk(
        phase="SCHEMA", severity="HIGH", vuln_class="TRACE_LATERAL",
        tool_name="read_file",
        raw_response="leaked: /etc/passwd contents returned",
    )
    f_runtime = _mk(
        id="f01", phase="TOOL-FUZZ", severity="MEDIUM",
        vuln_class="TRACE_LATERAL",
        tool_name="read_file",
        raw_response="fuzz crashed server at offset 42",
    )
    out = _calibrate_findings([f_schema, f_runtime])
    # Both preserved (different response fingerprints).
    assert len(out) == 2
    schema_after = next(o for o in out if o.phase == "SCHEMA")
    # Runtime corroboration on the same tool lets SCHEMA keep HIGH.
    assert schema_after.severity == "HIGH"


# ── SCHEMA severity cap ──────────────────────────────────────────────────────

def test_schema_only_high_without_corroboration_capped():
    f = _mk(
        phase="SCHEMA", severity="HIGH", vuln_class="MESH_TRUST",
        raw_response="unusual reflection of payload",
    )
    out = _calibrate_findings([f])
    assert out[0].severity == "MEDIUM"
    assert "schema_only:capped" in out[0].observed_behavior


def test_schema_medium_not_capped_further():
    """The cap ceiling is MEDIUM, never below."""
    f = _mk(phase="SCHEMA", severity="MEDIUM",
            vuln_class="MESH_TRUST", raw_response="x")
    out = _calibrate_findings([f])
    assert out[0].severity == "MEDIUM"


# ── Dedupe ───────────────────────────────────────────────────────────────────

def test_same_class_same_fingerprint_collapses_to_one():
    resp = ("Access denied - path outside allowed directories: "
            "/private/tmp/x")
    findings = [
        _mk(id="f1", tool_name="read_file",        raw_response=resp),
        _mk(id="f2", tool_name="write_file",       raw_response=resp),
        _mk(id="f3", tool_name="list_directory",   raw_response=resp),
        _mk(id="f4", tool_name="create_directory", raw_response=resp),
    ]
    out = _calibrate_findings(findings)
    assert len(out) == 1
    assert "occurrences=4" in out[0].observed_behavior
    # Representative lists the OTHER tools so the operator sees scope.
    for t in ("write_file", "list_directory", "create_directory"):
        assert t in out[0].observed_behavior


def test_different_vuln_class_not_collapsed():
    resp = "some generic response"
    findings = [
        _mk(id="f1", vuln_class="TRACE_LATERAL", raw_response=resp),
        _mk(id="f2", vuln_class="PHANTOM_MEMORY", raw_response=resp),
    ]
    out = _calibrate_findings(findings)
    assert len(out) == 2


def test_tool_specific_strings_normalised_in_fingerprint():
    """`read_file` vs `write_file` with otherwise identical responses
    must fingerprint the same — tool names are normalised out."""
    a = _fingerprint_response(
        "Access denied - read_file failed: not allowed", "read_file",
    )
    b = _fingerprint_response(
        "Access denied - write_file failed: not allowed", "write_file",
    )
    assert a == b


def test_empty_findings_list_returns_empty():
    assert _calibrate_findings([]) == []


def test_highest_severity_wins_as_representative():
    resp = "reflected payload content"
    findings = [
        _mk(id="a", severity="LOW",    raw_response=resp),
        _mk(id="b", severity="HIGH",   raw_response=resp),
        _mk(id="c", severity="MEDIUM", raw_response=resp),
    ]
    out = _calibrate_findings(findings)
    assert len(out) == 1
    # HIGH was the highest; but SCHEMA-cap drops it to MEDIUM.
    # The POINT of this test is just that the calibrator doesn't
    # pick the LOW representative — it picks the one that was
    # highest pre-calibration.
    assert out[0].severity == "MEDIUM"
    assert out[0].id == "b"


def test_real_world_shape_collapses_hard():
    """Regression-shaped test mirroring the Anthropic filesystem run:
    eight tools, same 'Access denied ... outside allowed directories'
    error, all graded HIGH by Haiku, one distinct vuln_class. Must
    collapse to a single MEDIUM representative with occurrences=8."""
    tools = [
        "create_directory", "directory_tree", "get_file_info",
        "list_directory", "move_file", "search_files",
        "read_file", "write_file",
    ]
    resp = ("Access denied - path outside allowed directories: "
            "/some/forbidden/path not in /private/tmp")
    findings = [
        _mk(id=f"f{i}", tool_name=t, severity="HIGH",
            vuln_class="TRACE_LATERAL", raw_response=resp,
            title="Path Traversal Attempt Reflected in Error Message")
        for i, t in enumerate(tools)
    ]
    out = _calibrate_findings(findings)
    assert len(out) == 1
    assert out[0].severity == "MEDIUM"
    assert "occurrences=8" in out[0].observed_behavior
