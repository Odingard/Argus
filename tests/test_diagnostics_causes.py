"""
tests/test_diagnostics_causes.py — Day-1 outer-loop foundation.

Exercises argus.diagnostics.causes.classify_from_text: pure
heuristic classifier that takes agent log text + finding count and
returns a SilentAgentReport.

The contract this locks in:

  - Priority order when multiple patterns match:
    crash > timeout > refusal > schema > hardened > no_signal.
  - Confidence scales with heuristic strength (crash 0.95, no_signal
    0.50).
  - Evidence is a single line from the log where the pattern matched,
    trimmed to 160 chars.
  - Remediation hint is present on every cause so the feedback layer
    can always inject something into the next-run prompt.

No LLM, no I/O, no network.
"""
from __future__ import annotations

from argus.diagnostics.causes import (
    SilenceCause, SilentAgentReport, classify_from_text,
)


# ── Priority order ────────────────────────────────────────────────────────────

def test_crash_beats_every_other_pattern():
    """An agent that crashed should always be classified AGENT_CRASHED,
    even if its log also contains timeout or refusal markers."""
    log = (
        "request timed out\n"
        "I can't help with that\n"
        "Traceback (most recent call last):\n"
        "  File \"agent.py\", line 42\n"
        "NameError: undefined\n"
    )
    r = classify_from_text("PI-02", log)
    assert r.cause == SilenceCause.AGENT_CRASHED
    assert r.confidence >= 0.9


def test_timeout_beats_refusal_and_schema():
    log = (
        "I cannot help\n"
        "input_schema validation failed\n"
        "asyncio.TimeoutError: after 30s\n"
    )
    r = classify_from_text("TP-02", log)
    assert r.cause == SilenceCause.TIMEOUT


def test_refusal_beats_schema_and_hardened():
    log = (
        "ValidationError: invalid type\n"
        "access denied\n"
        "I'm sorry, but I can't help with that\n"
    )
    r = classify_from_text("PI-02", log)
    assert r.cause == SilenceCause.MODEL_REFUSED


def test_schema_beats_target_hardened():
    log = (
        "403 forbidden\n"
        "jsonschema validation error: expected integer\n"
    )
    r = classify_from_text("RC-08", log)
    assert r.cause == SilenceCause.SCHEMA_MISMATCH


def test_target_hardened_only():
    log = (
        "Access denied - path outside allowed directories\n"
        "Access denied - second request\n"
    )
    r = classify_from_text("SC-09", log)
    assert r.cause == SilenceCause.TARGET_HARDENED


def test_empty_log_falls_to_no_signal():
    r = classify_from_text("EP-11", "")
    assert r.cause == SilenceCause.NO_SIGNAL
    assert r.confidence == 0.5


def test_clean_log_falls_to_no_signal():
    """Log with no distinctive patterns — agent completed quietly."""
    log = "probe sent, response 200, no indicators\nexit 0\n"
    r = classify_from_text("ME-10", log)
    assert r.cause == SilenceCause.NO_SIGNAL


# ── Each cause: evidence quote + remediation hint present ────────────────────

def test_crashed_carries_traceback_evidence():
    log = "some log\nTraceback (most recent call last):\nAttributeError"
    r = classify_from_text("X", log)
    assert "traceback" in r.evidence.lower()
    assert len(r.remediation_hint) > 0


def test_timeout_remediation_suggests_smaller_payloads():
    log = "asyncio.TimeoutError: exceeded 30s"
    r = classify_from_text("X", log)
    assert r.cause == SilenceCause.TIMEOUT
    assert "timeout" in r.remediation_hint.lower() \
        or "smaller" in r.remediation_hint.lower() \
        or "timed out" in r.remediation_hint.lower()


def test_refusal_emits_corpus_seed_text():
    """Refusal is the only cause that writes a corpus seed (so the
    next run has a refusal-hardened variant to try)."""
    log = "I'm sorry, but I can't comply with that request."
    r = classify_from_text("X", log)
    assert r.cause == SilenceCause.MODEL_REFUSED
    assert r.corpus_seed_text is not None
    assert "refusal" in r.corpus_seed_text.lower()


def test_schema_mismatch_remediation_mentions_coerce_or_types():
    log = "ValidationError: expected integer, got string"
    r = classify_from_text("X", log)
    assert r.cause == SilenceCause.SCHEMA_MISMATCH
    assert ("coerce" in r.remediation_hint.lower()
            or "type" in r.remediation_hint.lower())


def test_hardened_remediation_pushes_to_pivot():
    log = "Access denied - path outside allowed"
    r = classify_from_text("X", log)
    assert r.cause == SilenceCause.TARGET_HARDENED
    assert ("pivot" in r.remediation_hint.lower()
            or "state-changing" in r.remediation_hint.lower()
            or "timing" in r.remediation_hint.lower()
            or "shift" in r.remediation_hint.lower())


def test_no_signal_remediation_suggests_variant_widening():
    r = classify_from_text("X", "clean exit")
    assert r.cause == SilenceCause.NO_SIGNAL
    assert ("widen" in r.remediation_hint.lower()
            or "broader" in r.remediation_hint.lower()
            or "cross-surface" in r.remediation_hint.lower())


# ── Evidence line extraction ─────────────────────────────────────────────────

def test_evidence_is_single_line_trimmed():
    long_line = (
        "Traceback (most recent call last): " + ("x" * 300)
    )
    log = f"harmless line\n{long_line}\nother"
    r = classify_from_text("X", log)
    assert r.cause == SilenceCause.AGENT_CRASHED
    assert len(r.evidence) <= 160
    # Not empty
    assert r.evidence.strip()


def test_evidence_uses_first_matching_line():
    log = (
        "first line no match\n"
        "second line: Traceback (most recent call last)\n"
        "third line: Traceback (most recent call last) later\n"
    )
    r = classify_from_text("X", log)
    assert "second line" in r.evidence.lower()


# ── Defensive / sentinel ─────────────────────────────────────────────────────

def test_finding_count_nonzero_returns_sentinel():
    """If the caller mistakenly invokes for a productive agent, we
    return a safe sentinel rather than classify on flaky input."""
    r = classify_from_text(
        "PI-02",
        "any log text",
        finding_count=3,
    )
    assert r.cause == SilenceCause.NO_SIGNAL
    assert r.confidence == 0.0
    assert "not silent" in r.evidence.lower()


def test_report_is_frozen_hashable():
    r = classify_from_text("X", "some log")
    # SilentAgentReport is a frozen dataclass
    assert hash(r) == hash(r)


def test_silence_cause_enum_values_stable():
    """Lock in the str value of each enum member — the feedback layer
    writes these into diagnostic_priors.json and EvolveCorpus tags."""
    assert SilenceCause.AGENT_CRASHED.value   == "agent_crashed"
    assert SilenceCause.TIMEOUT.value         == "timeout"
    assert SilenceCause.MODEL_REFUSED.value   == "model_refused"
    assert SilenceCause.SCHEMA_MISMATCH.value == "schema_mismatch"
    assert SilenceCause.TARGET_HARDENED.value == "target_hardened"
    assert SilenceCause.NO_SIGNAL.value       == "no_signal"


def test_silent_agent_report_exposed_via_public_api():
    """Importable from argus.diagnostics — not a leak of a private."""
    import argus.diagnostics as d
    assert d.SilenceCause is SilenceCause
    assert d.SilentAgentReport is SilentAgentReport
    assert d.classify_from_text is classify_from_text
