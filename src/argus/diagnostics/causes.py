"""
argus/diagnostics/causes.py — classify WHY an agent ran silent.

When a swarm engagement produces zero findings from one of the 12
agents, today's ARGUS shrugs. The outer loop turns that silence into
signal: every silent agent gets a deterministic SilenceCause tag and
a remediation hint that feeds the next run's Haiku prompt, so run 2
adjusts for what run 1 missed.

This file is PURE — no I/O, no network, no LLM. The heuristic
classifier takes already-aggregated log text plus a finding count
and returns a SilentAgentReport. The orchestrator layer
(``classifier.py``) handles the file reads and the per-run
aggregation.

Priority order when multiple patterns match:
    AGENT_CRASHED   > TIMEOUT > MODEL_REFUSED > SCHEMA_MISMATCH
    > TARGET_HARDENED > NO_SIGNAL

The first non-NO_SIGNAL category that matches wins. NO_SIGNAL is the
fallback for agents that ran clean but whose detectors didn't fire.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class SilenceCause(str, Enum):
    """Why an agent produced zero findings on a given run."""

    # Exception escaped the agent's .run() — stack trace present.
    AGENT_CRASHED   = "agent_crashed"

    # asyncio.TimeoutError captured in the agent's log.
    TIMEOUT         = "timeout"

    # The reasoning model refused to generate variants (safety filter).
    MODEL_REFUSED   = "model_refused"

    # The agent's attack payload shape didn't fit the tool's schema.
    SCHEMA_MISMATCH = "schema_mismatch"

    # The tool rejected every probe with a scope / access error.
    TARGET_HARDENED = "target_hardened"

    # Agent finished normally; detector simply did not fire.
    NO_SIGNAL       = "no_signal"


@dataclass(frozen=True)
class SilentAgentReport:
    """Per-agent diagnostic for one silent run.

    ``confidence`` is a heuristic strength (0-1) reflecting how sure
    we are of the cause classification. ``evidence`` is a one-line
    excerpt from the agent's log supporting the classification.
    ``remediation_hint`` is the instruction the next run's Haiku
    prompt prefix will carry for this agent. ``corpus_seed_text`` is
    optional — when set, the feedback layer writes it to EvolveCorpus
    as a new discovered-template tagged with the cause."""
    agent_id:         str
    cause:            SilenceCause
    confidence:       float
    evidence:         str
    remediation_hint: str
    corpus_seed_text: Optional[str] = None


# ── Heuristic pattern tables ──────────────────────────────────────────────────
#
# All patterns are matched against a lowercased flatten of the
# agent's log text. Keep lists narrow — false positives here mean
# the next run's Haiku prompt carries the wrong adjustment, which
# slows down convergence but isn't dangerous.

_AGENT_CRASHED_PATTERNS: tuple[str, ...] = (
    "traceback (most recent call last)",
    "unhandled exception",
    " crashed",                    # matches "agent X crashed"
    "fatal error in agent",
    "uncaught error",
)

_TIMEOUT_PATTERNS: tuple[str, ...] = (
    "asyncio.timeouterror",
    "timeouterror",
    "request timed out",
    "timeout expired",
    "timed out after",
)

_MODEL_REFUSAL_PATTERNS: tuple[str, ...] = (
    "i can't help with",
    "i cannot help",
    "i'm sorry, but",
    "i am unable",
    "i won't",
    "against my guidelines",
    "against my principles",
    "safety policy",
    "violates my",
    "cannot assist",
    "i'm not able to",
)

_SCHEMA_MISMATCH_PATTERNS: tuple[str, ...] = (
    "input_schema",
    "schema validation",
    "validationerror",
    "pydantic_core._pydantic_core",
    "invalid type",
    "expected integer",
    "expected string",
    "expected object",
    "expected number",
    "expected boolean",
    "jsonschema",
    "required property",
    "does not match pattern",
)

# Mirrors the list in mcp_live_attacker._SCOPE_ENFORCED_PATTERNS;
# both must stay in sync. A divergence doesn't cause correctness
# bugs, but the per-agent diagnostic would classify a finding the
# calibrator already scope-downgraded, or vice versa. Keep in sync.
_TARGET_HARDENED_PATTERNS: tuple[str, ...] = (
    "access denied",
    "permission denied",
    "outside allowed",
    "not in allowed",
    "not allowed",
    "path not permitted",
    "is not within",
    "not a valid path",
    "must be absolute",
    "forbidden",
    "error: enoent",
    "401 unauthorized",
    "403 forbidden",
)


# ── Classification ───────────────────────────────────────────────────────────

def classify_from_text(
    agent_id: str,
    log_text: str,
    finding_count: int = 0,
) -> SilentAgentReport:
    """Deterministic classification of why an agent ran silent.

    Pure function — no file I/O, no LLM calls. Callers are expected
    to aggregate the agent's log (stdout + stderr + agent_out JSON)
    into a single string before invoking. ``finding_count`` should
    be the number of findings the agent produced in this run; if
    non-zero, the agent wasn't actually silent and the return is a
    sentinel with cause=NO_SIGNAL and confidence=0.

    Priority: crashes > timeouts > refusals > schema > hardened >
    no-signal."""
    if finding_count > 0:
        return SilentAgentReport(
            agent_id=agent_id,
            cause=SilenceCause.NO_SIGNAL,
            confidence=0.0,
            evidence="agent produced findings; not silent",
            remediation_hint="",
        )

    low = (log_text or "").lower()

    # (1) Crash — most important to surface; a crashing agent is
    # worse than an agent that finished without findings.
    if any(p in low for p in _AGENT_CRASHED_PATTERNS):
        return SilentAgentReport(
            agent_id=agent_id,
            cause=SilenceCause.AGENT_CRASHED,
            confidence=0.95,
            evidence=_first_matching_line(log_text, _AGENT_CRASHED_PATTERNS),
            remediation_hint=(
                "the agent crashed with an unhandled exception on "
                "the last run; surface the traceback and fix before "
                "retry."
            ),
        )

    # (2) Timeout — actionable signal that payloads / surfaces are
    # too heavy; operator should shrink scope or extend timeouts.
    if any(p in low for p in _TIMEOUT_PATTERNS):
        return SilentAgentReport(
            agent_id=agent_id,
            cause=SilenceCause.TIMEOUT,
            confidence=0.90,
            evidence=_first_matching_line(log_text, _TIMEOUT_PATTERNS),
            remediation_hint=(
                "a probe timed out; try smaller payloads, smaller "
                "batches, or raise the per-surface timeout."
            ),
        )

    # (3) Model refusal — the reasoning model declined to generate a
    # variant class. Often solvable by reframing as diagnostic/audit.
    if any(p in low for p in _MODEL_REFUSAL_PATTERNS):
        return SilentAgentReport(
            agent_id=agent_id,
            cause=SilenceCause.MODEL_REFUSED,
            confidence=0.85,
            evidence=_first_matching_line(log_text, _MODEL_REFUSAL_PATTERNS),
            remediation_hint=(
                "the reasoning model refused the previous variant "
                "class; reframe prompts as red-team audit work or "
                "split the harmful portion across turns."
            ),
            corpus_seed_text=(
                "[diagnostic:refusal-hardened] consider a benign "
                "audit-team framing of the original probe, with the "
                "sensitive portion deferred to a later turn."
            ),
        )

    # (4) Schema mismatch — payloads didn't fit param types.
    if any(p in low for p in _SCHEMA_MISMATCH_PATTERNS):
        return SilentAgentReport(
            agent_id=agent_id,
            cause=SilenceCause.SCHEMA_MISMATCH,
            confidence=0.80,
            evidence=_first_matching_line(log_text, _SCHEMA_MISMATCH_PATTERNS),
            remediation_hint=(
                "probes failed schema validation; coerce payloads "
                "to the declared parameter types before sending and "
                "retry the same variants."
            ),
        )

    # (5) Target hardened — every probe was rejected with a scope
    # error. The agent needs to pivot tactics.
    if any(p in low for p in _TARGET_HARDENED_PATTERNS):
        return SilentAgentReport(
            agent_id=agent_id,
            cause=SilenceCause.TARGET_HARDENED,
            confidence=0.80,
            evidence=_first_matching_line(log_text, _TARGET_HARDENED_PATTERNS),
            remediation_hint=(
                "target enforced scope on every probe; shift focus "
                "to state-changing tools, cross-tool chains, timing "
                "side-channels, or resource surface."
            ),
        )

    # (6) No signal — fell through. Agent ran clean, detector quiet.
    return SilentAgentReport(
        agent_id=agent_id,
        cause=SilenceCause.NO_SIGNAL,
        confidence=0.50,
        evidence="agent completed normally; detector did not fire",
        remediation_hint=(
            "agent ran clean with no findings; widen the variant "
            "space and look at cross-surface interactions on the "
            "next run."
        ),
    )


def _first_matching_line(text: str, patterns: tuple[str, ...]) -> str:
    """Return the first line from text that contains any pattern.

    Used to give the operator (and the next-run feedback layer) a
    grounded evidence quote rather than a hand-wave. Empty string if
    no line matches — shouldn't happen since the caller only invokes
    after `any(p in low ...)` already succeeded on the flatten."""
    if not text:
        return ""
    for line in text.splitlines():
        low = line.lower()
        for p in patterns:
            if p in low:
                return line.strip()[:160]
    return "(pattern matched in aggregate but not on any single line)"


__all__ = [
    "SilenceCause", "SilentAgentReport", "classify_from_text",
]
