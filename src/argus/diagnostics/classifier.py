"""
argus/diagnostics/classifier.py — per-run aggregator.

Takes the 12-agent registry + the swarm result + a log loader, and
produces a ``DiagnosticReport`` that names every silent agent with a
cause tag. Day-1 scope: the orchestration shell, the pure-function
classifier in causes.py, and a LogLoader protocol that the tests
inject with an in-memory dict (so no disk I/O in tests).

Real file-backed LogLoader wiring lands in Day 2 alongside the
feedback layer.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from argus.diagnostics.causes import (
    SilentAgentReport, classify_from_text,
)


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DiagnosticReport:
    """Per-run aggregate — one per engagement."""
    run_id:            str
    target:            str
    total_agents:      int
    silent_agents:     tuple[SilentAgentReport, ...]
    productive_agents: tuple[str, ...]
    aggregate_causes:  dict[str, int] = field(default_factory=dict)

    @property
    def silent_count(self) -> int:
        return len(self.silent_agents)

    @property
    def productive_count(self) -> int:
        return len(self.productive_agents)

    @property
    def silence_ratio(self) -> float:
        if self.total_agents == 0:
            return 0.0
        return self.silent_count / self.total_agents


# ── Log-loading abstraction ───────────────────────────────────────────────────
#
# The classifier does not read files directly. The caller passes a
# ``LogLoader`` — a callable ``agent_id -> str`` — so tests can stub
# with dicts and production can read from disk without the
# classifier caring. This is the same seam pattern EvolveCorpus uses
# for filesystem injection.

LogLoader = Callable[[str], str]


def dict_log_loader(logs: dict[str, str]) -> LogLoader:
    """Factory: build a LogLoader backed by an in-memory dict.
    Useful in tests and for synthetic runs."""
    def _load(agent_id: str) -> str:
        return logs.get(agent_id, "")
    return _load


# ── Classifier ────────────────────────────────────────────────────────────────

class SilenceClassifier:
    """Orchestrates cause classification across an entire run.

    Usage::

        classifier = SilenceClassifier(registry={"PI-02": PromptInjHunter, ...})
        report = classifier.classify_run(
            swarm_result={"findings": [...]},
            log_loader=dict_log_loader({"PI-02": "...log text..."}),
            target="mcp://example/sse",
            run_id="run_20260423_091500",
        )
    """

    def __init__(self, registry: dict[str, Any]):
        # ``registry`` is the agent dict — keys are agent_ids, values
        # are the agent class/factory (we only use the keys here).
        if not isinstance(registry, dict):
            raise TypeError("registry must be a dict of agent_id -> class")
        self.registry = dict(registry)

    def classify_run(
        self,
        *,
        swarm_result:  dict,
        log_loader:    LogLoader,
        target:        str,
        run_id:        str = "",
    ) -> DiagnosticReport:
        """Compute a DiagnosticReport for a completed swarm run.

        ``swarm_result`` must contain a ``"findings"`` key whose value
        is iterable of objects carrying ``agent_id`` (dicts with that
        key, or dataclasses). Agents absent from ``swarm_result["findings"]``
        are classified as silent; agents present are recorded as
        productive without being classified.

        Pure except for the log_loader calls (which the caller owns)."""
        findings: Iterable[Any] = swarm_result.get("findings") or []

        # Count findings per agent so we can distinguish silent
        # agents from productive ones without assuming a specific
        # finding schema.
        per_agent_count: Counter[str] = Counter()
        for f in findings:
            aid = _finding_agent_id(f)
            if aid:
                per_agent_count[aid] += 1

        silent_reports: list[SilentAgentReport] = []
        productive_ids: list[str] = []
        for agent_id in sorted(self.registry):
            if per_agent_count.get(agent_id, 0) > 0:
                productive_ids.append(agent_id)
                continue
            log_text = log_loader(agent_id)
            silent_reports.append(
                classify_from_text(
                    agent_id=agent_id,
                    log_text=log_text,
                    finding_count=0,
                )
            )

        # Aggregate cause-count table — string keys so the report
        # serialises cleanly (SilenceCause IS a str subclass but
        # json.dumps handles it via the ``value`` field anyway).
        aggregate: dict[str, int] = {}
        for r in silent_reports:
            aggregate[r.cause.value] = aggregate.get(r.cause.value, 0) + 1

        return DiagnosticReport(
            run_id=run_id,
            target=target,
            total_agents=len(self.registry),
            silent_agents=tuple(silent_reports),
            productive_agents=tuple(productive_ids),
            aggregate_causes=aggregate,
        )


def _finding_agent_id(f: Any) -> Optional[str]:
    """Return the agent_id off a finding — handles dict shape AND
    dataclass shape AND MCPFinding's ``tool_name``-only shape (no
    agent_id)."""
    if isinstance(f, dict):
        aid = f.get("agent_id")
        if isinstance(aid, str):
            return aid
        return None
    aid = getattr(f, "agent_id", None)
    if isinstance(aid, str):
        return aid
    return None


__all__ = [
    "DiagnosticReport", "LogLoader", "SilenceClassifier",
    "dict_log_loader",
]
