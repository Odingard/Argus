"""
argus/swarm/blackboard.py

Shared state for a running ARGUS swarm. Every offensive agent, the
supervisor, the continuous correlator, and the devil's-advocate filter
read and write through this one structure.

Patterns ported (translated Go → Python) from Armur-Ai/Pentest-Swarm-AI
(Apache-2.0):

  - Stigmergy: agents don't address each other. They post findings and
    pheromone-weighted hot paths onto the board; other agents' predicates
    fire off of that state. Emergence, not orchestration.
  - Pheromone decay: every finding has a `weight` that decays over time.
    Stale paths naturally retire; hot paths stay hot.
  - Predicate subscribe: subscribers register a callable `match(event)`
    and receive only events that match. Avoids N×M hand-wiring.
  - Per-subscriber budget: each subscriber declares a token / call budget;
    the scheduler refuses to dispatch past it.

Everything is thread-safe and every mutation is JSONL-logged for audit.
"""
from __future__ import annotations

import json
import math
import os
import threading
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterator, Optional

from argus.agents.base import AgentFinding


# ── Shapes ────────────────────────────────────────────────────────────────────

@dataclass
class HotFile:
    """A file other agents should prioritize because a peer found something."""
    path:        str
    reason:      str
    posted_by:   str
    weight:      float      # pheromone intensity, 0..1, subject to decay
    posted_at:   str = ""
    last_seen:   float = 0.0   # monotonic time — fed into decay curve


@dataclass
class ChainHypothesis:
    """A candidate chain proposed by the continuous correlator."""
    hypothesis_id:    str
    title:            str
    finding_ids:      list[str] = field(default_factory=list)
    rationale:        str = ""
    confidence:       float = 0.0       # 0..1
    proposed_by:      str = "correlator"
    posted_at:        str = ""


@dataclass
class BudgetState:
    """Per-subscriber dispatch budget."""
    subscriber_id:  str
    calls_allowed:  int
    calls_used:     int = 0
    tokens_allowed: int = 0
    tokens_used:    int = 0

    def can_dispatch(self) -> bool:
        if self.calls_used >= self.calls_allowed:
            return False
        if self.tokens_allowed and self.tokens_used >= self.tokens_allowed:
            return False
        return True


# Event shapes flowing through the predicate bus.
@dataclass
class _Event:
    kind:    str        # "finding" | "hot_file" | "hypothesis" | "annotation"
    payload: dict


# A subscriber is a (predicate, callback, budget) triple.
Predicate = Callable[[_Event], bool]
Callback  = Callable[[_Event], None]


# ── Blackboard ────────────────────────────────────────────────────────────────

class Blackboard:
    """
    Thread-safe shared state for the swarm. One instance per run.

    Public API:
        post_finding / mark_hot / post_hypothesis / annotate_finding
            — writers. Every call also fires the predicate bus.
        findings / hot_files / hypotheses / snapshot
            — readers. hot_files applies pheromone decay on read.
        subscribe(id, predicate, callback, calls_allowed=..., tokens_allowed=...)
            — register a subscriber. Callback is invoked synchronously
              under the board lock for each matching event, so callbacks
              should enqueue work rather than block.
        follow_findings
            — convenience generator for workers that want to poll.
    """

    # Pheromone half-life in seconds. After this many seconds without a
    # re-post, a hot file's weight halves. Tunable via env var.
    PHEROMONE_HALFLIFE_S = float(
        os.environ.get("ARGUS_PHEROMONE_HALFLIFE_S", "180")
    )

    def __init__(self, run_dir: str) -> None:
        self._lock = threading.RLock()
        self._findings:   list[AgentFinding]    = []
        self._hot_files:  dict[str, HotFile]    = {}   # keyed by path
        self._hypotheses: list[ChainHypothesis] = []
        self._subs:       list[tuple[str, Predicate, Callback, BudgetState]] = []
        self._started_at_mono = time.monotonic()

        run_dir_p = Path(run_dir)
        run_dir_p.mkdir(parents=True, exist_ok=True)
        self._log_path = run_dir_p / "swarm_blackboard.jsonl"
        self._log_path.touch(exist_ok=True)

    # ── Writers ────────────────────────────────────────────────────────────

    def post_finding(self, finding: AgentFinding) -> None:
        with self._lock:
            self._findings.append(finding)
            self._append_log("finding", finding.to_dict())
            self._fire(_Event("finding", finding.to_dict()))

    def mark_hot(self, path: str, reason: str, posted_by: str,
                 weight: float = 0.6) -> None:
        """Reinforce a file's pheromone trail. Merges with existing weight."""
        w = max(0.0, min(1.0, weight))
        now_mono = time.monotonic()
        with self._lock:
            existing = self._hot_files.get(path)
            if existing:
                # Decay existing, then combine with new signal.
                decayed = self._decay(existing)
                merged = min(1.0, decayed + w * 0.5)
                existing.weight = merged
                existing.reason = f"{existing.reason} | {reason}"[:256]
                existing.posted_by = posted_by
                existing.last_seen = now_mono
                hf = existing
            else:
                hf = HotFile(
                    path=path, reason=reason, posted_by=posted_by,
                    weight=w,
                    posted_at=datetime.utcnow().isoformat(),
                    last_seen=now_mono,
                )
                self._hot_files[path] = hf

            self._append_log("hot_file", asdict(hf))
            self._fire(_Event("hot_file", asdict(hf)))

    def post_hypothesis(self, hyp: ChainHypothesis) -> None:
        if not hyp.posted_at:
            hyp.posted_at = datetime.utcnow().isoformat()
        with self._lock:
            self._hypotheses.append(hyp)
            self._append_log("hypothesis", asdict(hyp))
            self._fire(_Event("hypothesis", asdict(hyp)))

    def annotate_finding(self, finding_id: str, key: str, value) -> None:
        """
        Used by devil's-advocate / correlator to stamp verdicts onto a
        finding without mutating the AgentFinding dataclass.
        """
        payload = {"finding_id": finding_id, "key": key, "value": value}
        with self._lock:
            self._append_log("annotation", payload)
            self._fire(_Event("annotation", payload))

    # ── Readers ────────────────────────────────────────────────────────────

    def findings(self, after: Optional[int] = None) -> list[AgentFinding]:
        with self._lock:
            if after is None:
                return list(self._findings)
            return list(self._findings[after:])

    def hot_files(self, limit: int = 20, min_weight: float = 0.1) -> list[HotFile]:
        """Apply pheromone decay on read. Files below `min_weight` are dropped."""
        with self._lock:
            live = []
            for hf in self._hot_files.values():
                current = self._decay(hf)
                hf.weight = current  # persist the decayed value
                if current >= min_weight:
                    live.append(hf)
            live.sort(key=lambda h: -h.weight)
            return live[:limit]

    def hypotheses(self) -> list[ChainHypothesis]:
        with self._lock:
            return list(self._hypotheses)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "findings":   [f.to_dict() for f in self._findings],
                "hot_files":  [asdict(h) for h in self.hot_files(limit=100)],
                "hypotheses": [asdict(h) for h in self._hypotheses],
                "uptime_s":   round(time.monotonic() - self._started_at_mono, 2),
            }

    # ── Subscription (predicate bus) ───────────────────────────────────────

    def subscribe(
        self,
        subscriber_id: str,
        predicate:     Predicate,
        callback:      Callback,
        *,
        calls_allowed:  int = 1_000,
        tokens_allowed: int = 0,
    ) -> BudgetState:
        budget = BudgetState(
            subscriber_id=subscriber_id,
            calls_allowed=calls_allowed,
            tokens_allowed=tokens_allowed,
        )
        with self._lock:
            self._subs.append((subscriber_id, predicate, callback, budget))
        return budget

    def follow_findings(self, poll_interval: float = 0.5,
                        stop_event: Optional[threading.Event] = None
                        ) -> Iterator[AgentFinding]:
        cursor = 0
        while True:
            if stop_event is not None and stop_event.is_set():
                return
            new = self.findings(after=cursor)
            if new:
                cursor += len(new)
                for f in new:
                    yield f
            else:
                time.sleep(poll_interval)

    # ── Internals ──────────────────────────────────────────────────────────

    def _fire(self, event: _Event) -> None:
        """Dispatch event to every matching subscriber. Called under _lock."""
        for sub_id, predicate, callback, budget in list(self._subs):
            if not budget.can_dispatch():
                continue
            try:
                if not predicate(event):
                    continue
            except Exception as e:
                print(f"[blackboard] predicate failed for {sub_id}: {e}")
                continue
            budget.calls_used += 1
            try:
                callback(event)
            except Exception as e:
                print(f"[blackboard] callback {sub_id} raised: {e}")

    def _decay(self, hf: HotFile) -> float:
        """Half-life pheromone decay."""
        if self.PHEROMONE_HALFLIFE_S <= 0:
            return hf.weight
        elapsed = time.monotonic() - (hf.last_seen or self._started_at_mono)
        if elapsed <= 0:
            return hf.weight
        factor = math.pow(0.5, elapsed / self.PHEROMONE_HALFLIFE_S)
        return max(0.0, hf.weight * factor)

    def _append_log(self, kind: str, payload: dict) -> None:
        record = {
            "t":    datetime.utcnow().isoformat(),
            "kind": kind,
            "data": payload,
        }
        try:
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except OSError as e:
            print(f"[blackboard] log write failed: {e}")
