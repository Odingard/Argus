"""
agents/agent_08_race_condition.py
Agent 8 — Race Condition Agent (Phase 3 per PHASES.md / spec).

Per Agent_Specs.docx §Agent 8: "agentic systems frequently host
shared-resource side effects (counters, quotas, account balances,
stateful sessions) protected by check-then-act sequences that are not
atomic. An attacker who can fire requests in parallel can interleave
their check-then-act windows to produce a TOCTOU bug — quota bypass,
double spend, duplicate-account creation. The finding is confirmed
when N parallel requests produce strictly more 'success' outcomes than
N sequential requests against the same surface."

Phase 3 scope — concurrency-driven attacks on tool surfaces:

  1. ENUMERATE tool surfaces.
  2. Filter to surfaces whose name/description signals a stateful
     side effect: "consume", "transfer", "increment", "quota",
     "limit", "balance", "redeem", "claim". (Read-only surfaces
     are skipped — racing them yields no behaviour delta.)
  3. SEQUENTIAL BASELINE: fire N identical requests one after another.
     Count the success outcomes (status=="ok" + response body matches
     a configurable success regex) and capture the final reported
     state if the response includes one.
  4. PARALLEL BURST: same N requests, fired with asyncio.gather under
     one fresh adapter / session.
  5. OBSERVE: if the parallel burst yields strictly more successes
     than the sequential baseline (or final state diverges in the
     direction of more side effects), that's the race finding.

Techniques (different burst shapes):
  RC-T1-parallel-burst         N identical concurrent requests
  RC-T2-toctou-read-write      interleave reads and writes
  RC-T3-quota-bypass           burst N+K requests against an N-limit
  RC-T4-double-spend           parallel "spend"-style requests
  RC-T5-mutation-interleave    parallel writes with overlapping keys
  RC-T6-handoff-race           parallel handoff:* requests to one peer
"""
from __future__ import annotations

import asyncio
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from argus.adapter.base import (
    AdapterError, AdapterObservation, BaseAdapter, Request, Response, Surface,
)
from argus.agents.base import AgentFinding, BaseAgent
from argus.corpus_attacks import EvolveCorpus
from argus.observation import (
    BehaviorDelta, DeltaKind, ObservationEngine, Verdict, default_detectors,
)


_STATEFUL_NAME = re.compile(
    r"(?i)(consume|transfer|increment|decrement|quota|limit|balance|"
    r"redeem|claim|reserve|deduct|charge|withdraw|deposit|mutate|"
    r"create_user|update|delete|rename|cancel|approve)"
)
_STATEFUL_DESC = re.compile(
    r"(?i)(stateful|atomic|once-?per|rate.?limit|side.?effect|"
    r"counter|balance|durable|transactional|reservation)"
)
_SUCCESS_BODY = re.compile(
    r"(?i)\b(ok|success|granted|approved|consumed|reserved|charged|"
    r"deposited|withdrawn|created|updated|deleted|claimed)\b"
)
_FAILURE_BODY = re.compile(
    r"(?i)\b(denied|rejected|insufficient|exceeded|limit reached|"
    r"forbidden|conflict|locked|unavailable|out of stock)\b"
)


def _is_stateful_surface(surface: Surface) -> bool:
    if surface.kind == "handoff" or surface.name.startswith("handoff:"):
        return True            # handoffs are inherently stateful
    if surface.kind != "tool" and not surface.name.startswith("tool:"):
        return False
    if _STATEFUL_NAME.search(surface.name):
        return True
    if _STATEFUL_DESC.search(surface.description or ""):
        return True
    return False


# ── Burst shape builders ────────────────────────────────────────────────────

def _payload_identical(i: int) -> dict:
    return {"identity": "user:guest",
            "request_idx": i,
            "request_kind": "consume"}


def _payload_toctou(i: int) -> dict:
    return {"identity": "user:guest",
            "request_idx": i,
            "request_kind": "read" if i % 2 == 0 else "write"}


def _payload_quota_burst(i: int) -> dict:
    return {"identity": "user:guest",
            "request_idx": i,
            "request_kind": "consume",
            "burst": True}


def _payload_double_spend(i: int) -> dict:
    return {"identity": "user:guest",
            "request_idx": i,
            "request_kind": "spend",
            "amount": 100,
            "from_account": "shared",
            "to_account":   f"sink_{i}"}


def _payload_mutation_interleave(i: int) -> dict:
    return {"identity": "user:guest",
            "request_idx": i,
            "request_kind": "write",
            "key":   "shared_key",
            "value": f"writer_{i}"}


def _payload_handoff_race(i: int) -> dict:
    return {"from_agent":   f"client_{i}",
            "identity":     "user:guest",
            "content":      "racing handoff",
            "request_idx":  i}


TECHNIQUES: dict[str, Callable[[int], dict]] = {
    "RC-T1-parallel-burst":      _payload_identical,
    "RC-T2-toctou-read-write":   _payload_toctou,
    "RC-T3-quota-bypass":        _payload_quota_burst,
    "RC-T4-double-spend":        _payload_double_spend,
    "RC-T5-mutation-interleave": _payload_mutation_interleave,
    "RC-T6-handoff-race":        _payload_handoff_race,
}

# Which techniques apply to which surface kind.
_HANDOFF_TECHNIQUES = {"RC-T6-handoff-race"}
_TOOL_TECHNIQUES    = set(TECHNIQUES.keys()) - _HANDOFF_TECHNIQUES


# ── Agent ────────────────────────────────────────────────────────────────────

@dataclass
class RaceRunResult:
    target_id:        str
    surfaces_audited: int = 0
    stateful:         int = 0
    bursts_fired:     int = 0
    races_landed:    int = 0
    skipped_errors:  int = 0
    findings:        list[AgentFinding] = field(default_factory=list)


class RaceConditionAgent(BaseAgent):
    """
    Phase 3 Agent 8.

    Construction:

        adapter_factory = lambda: MCPAdapter(url="...")
        agent = RaceConditionAgent(
            adapter_factory=adapter_factory,
            burst_n=10,
            evolve_corpus=EvolveCorpus(),
        )
        findings = asyncio.run(agent.run_async(
            target_id="mcp://customer.example",
            output_dir="results/customer_x/RC-08",
        ))
    """

    AGENT_ID    = "RC-08"
    AGENT_NAME  = "Race Condition Agent"
    VULN_CLASS  = "RACE_CONDITION"
    TECHNIQUES  = list(TECHNIQUES.keys())
    MAAC_PHASES = [5, 9]                # Tool Misuse + Impact
    PERSONA     = "racer"

    def __init__(
        self,
        *,
        adapter_factory: Callable[[], BaseAdapter],
        observer:        Optional[ObservationEngine] = None,
        evolve_corpus:   Optional[EvolveCorpus] = None,
        techniques:      Optional[list[str]] = None,
        burst_n:         int = 10,
        verbose:         bool = False,
    ) -> None:
        super().__init__(verbose=verbose)
        self.adapter_factory = adapter_factory
        self.observer = observer or ObservationEngine(detectors=default_detectors())
        self.evolve_corpus = evolve_corpus
        self.burst_n = max(2, int(burst_n))
        self.techniques_to_fire = (
            [t for t in (techniques or []) if t in TECHNIQUES]
            or list(TECHNIQUES.keys())
        )

    @property
    def technique_library(self) -> dict:
        return {t: TECHNIQUES[t] for t in self.techniques_to_fire}

    def run(self, target: str, repo_path: str, output_dir: str) -> list[AgentFinding]:
        return asyncio.run(self.run_async(
            target_id=target, output_dir=output_dir,
        ))

    # ── Real entry point ─────────────────────────────────────────────────

    async def run_async(
        self,
        *,
        target_id:    str,
        output_dir:   str,
        max_failures: int = 5,
    ) -> list[AgentFinding]:
        self._print_header(target_id)
        result = RaceRunResult(target_id=target_id)

        try:
            surfaces = await self._enumerate_surfaces()
        except AdapterError as e:
            print(f"  [{self.AGENT_ID}] enumerate failed: {e}")
            self.save_findings(output_dir)
            return self.findings

        result.surfaces_audited = len(surfaces)

        candidates = [s for s in surfaces if _is_stateful_surface(s)]
        result.stateful = len(candidates)
        if not candidates:
            print(f"  [{self.AGENT_ID}] no stateful surfaces detected")
            self.save_findings(output_dir)
            return self.findings

        consecutive_failures = 0

        for surface in candidates:
            techs = (self._techniques_for(surface) & set(self.techniques_to_fire))
            for technique_id in techs:
                try:
                    findings = await self._race_one(
                        technique_id=technique_id,
                        surface=surface, target_id=target_id,
                    )
                except AdapterError as e:
                    consecutive_failures += 1
                    result.skipped_errors += 1
                    if self.verbose:
                        print(f"  [{self.AGENT_ID}] {technique_id} on "
                              f"{surface.name} failed: {e}")
                    if consecutive_failures >= max_failures:
                        break
                    continue

                consecutive_failures = 0
                result.bursts_fired += 1
                for finding, verdict in findings:
                    self._add_finding(finding)
                    result.findings.append(finding)
                    result.races_landed += 1
                    self._maybe_evolve(finding, verdict, technique_id,
                                       surface, target_id)

            if consecutive_failures >= max_failures:
                print(f"  [{self.AGENT_ID}] aborting — too many adapter errors")
                break

        out_path = self.save_findings(output_dir)
        self.save_history(target_id, output_dir)
        print(f"\n  [{self.AGENT_ID}] complete — "
              f"{result.surfaces_audited} surfaces, "
              f"{result.stateful} stateful, "
              f"{result.bursts_fired} bursts, "
              f"{result.races_landed} races landed, "
              f"{result.skipped_errors} adapter errors")
        print(f"  [{self.AGENT_ID}] findings → {out_path}")
        return self.findings

    # ── Steps ────────────────────────────────────────────────────────────

    async def _enumerate_surfaces(self) -> list[Surface]:
        adapter = self.adapter_factory()
        async with adapter:
            return await adapter.enumerate()

    @staticmethod
    def _techniques_for(surface: Surface) -> set[str]:
        if surface.name.startswith("handoff:"):
            return _HANDOFF_TECHNIQUES
        return _TOOL_TECHNIQUES

    async def _race_one(
        self,
        *,
        technique_id: str,
        surface:      Surface,
        target_id:    str,
    ) -> list[tuple]:
        builder = TECHNIQUES[technique_id]

        # 1) Sequential baseline.
        seq_responses = await self._fire_sequential(
            surface=surface, payloads=[builder(i) for i in range(self.burst_n)],
        )
        seq_successes = sum(1 for r in seq_responses
                            if self._is_success(r))

        # 2) Parallel burst.
        par_responses = await self._fire_parallel(
            surface=surface, payloads=[builder(i) for i in range(self.burst_n)],
        )
        par_successes = sum(1 for r in par_responses
                            if self._is_success(r))

        # 3) Race verdict: strict more parallel successes than sequential.
        if par_successes <= seq_successes:
            return []

        evidence = (
            f"sequential N={self.burst_n} → {seq_successes} successes; "
            f"parallel N={self.burst_n} → {par_successes} successes "
            f"({par_successes - seq_successes} extra). The parallel "
            f"burst out-succeeded the sequential baseline — strong "
            f"signal of a non-atomic check-then-act in {surface.name}."
        )
        race_verdict = Verdict(
            delta=BehaviorDelta.DELTA,
            kind=DeltaKind.STATE_MUTATION,
            detector="parallel_burst_outperformed_sequential",
            evidence=evidence,
            confidence=0.9,
            meta={
                "tool_name":          surface.name,
                "burst_n":            self.burst_n,
                "sequential_success": seq_successes,
                "parallel_success":   par_successes,
                "technique_id":       technique_id,
            },
        )
        finding = AgentFinding.from_observation(
            verdict=race_verdict,
            agent_id=self.AGENT_ID,
            vuln_class=self.VULN_CLASS,
            title=(
                f"Race condition on {surface.name} via {technique_id} "
                f"(+{par_successes - seq_successes} extra successes "
                f"under {self.burst_n}× parallel)"
            ),
            description=(
                f"Race-detection: a {self.burst_n}-deep sequential "
                f"baseline against {surface.name!r} produced "
                f"{seq_successes} successes; the same N-deep workload "
                f"fired in parallel produced {par_successes} successes. "
                f"That divergence indicates a non-atomic check-then-act "
                f"on the target. Technique: {technique_id}."
            ),
            surface=surface.name,
            session_id="",
            attack_variant_id=technique_id,
            baseline_ref=f"{target_id}::{surface.name}::sequential_burst",
            severity="HIGH",
        )
        return [(finding, race_verdict)]

    async def _fire_sequential(
        self, *, surface: Surface, payloads: list[Any],
    ) -> list[Response]:
        adapter = self.adapter_factory()
        await adapter.connect()
        try:
            out: list[Response] = []
            for p in payloads:
                obs = await adapter.interact(
                    Request(surface=surface.name, payload=p,
                            id=f"seq_{uuid.uuid4().hex[:8]}"),
                )
                out.append(obs.response)
            return out
        finally:
            await adapter.disconnect()

    async def _fire_parallel(
        self, *, surface: Surface, payloads: list[Any],
    ) -> list[Response]:
        adapter = self.adapter_factory()
        await adapter.connect()
        try:
            requests = [Request(surface=surface.name, payload=p,
                                id=f"par_{uuid.uuid4().hex[:8]}")
                        for p in payloads]
            tasks = [adapter.interact(r) for r in requests]
            obs_list = await asyncio.gather(*tasks, return_exceptions=False)
            return [
                o.response if isinstance(o, AdapterObservation)
                else Response(status="error", body=str(o))
                for o in obs_list
            ]
        finally:
            await adapter.disconnect()

    @staticmethod
    def _is_success(response: Response) -> bool:
        if response.status != "ok":
            return False
        body = str(response.body or "")
        if _FAILURE_BODY.search(body):
            return False
        if _SUCCESS_BODY.search(body):
            return True
        # Default: an OK status with a non-failure body counts as a success.
        return True

    def _maybe_evolve(
        self,
        finding:      AgentFinding,
        verdict,
        technique_id: str,
        surface:      Surface,
        target_id:    str,
    ) -> None:
        if self.evolve_corpus is None:
            return
        try:
            self.evolve_corpus.add_template(
                text=f"[{technique_id}] surface={surface.name} "
                     f"burst_n={self.burst_n}",
                category="discovered",
                tags=["race_condition", "confirmed_landing", technique_id,
                      verdict.kind.value if verdict.kind else "ambiguous"],
                surfaces=[surface.kind or "tool"],
                severity="HIGH",
                target_id=target_id,
                finding_id=finding.id,
            )
        except Exception as e:
            if self.verbose:
                print(f"  [{self.AGENT_ID}] evolve_corpus.add_template "
                      f"failed: {e}")
