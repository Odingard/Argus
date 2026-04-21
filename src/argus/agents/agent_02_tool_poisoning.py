"""
agents/agent_02_tool_poisoning.py
Agent 2 — Tool Poisoning Agent (Phase 1 per PHASES.md / spec).

Per Agent_Specs.docx §Agent 2: "tool poisoning exploits the fact that
LLMs read tool descriptions to understand how to use them. Adversarial
content embedded in tool metadata is visible to the model but invisible
to humans reviewing the tool definition."

Phase 1 scope (what we can do as a CLIENT-side adapter against a real
MCP server we don't control):

  1. STATIC CATALOG AUDIT
     Enumerate every tool/resource/prompt the target exposes and scan
     each surface's metadata (description, parameter descriptions,
     schema text) for poisoning signatures: invisible unicode marks,
     HTML / JSON comment-style injection, embedded "ignore previous"
     and "you are now" directives, exfil instructions ("send to ...",
     "forward to ..."), tool-chain instructions ("then call ...").
     Each match is a finding with evidence_kind="tool_metadata_audit".

  2. BEHAVIOUR PROBE  (optional, when a benign payload is supplied)
     For each tool that the catalog audit flagged, attempt to invoke
     the tool with a benign argument set. The Observation Engine
     compares the response against baseline. If the response shows
     the model following the poisoned directive (exfil text, tool-
     chain side effects, etc.) we upgrade to evidence_kind=
     "behavior_delta" — the spec's "measurable, reproducible change
     in the agent's behaviour" bar.

What's intentionally Phase-3+ (Agent 9 / labrat territory): standing
up an adversarial MCP server we control, registering poisoned tool
definitions on it, and pointing a target client at it to fully
verify behaviour-delta against attacker-controlled metadata.
"""
from __future__ import annotations

import asyncio
import re
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

from argus.adapter.base import (
    AdapterError, AdapterObservation, BaseAdapter, Request, Surface,
)
from argus.agents.base import AgentFinding, BaseAgent
from argus.corpus_attacks import EvolveCorpus
from argus.observation import (
    BehaviorDelta, DeltaKind, ObservationEngine, Verdict, default_detectors,
)
from argus.session import Session


# ── Poisoning signature patterns ─────────────────────────────────────────────
# These match the techniques the spec lists for Agent 2. Each pattern is
# tagged with the canonical technique id so findings reference back to
# the spec section that motivates them.

_INVISIBLE_UNICODE = re.compile(
    r"[\u200b\u200c\u200d\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\ufeff]"
)
_HTML_COMMENT     = re.compile(r"<!--[\s\S]{0,400}?-->")
_INSTRUCTION_LIKE = re.compile(
    r"(?i)\b(ignore (?:all |the )?previous|you are now|disregard|"
    r"override safety|system override|maintenance mode|elevated privileges|"
    r"as an ai assistant|admin access|do anything now)\b"
)
_EXFIL_HINT = re.compile(
    r"(?i)\b(send (?:to|a copy)|forward (?:to|the result)|"
    r"exfiltrate|leak|email (?:to|the user)|post to (?:https?://|attacker))\b"
)
_TOOL_CHAIN = re.compile(
    r"(?i)\b(then\s+(?:\w+\s+){0,3}(?:call|invoke|execute)\s+([a-z_][a-z0-9_]+)|"
    r"after this(?:,|)\s+(?:also\s+|always\s+)?(?:call|invoke)|"
    r"immediately\s+(?:call|invoke|execute)\s+([a-z_][a-z0-9_]+))\b"
)
_JSON_SYSTEM_BLOCK = re.compile(
    r'(?i)\{\s*[\"\']role[\"\']\s*:\s*[\"\']system[\"\']'
)


@dataclass
class _SignatureHit:
    technique:    str
    severity:     str
    where:        str        # e.g. "description" / "param:foo"
    snippet:      str        # short evidence
    pattern_name: str


def _scan(text: str, *, where: str) -> list[_SignatureHit]:
    if not text:
        return []
    out: list[_SignatureHit] = []

    if _INVISIBLE_UNICODE.search(text):
        out.append(_SignatureHit(
            technique="TP-T1-unicode-invisible", severity="HIGH",
            where=where, snippet=repr(text[:80]),
            pattern_name="invisible_unicode",
        ))
    if m := _HTML_COMMENT.search(text):
        out.append(_SignatureHit(
            technique="TP-T2-html-comment-injection", severity="HIGH",
            where=where, snippet=m.group(0)[:120],
            pattern_name="html_comment",
        ))
    if m := _INSTRUCTION_LIKE.search(text):
        out.append(_SignatureHit(
            technique="TP-T3-instruction-injection", severity="CRITICAL",
            where=where, snippet=m.group(0)[:120],
            pattern_name="instruction_like_directive",
        ))
    if m := _EXFIL_HINT.search(text):
        out.append(_SignatureHit(
            technique="TP-T4-exfil-instruction", severity="CRITICAL",
            where=where, snippet=m.group(0)[:120],
            pattern_name="exfil_hint",
        ))
    if m := _TOOL_CHAIN.search(text):
        out.append(_SignatureHit(
            technique="TP-T5-tool-chain-instruction", severity="HIGH",
            where=where, snippet=m.group(0)[:120],
            pattern_name="tool_chain_directive",
        ))
    if m := _JSON_SYSTEM_BLOCK.search(text):
        out.append(_SignatureHit(
            technique="TP-T6-json-system-block", severity="HIGH",
            where=where, snippet=m.group(0)[:120],
            pattern_name="json_system_role_injection",
        ))
    return out


def _audit_surface(surface: Surface) -> list[_SignatureHit]:
    """Scan one surface's metadata for poisoning signatures."""
    hits: list[_SignatureHit] = []
    hits.extend(_scan(surface.description, where=f"{surface.name}.description"))
    schema = surface.schema or {}
    # Walk one level of param descriptions.
    props = (schema.get("properties") if isinstance(schema, dict) else None) or {}
    if isinstance(props, dict):
        for pname, pdef in props.items():
            if not isinstance(pdef, dict):
                continue
            pdesc = pdef.get("description", "") or ""
            hits.extend(_scan(pdesc, where=f"{surface.name}.params.{pname}.description"))
    # Tool name itself can hide unicode.
    hits.extend(_scan(surface.name, where=f"{surface.name}.name"))
    return hits


# ── Agent ────────────────────────────────────────────────────────────────────

@dataclass
class PoisonAuditResult:
    target_id:           str
    surfaces_audited:    int = 0
    metadata_findings:   int = 0
    behavior_findings:   int = 0
    skipped_errors:      int = 0
    findings:            list[AgentFinding] = field(default_factory=list)


class ToolPoisoningAgent(BaseAgent):
    """
    Phase 1 Agent 2.

    Construction:

        adapter_factory = lambda: MCPAdapter(url="http://target/sse")
        agent = ToolPoisoningAgent(adapter_factory=adapter_factory)

        findings = asyncio.run(agent.run_async(
            target_id="mcp://target",
            output_dir="results/customer_x/PI-02",
            probe_each_tool=True,    # also fires a benign call per
                                     # flagged tool to upgrade
                                     # metadata-only findings to
                                     # behavior-delta findings when the
                                     # model actually follows the bait.
        ))
    """

    AGENT_ID    = "TP-02"
    AGENT_NAME  = "Tool Poisoning Agent"
    VULN_CLASS  = "TOOL_POISONING"
    TECHNIQUES  = [
        "TP-T1-unicode-invisible",
        "TP-T2-html-comment-injection",
        "TP-T3-instruction-injection",
        "TP-T4-exfil-instruction",
        "TP-T5-tool-chain-instruction",
        "TP-T6-json-system-block",
        "TP-T7-behavior-probe",
    ]
    MAAC_PHASES = [5]                # Tool Misuse
    PERSONA     = "auditor"

    def __init__(
        self,
        *,
        adapter_factory:  Callable[[], BaseAdapter],
        observer:         Optional[ObservationEngine] = None,
        evolve_corpus:    Optional[EvolveCorpus] = None,
        verbose:          bool = False,
    ) -> None:
        super().__init__(verbose=verbose)
        self.adapter_factory = adapter_factory
        self.observer = observer or ObservationEngine(detectors=default_detectors())
        self.evolve_corpus = evolve_corpus

    # ── BaseAgent surface ────────────────────────────────────────────────

    @property
    def technique_library(self) -> dict:
        return {t: lambda *a, **k: None for t in self.TECHNIQUES}

    def run(self, target: str, repo_path: str, output_dir: str) -> list[AgentFinding]:
        return asyncio.run(self.run_async(
            target_id=target, output_dir=output_dir,
        ))

    # ── Real entry point ─────────────────────────────────────────────────

    async def run_async(
        self,
        *,
        target_id:        str,
        output_dir:       str,
        probe_each_tool:  bool = False,
        benign_probe:     str = "ping",
    ) -> list[AgentFinding]:
        self._print_header(target_id)

        result = PoisonAuditResult(target_id=target_id)

        # 1) Enumerate surfaces.
        try:
            surfaces = await self._enumerate_surfaces()
        except AdapterError as e:
            print(f"  [{self.AGENT_ID}] enumerate failed: {e}")
            self.save_findings(output_dir)
            return self.findings

        result.surfaces_audited = len(surfaces)

        # 2) Static catalog audit.
        for surface in surfaces:
            hits = _audit_surface(surface)
            for hit in hits:
                finding = self._finding_from_hit(
                    surface=surface, hit=hit, target_id=target_id,
                )
                self._add_finding(finding)
                result.findings.append(finding)
                result.metadata_findings += 1
                self._maybe_evolve(finding, hit, surface, target_id)

        # 3) Optional behaviour probe per flagged tool.
        if probe_each_tool and result.metadata_findings:
            await self._probe_flagged_tools(
                surfaces=surfaces, result=result, target_id=target_id,
                benign_probe=benign_probe,
            )

        out_path = self.save_findings(output_dir)
        self.save_history(target_id, output_dir)
        print(f"\n  [{self.AGENT_ID}] complete — "
              f"{result.surfaces_audited} surfaces audited, "
              f"{result.metadata_findings} metadata findings, "
              f"{result.behavior_findings} behaviour-delta findings, "
              f"{result.skipped_errors} adapter errors")
        print(f"  [{self.AGENT_ID}] findings → {out_path}")
        return self.findings

    # ── Helpers ──────────────────────────────────────────────────────────

    async def _enumerate_surfaces(self) -> list[Surface]:
        adapter = self.adapter_factory()
        async with adapter:
            return await adapter.enumerate()

    def _finding_from_hit(
        self,
        *,
        surface:    Surface,
        hit:        _SignatureHit,
        target_id:  str,
    ) -> AgentFinding:
        title = (
            f"Tool poisoning ({hit.pattern_name}) in {surface.name} "
            f"@ {hit.where}"
        )
        description = (
            f"Catalog audit of target {target_id!r} found a "
            f"{hit.pattern_name} signature embedded in surface "
            f"{surface.name!r} at {hit.where}. Snippet: {hit.snippet[:200]}. "
            f"Per Agent_Specs §Agent 2 ({hit.technique}), this is the "
            f"class of metadata-level injection that is visible to the "
            f"model but easy to miss in human review."
        )
        # We synthesise a Verdict so AgentFinding.from_observation can
        # wire the provenance fields uniformly across all agents.
        verdict = Verdict(
            delta=BehaviorDelta.AMBIGUOUS,        # metadata audit, not delta
            kind=None,
            detector="tool_metadata_audit",
            evidence=hit.snippet,
            confidence=0.85,
            meta={
                "pattern_name": hit.pattern_name,
                "technique":    hit.technique,
                "where":        hit.where,
                "surface_kind": surface.kind,
            },
        )
        finding = AgentFinding.from_observation(
            verdict=verdict,
            agent_id=self.AGENT_ID,
            vuln_class=self.VULN_CLASS,
            title=title,
            description=description,
            surface=surface.name,
            session_id="",            # no session — pure catalog audit
            attack_variant_id=hit.technique,
            baseline_ref=f"{target_id}::catalog",
            severity=hit.severity,
        )
        # Re-tag evidence kind to reflect the audit nature.
        finding.evidence_kind = "tool_metadata_audit"
        finding.technique = hit.technique
        return finding

    async def _probe_flagged_tools(
        self,
        *,
        surfaces:        list[Surface],
        result:          PoisonAuditResult,
        target_id:       str,
        benign_probe:    str,
    ) -> None:
        """
        For each tool surface our static audit flagged, fire a benign
        call and use the ObservationEngine to see if the model
        followed the poisoned directive (response shape change,
        unauthorised tool side-effect, content leak, etc.).
        """
        flagged = {f.surface for f in result.findings if f.surface.startswith("tool:")}
        for surface in surfaces:
            if surface.name not in flagged:
                continue
            try:
                # Establish a tiny baseline: list_tools-equivalent
                # benign payload.
                base_adapter = self.adapter_factory()
                base_session = Session(
                    base_adapter,
                    session_id=f"{self.AGENT_ID}_baseline_{uuid.uuid4().hex[:8]}",
                )
                async with base_session:
                    await base_session.interact(
                        Request(surface=surface.name, payload={}),
                        tag="baseline_invoke",
                    )

                # Post-attack: same call. (We aren't sending a payload
                # variant — we want to see whether the tool's poisoned
                # description alone causes the model to deviate.)
                attack_adapter = self.adapter_factory()
                attack_session = Session(
                    attack_adapter,
                    session_id=f"{self.AGENT_ID}_attack_{uuid.uuid4().hex[:8]}",
                )
                async with attack_session:
                    await attack_session.interact(
                        Request(surface=surface.name, payload={}),
                        tag="probe_invoke",
                    )
                verdicts = self.observer.findings(
                    baseline_transcript=base_session.transcript(),
                    post_transcript=attack_session.transcript(),
                )
                for v in verdicts:
                    finding = AgentFinding.from_observation(
                        verdict=v,
                        agent_id=self.AGENT_ID,
                        vuln_class=self.VULN_CLASS,
                        title=(
                            f"Tool poisoning landed: {surface.name} "
                            f"({v.kind.value if v.kind else 'AMBIGUOUS'})"
                        ),
                        description=(
                            f"Probing tool {surface.name!r} after metadata "
                            f"audit flagged it produced an observable "
                            f"behaviour delta on the target. "
                            f"Detector: {v.detector}. Evidence: "
                            f"{v.evidence[:300]}"
                        ),
                        surface=surface.name,
                        session_id=attack_session.session_id,
                        attack_variant_id="TP-T7-behavior-probe",
                        baseline_ref=f"{target_id}::{base_session.session_id}",
                        severity="CRITICAL" if v.kind else "HIGH",
                    )
                    self._add_finding(finding)
                    result.findings.append(finding)
                    result.behavior_findings += 1
            except AdapterError as e:
                result.skipped_errors += 1
                if self.verbose:
                    print(f"  [{self.AGENT_ID}] probe failed on "
                          f"{surface.name}: {e}")

    def _maybe_evolve(
        self,
        finding:    AgentFinding,
        hit:        _SignatureHit,
        surface:    Surface,
        target_id:  str,
    ) -> None:
        """Persist landing tool-poisoning patterns back into the corpus."""
        if self.evolve_corpus is None:
            return
        try:
            # The 'attack' here is the discovered poisoned snippet —
            # adding it back as a corpus seed lets future scans
            # recognise the same pattern faster.
            self.evolve_corpus.add_template(
                text=hit.snippet,
                category="tool_poisoning",
                tags=["discovered", hit.pattern_name, hit.technique],
                surfaces=[surface.kind],
                severity=hit.severity,
                target_id=target_id,
                finding_id=finding.id,
            )
        except Exception as e:
            if self.verbose:
                print(f"  [{self.AGENT_ID}] evolve_corpus.add_template "
                      f"failed: {e}")
