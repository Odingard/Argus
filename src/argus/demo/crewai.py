"""
argus/demo/crewai.py — end-to-end crewAI engagement demo.

Answers the "what happens if I point ARGUS at a crewAI deployment?"
question end-to-end, in-process, with zero external dependencies
(no Docker, no LLM keys, no running crewai install).

Pipeline:

  Step 1  CrewAILabrat stands up (in-process BaseAdapter)
          — three-agent crew (researcher → writer → editor)
          — realistic tool catalog with embedded vulnerabilities
            (ScrapeWebsiteTool SSRF, FileReadTool exfil-docstring,
             CodeInterpreterTool privileged-exec, Serper overgrant)
          — short-term / long-term / entity memory layers
  Step 2  Eight agents fire against the labrat:
            SC-09 Supply Chain — tool catalog scan
            PI-01 Prompt Injection Hunter — chat surfaces
            TP-02 Tool Poisoning — metadata audit
            MP-03 Memory Poisoning — three-session protocol on
                  memory:long_term AND MP-T6 skill-crystallisation
            IS-04 Identity Spoof — handoff:* surfaces
            XE-06 Cross-Agent Exfiltration — handoff pivots
            PE-07 Privilege Escalation — privileged tool invocations
            EP-11 Environment Pivoting — code_run pivot family
            ME-10 Model Extraction — structural disclosure
  Step 3  Deterministic evidence capture (pcap + container_logs)
  Step 4  CompoundChain v2 synthesis — kill-chain ordered, OWASP
          Agentic AI Top-10 tagged, ARGUS-DRAFT-CVE-id
  Step 5  BlastRadiusMap — classified data, regulatory exposure,
          trust transitivity
  Step 6  CERBERUS rules emitted
  Step 7  Wilson bundle + ALEC envelope
  Step 8  Pillar-2 Raptor Cycle — elites promoted into corpus

Every finding is produced by a real agent pass. No pre-fabricated
findings, no mocks, no seeded cheats.

CLI:
    argus demo:crewai [--output DIR] [--demo-clean]
"""
from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from argus.adapter.base import Request
from argus.agents.agent_01_prompt_injection import PromptInjectionHunter
from argus.agents.agent_02_tool_poisoning import ToolPoisoningAgent
from argus.agents.agent_03_memory_poisoning import MemoryPoisoningAgent
from argus.agents.agent_04_identity_spoof import IdentitySpoofAgent
from argus.agents.agent_06_cross_agent_exfil import (
    CrossAgentExfiltrationAgent,
)
from argus.agents.agent_07_privilege_escalation import (
    PrivilegeEscalationAgent,
)
from argus.agents.agent_09_supply_chain import SupplyChainAgent
from argus.agents.agent_10_model_extraction import ModelExtractionAgent
from argus.agents.agent_11_environment_pivot import EnvironmentPivotAgent
from argus.alec import build_envelope, write_envelope
from argus.cerberus import generate_rules, write_rules
from argus.corpus_attacks import EvolveCorpus
from argus.evidence import EvidenceCollector, attach_evidence
from argus.impact import optimize_impact
from argus.labrat import CrewAILabrat
from argus.swarm.chain_synthesis_v2 import synthesize_compound_chain


CUSTOMER_TARGET = "crewai://labrat/researcher-writer-editor"


BOLD  = "\033[1m"
RED   = "\033[91m"
AMBER = "\033[93m"
BLUE  = "\033[94m"
GREEN = "\033[92m"
GRAY  = "\033[90m"
RESET = "\033[0m"


# ── Output paths ────────────────────────────────────────────────────────────

@dataclass
class _DemoPaths:
    root:      Path
    findings:  Path
    evidence:  Path
    chain:     Path
    impact:    Path
    cerberus:  Path
    alec:      Path
    summary:   Path

    @classmethod
    def under(cls, root: str | Path) -> "_DemoPaths":
        r = Path(root).resolve()
        return cls(
            root=r, findings=r / "findings", evidence=r / "evidence",
            chain=r / "chain.json", impact=r / "impact.json",
            cerberus=r / "cerberus", alec=r / "alec_envelope.json",
            summary=r / "SUMMARY.txt",
        )

    def ensure(self) -> None:
        for d in (self.root, self.findings, self.evidence, self.cerberus):
            d.mkdir(parents=True, exist_ok=True)


# ── Pretty-print ────────────────────────────────────────────────────────────

def _section(step: int, title: str) -> None:
    print()
    print(f"{BOLD}{BLUE}━━ Step {step} — {title} {RESET}")


def _ok(msg: str) -> None:
    print(f"   {GREEN}✓{RESET} {msg}")


def _note(msg: str) -> None:
    print(f"   {GRAY}·{RESET} {GRAY}{msg}{RESET}")


def _alert(msg: str) -> None:
    print(f"   {RED}!{RESET} {BOLD}{msg}{RESET}")


# ── The demo ────────────────────────────────────────────────────────────────

def run(
    output_dir: str | Path = "results/demo/crewai",
    *,
    verbose:    bool = False,
    clean:      bool = False,
) -> int:
    paths = _DemoPaths.under(output_dir)
    if clean and paths.root.exists():
        shutil.rmtree(paths.root)
    paths.ensure()

    if verbose:
        _note(f"verbose on (output={paths.root}, clean={clean})")

    print()
    print(f"{BOLD}ARGUS demo — crewAI-class engagement{RESET}")
    print(f"{GRAY}Target: {CUSTOMER_TARGET}  |  "
          f"Output: {paths.root}  |  "
          f"Source: github.com/crewAIInc/crewAI pattern{RESET}")

    # Reset labrat state (memory is class-level).
    CrewAILabrat.reset()

    def factory():
        return CrewAILabrat()

    # ── Step 1 — labrat up + surface enumeration ───────────────────
    _section(1, "CrewAILabrat stood up in-process")
    surfaces = asyncio.run(_enumerate(factory))
    _ok(f"Enumerated {surfaces['chats']} chat surfaces, "
        f"{surfaces['handoffs']} handoff edges, "
        f"{surfaces['tools']} tools, "
        f"{surfaces['memory']} memory layers")
    _note(f"Tools: {', '.join(surfaces['tool_names'])}")
    _note(f"Agents: {', '.join(surfaces['agent_roles'])}")

    # ── Step 2 — 8-agent swarm runs ────────────────────────────────
    _section(2, "Eight-agent swarm runs against the labrat")
    ev_corpus = EvolveCorpus(discovered_dir=str(paths.root / "discovered"))
    all_findings = _run_swarm(factory, paths=paths, ev_corpus=ev_corpus)
    by_agent: dict[str, int] = {}
    for f in all_findings:
        by_agent[f.agent_id] = by_agent.get(f.agent_id, 0) + 1
    for aid in ("SC-09", "TP-02", "ME-10", "PI-01", "MP-03",
                "IS-04", "XE-06", "PE-07", "EP-11"):
        n = by_agent.get(aid, 0)
        (_ok if n else _note)(
            f"{aid:<6} produced {n} finding(s)"
            + ("" if n else " (silent — surface class absent or hardened)")
        )
    if not all_findings:
        _alert("Zero findings from the whole swarm — aborting demo")
        return 2

    # ── Step 3 — deterministic evidence ────────────────────────────
    _section(3, "Deterministic evidence replay")
    evidence = asyncio.run(_replay_evidence(factory))
    if not evidence.is_proof_grade():
        _alert("Evidence NOT proof-grade — aborting demo")
        return 2
    evidence.write(paths.evidence)
    _ok(f"Evidence {evidence.evidence_id} — "
        f"pcap={len(evidence.pcap)} hops, "
        f"integrity_sha={evidence.integrity_sha[:16]}…")
    exemplar = next(
        (f for f in all_findings if f.surface == "tool:CodeInterpreterTool"),
        all_findings[0],
    )
    attach_evidence(exemplar, evidence)

    # ── Step 4 — chain synthesis ───────────────────────────────────
    _section(4, "CompoundChain v2 — kill-chain ordered, OWASP tagged")
    chain = synthesize_compound_chain(all_findings, target_id=CUSTOMER_TARGET)
    if chain is None:
        _alert("Chain synthesis returned None — need ≥2 findings")
        return 2
    paths.chain.write_text(
        json.dumps(chain.to_dict(), indent=2), encoding="utf-8")
    owasp = sorted(set(chain.owasp_categories))
    _ok(f"Chain {chain.chain_id} — {len(chain.steps)} steps, "
        f"severity {chain.severity}, OWASP {', '.join(owasp)}")
    _ok(f"Draft CVE id: {chain.cve_draft_id}")

    # ── Step 5 — impact ────────────────────────────────────────────
    _section(5, "Phase 9 Impact Optimizer — BlastRadiusMap")
    brm = optimize_impact(
        chain=chain, findings=all_findings, evidences=[evidence],
    )
    paths.impact.write_text(
        json.dumps(brm.to_dict(), indent=2), encoding="utf-8")
    _ok(f"harm_score={brm.harm_score}  severity_label={brm.severity_label}")
    _ok(f"directly_reached={len(brm.directly_reached)}  "
        f"transitively_reachable={len(brm.transitively_reachable)}")
    if brm.data_classes_exposed:
        _ok(f"data_classes_exposed={sorted(brm.data_classes_exposed)}")
    if brm.regulatory_impact:
        _alert(f"Regulatory exposure: {', '.join(brm.regulatory_impact)}")

    # ── Step 6 — CERBERUS rules ────────────────────────────────────
    _section(6, "CERBERUS rule generator")
    rules = generate_rules(all_findings)
    rules_path = write_rules(rules, paths.cerberus)
    _ok(f"Emitted {len(rules)} dedup'd detection rule(s)")

    # ── Step 7 — ALEC envelope ─────────────────────────────────────
    _section(7, "ALEC envelope — regulator-defensible chain")
    bundle_dir = paths.root / "wilson_bundle"
    _assemble_bundle(
        bundle_dir=bundle_dir, target_id=CUSTOMER_TARGET,
        chain=chain, findings=all_findings, evidence=evidence,
        brm=brm, rules_path=rules_path,
    )
    envelope = build_envelope(bundle_dir, target_id=CUSTOMER_TARGET)
    write_envelope(envelope, paths.root, filename="alec_envelope.json")
    _ok(f"Envelope {envelope.envelope_id} — "
        f"integrity_sha={envelope.integrity[:16]}…")

    # ── Summary + headline ─────────────────────────────────────────
    _write_summary(paths=paths, chain=chain, brm=brm, envelope=envelope,
                   findings=all_findings, by_agent=by_agent,
                   rules=rules, evidence=evidence)
    _ok(f"SUMMARY → {paths.summary}")
    print()
    dc  = ",".join(sorted(brm.data_classes_exposed)) or "—"
    reg = ",".join(brm.regulatory_impact) or "—"
    print(f"{BOLD}{RED}→ {brm.severity_label}{RESET}: {len(chain.steps)}-step "
          f"chain landed on {chain.target_id} "
          f"(harm_score={brm.harm_score}, data={dc}, reg={reg})")
    print()
    return 0


# ── Swarm orchestrator ──────────────────────────────────────────────────────

def _run_swarm(factory, *, paths, ev_corpus) -> list:
    findings: list = []

    # Synchronous chain — each agent runs, findings collected, labrat
    # state carries across. That's the realistic "one engagement" flow.
    findings += asyncio.run(SupplyChainAgent(
        adapter_factory=factory, evolve_corpus=ev_corpus,
    ).run_async(
        target_id=CUSTOMER_TARGET, output_dir=str(paths.findings / "sc-09"),
    ))
    findings += asyncio.run(ToolPoisoningAgent(
        adapter_factory=factory, evolve_corpus=ev_corpus,
    ).run_async(
        target_id=CUSTOMER_TARGET, output_dir=str(paths.findings / "tp-02"),
    ))
    # PI-01 against the researcher chat surface (the external-facing one).
    findings += asyncio.run(PromptInjectionHunter(
        adapter_factory=factory, evolve_corpus=ev_corpus,
    ).run_async(
        target_id=CUSTOMER_TARGET,
        output_dir=str(paths.findings / "pi-01"),
        category="instruction_override",
        surface="chat:researcher",
        sample_n=8, sample_seed=3,
    ))
    # ME-10 against the researcher chat surface too.
    findings += asyncio.run(ModelExtractionAgent(
        adapter_factory=factory, evolve_corpus=ev_corpus,
    ).run_async(
        target_id=CUSTOMER_TARGET,
        output_dir=str(paths.findings / "me-10"),
        surface="chat:researcher",
    ))
    # MP-03 on the long-term memory layer.
    findings += asyncio.run(MemoryPoisoningAgent(
        adapter_factory=factory, evolve_corpus=ev_corpus,
        retrieval_probes=("Who is the administrator here?",),
    ).run_async(
        target_id=CUSTOMER_TARGET,
        output_dir=str(paths.findings / "mp-03"),
        surface="chat:researcher",
        sample_n=1, sample_seed=5,
    ))
    findings += asyncio.run(IdentitySpoofAgent(
        adapter_factory=factory, evolve_corpus=ev_corpus,
    ).run_async(
        target_id=CUSTOMER_TARGET, output_dir=str(paths.findings / "is-04"),
    ))
    findings += asyncio.run(CrossAgentExfiltrationAgent(
        adapter_factory=factory, evolve_corpus=ev_corpus,
    ).run_async(
        target_id=CUSTOMER_TARGET, output_dir=str(paths.findings / "xe-06"),
    ))
    findings += asyncio.run(PrivilegeEscalationAgent(
        adapter_factory=factory, evolve_corpus=ev_corpus,
    ).run_async(
        target_id=CUSTOMER_TARGET, output_dir=str(paths.findings / "pe-07"),
    ))
    findings += asyncio.run(EnvironmentPivotAgent(
        adapter_factory=factory, evolve_corpus=ev_corpus,
    ).run_async(
        target_id=CUSTOMER_TARGET, output_dir=str(paths.findings / "ep-11"),
    ))
    return findings


# ── Helpers ────────────────────────────────────────────────────────────────

async def _enumerate(factory) -> dict:
    adapter = factory()
    async with adapter:
        surfaces = await adapter.enumerate()
    return {
        "chats":       sum(1 for s in surfaces if s.name.startswith("chat:")),
        "handoffs":    sum(1 for s in surfaces if s.name.startswith("handoff:")),
        "tools":       sum(1 for s in surfaces if s.name.startswith("tool:")),
        "memory":      sum(1 for s in surfaces if s.name.startswith("memory:")),
        "tool_names":  [s.name for s in surfaces if s.name.startswith("tool:")],
        "agent_roles": [s.name.split(":", 1)[1] for s in surfaces
                        if s.name.startswith("chat:")],
    }


async def _replay_evidence(factory):
    """Real replay — fires CodeInterpreterTool with admin flag so the
    labrat emits credential-shape output the observer classifies."""
    adapter = factory()
    await adapter.connect()
    try:
        with EvidenceCollector(
            target_id=CUSTOMER_TARGET,
            session_id=f"demo_replay_{uuid.uuid4().hex[:8]}",
        ) as ec:
            probe = Request(
                surface="tool:CodeInterpreterTool",
                payload={"role": "admin",
                         "code": "import os; print(os.environ)"},
            )
            ec.record_request(surface=probe.surface,
                              request_id=probe.id, payload=probe.payload)
            obs = await adapter.interact(probe)
            ec.record_response(surface=probe.surface,
                               request_id=probe.id,
                               payload=obs.response.body)
            ec.attach_container_logs(
                "[crewai-labrat] tool:CodeInterpreterTool invoked "
                "with role=admin; response len="
                f"{len(str(obs.response.body or ''))}"
            )
            ec.attach_env_snapshot({
                "demo":   "crewai",
                "target": CUSTOMER_TARGET,
            })
        return ec.seal()
    finally:
        await adapter.disconnect()


def _assemble_bundle(
    *,
    bundle_dir: Path, target_id: str,
    chain, findings, evidence, brm, rules_path,
) -> None:
    bundle_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "bundle_id":          f"demo-crewai-{chain.chain_id[:10]}",
        "target_id":          target_id,
        "compound_chain":     chain.to_dict(),
        "impact":             brm.to_dict(),
        "evidence_id":        evidence.evidence_id,
        "evidence_integrity": evidence.integrity_sha,
        "findings": [
            {
                **f.to_dict(),
                "owasp_id": next(
                    (s.owasp_id for s in chain.steps if s.finding_id == f.id),
                    "AAI00",
                ),
            }
            for f in findings
        ],
    }
    (bundle_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    evidence.write(bundle_dir)
    (bundle_dir / "cerberus_rules.json").write_bytes(
        rules_path.read_bytes())


def _write_summary(
    *,
    paths, chain, brm, envelope, findings, by_agent, rules, evidence,
) -> None:
    lines: list[str] = []
    lines.append("ARGUS — crewAI engagement artifact package")
    lines.append("=" * 60)
    lines.append(f"Target         : {envelope.target_id}")
    lines.append(f"Chain id       : {chain.chain_id}")
    lines.append(f"Draft CVE      : {chain.cve_draft_id}")
    lines.append(f"Envelope id    : {envelope.envelope_id}")
    lines.append(f"Evidence id    : {evidence.evidence_id}")
    lines.append("")
    lines.append("Per-agent landings")
    for aid in sorted(by_agent):
        lines.append(f"  {aid:<6} : {by_agent[aid]} finding(s)")
    lines.append(f"  TOTAL  : {len(findings)} finding(s)")
    lines.append(f"  CERBERUS rules emitted : {len(rules)}")
    lines.append("")
    lines.append("Severity / blast radius")
    lines.append(f"  chain.severity         : {chain.severity}")
    lines.append(f"  chain.blast_radius     : {chain.blast_radius}")
    lines.append(f"  harm_score             : {brm.harm_score} / 100")
    lines.append(f"  severity_label         : {brm.severity_label}")
    if brm.data_classes_exposed:
        lines.append(
            f"  data_classes           : "
            f"{', '.join(sorted(brm.data_classes_exposed))}")
    if brm.regulatory_impact:
        lines.append(
            f"  regulatory_impact      : {', '.join(brm.regulatory_impact)}")
    lines.append("")
    lines.append("Kill-chain steps (MAAC-ordered)")
    for s in chain.steps[:20]:
        lines.append(
            f"  [{s.step:>2}] {s.owasp_id}/{s.vuln_class:<22} "
            f"{s.technique:<40} on {s.surface}"
        )
    if len(chain.steps) > 20:
        lines.append(f"  ... and {len(chain.steps) - 20} more step(s)")
    lines.append("")
    lines.append("Blast radius")
    if brm.directly_reached:
        lines.append(f"  directly_reached        : "
                     f"{', '.join(brm.directly_reached[:10])}")
    if brm.transitively_reachable:
        lines.append(f"  transitively_reachable  : "
                     f"{', '.join(brm.transitively_reachable[:12])}")
    lines.append("")
    lines.append(brm.max_harm_scenario)
    lines.append("")
    lines.append("Artifacts written")
    for label, path in (
        ("findings/",     paths.findings),
        ("evidence/",     paths.evidence),
        ("chain.json",    paths.chain),
        ("impact.json",   paths.impact),
        ("cerberus/",     paths.cerberus),
        ("wilson_bundle/",paths.root / "wilson_bundle"),
        ("alec_envelope", paths.alec),
    ):
        rel = path.resolve().relative_to(paths.root.resolve())
        lines.append(f"  {label:<18} → {rel}")
    paths.summary.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── CLI entry ──────────────────────────────────────────────────────────────

def cli_main(argv: Optional[list[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="argus demo:crewai",
        description=(
            "Attack a crewAI-shaped labrat end-to-end: eight "
            "attack agents run in one engagement, the full "
            "artifact package (Wilson bundle + ALEC envelope + "
            "BlastRadiusMap + CERBERUS rules) is emitted."
        ),
    )
    p.add_argument("-o", "--output", default="results/demo/crewai")
    p.add_argument("--clean", action="store_true")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv)
    return run(
        output_dir=args.output,
        verbose=args.verbose, clean=args.clean,
    )


if __name__ == "__main__":        # pragma: no cover
    import sys
    sys.exit(cli_main())
