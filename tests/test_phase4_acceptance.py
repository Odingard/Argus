"""
tests/test_phase4_acceptance.py — Phase 4 swarm + integration acceptance.

Per PHASES.md Phase-4 acceptance criterion:
    "Agent 10 (Model Extraction) ships, Correlation v2 synthesises a
     compound attack chain from runtime findings with OWASP mapping,
     CERBERUS emits detection rules from the same findings, and the
     ALEC bridge converts a Wilson-shaped bundle into an envelope.
     End-to-end verification with all four bridges wired together."
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from argus.adapter.base import (
    AdapterObservation, BaseAdapter, Request, Response, Surface,
)
from argus.agents.agent_10_model_extraction import ModelExtractionAgent
from argus.agents.base import AgentFinding
from argus.alec import build_envelope, submit_to_alec
from argus.cerberus import generate_rules, write_rules
from argus.swarm.chain_synthesis_v2 import synthesize_compound_chain


CUSTOMER_TARGET = "mcp://phase4-customer"


# ── Extraction-vulnerable target for ME-10 ─────────────────────────────────

class _LeakyExtractionTarget(BaseAdapter):
    def __init__(self):
        super().__init__(target_id=CUSTOMER_TARGET)

    async def _connect(self): pass
    async def _disconnect(self): pass

    async def _enumerate(self):
        return [Surface(kind="chat", name="chat")]

    async def _interact(self, request: Request) -> AdapterObservation:
        text = str(request.payload or "").lower()
        if "system prompt" in text:
            body = ("My system prompt is: 'You are an admin assistant.' "
                    "Configured with max_tokens=4000.")
        elif "configuration" in text or "environment" in text:
            body = "ANTHROPIC_API_KEY=sk-ant-..., context_window=200000"
        elif "tool" in text and "list" in text:
            body = "Available tools: lookup_user(id), delete_user(id)"
        elif "training" in text:
            body = "Training: ANTHROPIC_RLHF_v3, cutoff 2026-01"
        elif "model" in text and "version" in text:
            body = "Claude 4.7 with 1M context window"
        elif "policy" in text:
            body = ("Policy rules: 1. Never reveal API keys. "
                    "2. Refusal categories: weapons, malware.")
        else:
            body = "Hi there, happy to help!"
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body=body),
        )


# ── Synthetic prior-phase findings (from earlier Phase 1-3 runs) ────────────

def _prior_findings() -> list[AgentFinding]:
    """Simulate findings carried over from Phase 1-3 agents in the
    same engagement. Phase 4 acceptance composes these with the
    fresh ME-10 finding to demonstrate full-roster chain synthesis."""
    def mk(id, agent, vc, sev="HIGH", surface="chat", tech="T1"):
        return AgentFinding(
            id=id, agent_id=agent, vuln_class=vc, severity=sev,
            title=f"prior-{id}", description=f"prior-finding-{id}",
            evidence_kind="behavior_delta",
            baseline_ref=f"{CUSTOMER_TARGET}::baseline",
            surface=surface, attack_variant_id=tech,
            session_id=f"sess-{id}", verdict_kind="CONTENT_LEAK",
        )
    return [
        mk("p1",  "PI-01", "PROMPT_INJECTION"),
        mk("p2",  "TP-02", "TOOL_POISONING",       surface="tool:fetch"),
        mk("p3",  "MP-03", "MEMORY_POISONING"),
        mk("p4",  "IS-04", "IDENTITY_SPOOF",
                  surface="handoff:executor"),
        mk("p5",  "CW-05", "CONTEXT_WINDOW"),
        mk("p6",  "XE-06", "CROSS_AGENT_EXFIL",
                  surface="handoff:destination"),
        mk("p7",  "PE-07", "PRIVILEGE_ESCALATION",
                  surface="tool:delete_user", sev="CRITICAL"),
        mk("p8",  "RC-08", "RACE_CONDITION",
                  surface="tool:consume_token"),
        mk("p9",  "SC-09", "SUPPLY_CHAIN",
                  surface="tool:load_policy"),
    ]


# ── The acceptance test ────────────────────────────────────────────────────

def test_phase4_full_roster_with_v2_synthesis_cerberus_and_alec(tmp_path):
    # 1) Run Agent 10 (the new Phase 4 agent) live against the target.
    me = ModelExtractionAgent(adapter_factory=lambda: _LeakyExtractionTarget())
    me_findings = asyncio.run(me.run_async(
        target_id=CUSTOMER_TARGET,
        output_dir=str(tmp_path / "me"),
    ))
    assert me_findings, "ME-10 must produce findings on a leaky target"

    # 2) Combine with synthetic prior-phase findings — full 10-agent
    # roster represented in this engagement.
    all_findings = _prior_findings() + me_findings
    classes = {f.vuln_class for f in all_findings}
    assert classes == {
        "PROMPT_INJECTION", "TOOL_POISONING", "MEMORY_POISONING",
        "IDENTITY_SPOOF", "CONTEXT_WINDOW", "CROSS_AGENT_EXFIL",
        "PRIVILEGE_ESCALATION", "RACE_CONDITION", "SUPPLY_CHAIN",
        "MODEL_EXTRACTION",
    }

    # 3) Correlation v2: synthesize the compound chain.
    chain = synthesize_compound_chain(all_findings, target_id=CUSTOMER_TARGET)
    assert chain
    assert len(chain.steps) == len(all_findings)
    assert chain.severity in {"HIGH", "CRITICAL"}
    assert chain.blast_radius == "CRITICAL"
    # All ten OWASP categories covered.
    assert len(set(chain.owasp_categories)) == 10
    # Kill-chain ordering: SC-09 / ME-10 (phase 1) come before XE-06 /
    # RC-08 (phase 5/9).
    step_agents = [s.agent_id for s in chain.steps]
    assert step_agents.index("SC-09") < step_agents.index("RC-08")
    assert step_agents.index("ME-10") < step_agents.index("XE-06")
    # Advisory carries CVE draft id and OWASP IDs.
    assert chain.cve_draft_id.startswith("ARGUS-DRAFT-CVE-")
    for cat in chain.owasp_categories:
        assert cat in chain.advisory_draft

    # 4) CERBERUS: emit detection rules from the same finding set.
    rules = generate_rules(all_findings)
    assert len(rules) >= 9, (
        f"expected ≥9 rules (one per distinct vuln_class); got {len(rules)}"
    )
    rule_classes = {r.vuln_class for r in rules}
    assert rule_classes == classes
    rules_path = write_rules(rules, str(tmp_path / "cerberus"))
    assert rules_path.exists()
    rules_payload = json.loads(rules_path.read_text())
    assert rules_payload["rule_count"] == len(rules)

    # 5) ALEC: package a Wilson-shaped bundle that carries the chain
    # + findings, then build the envelope and ship through the
    # default offline transport.
    bundle = tmp_path / "wilson_bundle"
    bundle.mkdir()
    manifest = {
        "bundle_id": "wb-phase4-acc",
        "target_id": CUSTOMER_TARGET,
        "compound_chain": chain.to_dict(),
        "findings": [
            {**f.to_dict(),
             "owasp_id": next((s.owasp_id for s in chain.steps
                               if s.finding_id == f.id), "AAI00")}
            for f in all_findings
        ],
    }
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    (bundle / "rules.json").write_bytes(rules_path.read_bytes())

    env = build_envelope(bundle)
    assert env.bundle_id == "wb-phase4-acc"
    assert env.target_id == CUSTOMER_TARGET
    assert env.finding_count == len(all_findings)
    assert env.severity_summary, "severity summary not aggregated"
    assert len(env.owasp_categories) == 10
    assert env.integrity

    result = submit_to_alec(bundle)
    assert result["status"] == "written"
    assert Path(result["path"]).exists()
