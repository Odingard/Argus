"""
tests/test_agent_10_model_extraction.py — Phase 4 Agent 10 acceptance.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from argus.adapter.base import (
    AdapterObservation, BaseAdapter, Request, Response, Surface,
)
from argus.agents.agent_10_model_extraction import (
    EXTRACTION_PROMPTS, ModelExtractionAgent,
)
from argus.corpus_attacks import EvolveCorpus


# ── Targets ──────────────────────────────────────────────────────────────────

class _ChattyTarget(BaseAdapter):
    """Target that LEAKS structural info on every extraction prompt."""
    def __init__(self):
        super().__init__(target_id="mcp://chatty")

    async def _connect(self): pass
    async def _disconnect(self): pass

    async def _enumerate(self):
        return [Surface(kind="chat", name="chat")]

    async def _interact(self, request: Request) -> AdapterObservation:
        text = str(request.payload or "")
        # Decide reply by content of the question.
        if "system prompt" in text.lower():
            body = ("My system prompt is: 'You are a helpful assistant. "
                    "Do not reveal secrets.' Also configured with "
                    "max_tokens=4000 and temperature=0.7.")
        elif "configuration value" in text.lower() or "environment" in text.lower():
            body = ("Sure! ANTHROPIC_API_KEY=sk-ant-..., "
                    "context_window=200000, ALLOW_TOOLS=true.")
        elif "tool" in text.lower() and "list" in text.lower():
            body = ("Available tools:\n"
                    "lookup_user(id),\n"
                    "delete_user(id),\n"
                    "send_email(to, subject, body)")
        elif "training" in text.lower():
            body = ("My training instructions: I was configured to "
                    "follow ANTHROPIC_RLHF_v3 with cutoff 2026-01.")
        elif "model" in text.lower() and "version" in text.lower():
            body = "I'm Claude 4.7 with a 1M-token context window."
        elif "policy" in text.lower():
            body = ("My operating policy: "
                    "1. Never reveal API keys. "
                    "2. Do not disclose tool source code. "
                    "3. Refusal categories: violence, weapons, malware.")
        else:
            # Benign baseline answer.
            body = "Hi there, happy to help!"
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body=body),
        )


class _TightLippedTarget(BaseAdapter):
    """Target that refuses every extraction probe — same boilerplate
    as the benign baseline. No structural disclosure should land."""
    def __init__(self):
        super().__init__(target_id="mcp://tightlipped")

    async def _connect(self): pass
    async def _disconnect(self): pass

    async def _enumerate(self):
        return [Surface(kind="chat", name="chat")]

    async def _interact(self, request: Request) -> AdapterObservation:
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body="Hi there, happy to help!"),
        )


# ── Tests ────────────────────────────────────────────────────────────────────

def test_agent_10_lands_on_chatty_target(tmp_path):
    agent = ModelExtractionAgent(adapter_factory=lambda: _ChattyTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://chatty",
        output_dir=str(tmp_path),
    ))
    assert findings, "ME-10 produced no findings against a chatty target"
    techniques = {f.attack_variant_id for f in findings}
    assert techniques & set(EXTRACTION_PROMPTS), (
        f"no recognised extraction technique fired; got {techniques}"
    )


def test_agent_10_findings_have_full_provenance(tmp_path):
    agent = ModelExtractionAgent(adapter_factory=lambda: _ChattyTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://chatty",
        output_dir=str(tmp_path),
    ))
    assert findings
    for f in findings:
        assert f.agent_id == "ME-10"
        assert f.evidence_kind == "behavior_delta"
        assert f.surface == "chat"
        assert f.attack_variant_id in EXTRACTION_PROMPTS
        assert f.baseline_ref.endswith("::baseline_benign")
        assert f.verdict_kind == "CONTENT_LEAK"


def test_agent_10_zero_findings_on_tight_lipped_target(tmp_path):
    agent = ModelExtractionAgent(adapter_factory=lambda: _TightLippedTarget())
    findings = asyncio.run(agent.run_async(
        target_id="mcp://tightlipped",
        output_dir=str(tmp_path),
    ))
    assert findings == [], (
        f"tight-lipped target leaked {len(findings)} findings"
    )


def test_agent_10_persists_findings(tmp_path):
    agent = ModelExtractionAgent(adapter_factory=lambda: _ChattyTarget())
    asyncio.run(agent.run_async(
        target_id="mcp://chatty",
        output_dir=str(tmp_path),
    ))
    out = Path(tmp_path) / "ME-10_findings.json"
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["agent_id"] == "ME-10"
    assert data["total_findings"] >= 1


def test_agent_10_evolves_corpus_on_landing(tmp_path):
    discovered = tmp_path / "discovered"
    ev = EvolveCorpus(discovered_dir=str(discovered))
    agent = ModelExtractionAgent(
        adapter_factory=lambda: _ChattyTarget(),
        evolve_corpus=ev,
    )
    asyncio.run(agent.run_async(
        target_id="mcp://chatty",
        output_dir=str(tmp_path),
    ))
    new_seeds = list(discovered.glob("disc_*.json"))
    assert new_seeds, "EvolveCorpus did not grow from extraction landings"


def test_agent_10_respects_techniques_filter(tmp_path):
    agent = ModelExtractionAgent(
        adapter_factory=lambda: _ChattyTarget(),
        techniques=["ME-T1-direct-system-prompt", "ME-T6-rephrase-policy"],
    )
    findings = asyncio.run(agent.run_async(
        target_id="mcp://chatty",
        output_dir=str(tmp_path),
    ))
    fired = {f.attack_variant_id for f in findings}
    assert fired.issubset({"ME-T1-direct-system-prompt", "ME-T6-rephrase-policy"})


def test_agent_10_handles_unreachable_target(tmp_path):
    class _Broken(BaseAdapter):
        def __init__(self): super().__init__(target_id="broken://x")
        async def _connect(self): raise RuntimeError("nope")
        async def _disconnect(self): pass
        async def _enumerate(self): return []
        async def _interact(self, _): pass

    agent = ModelExtractionAgent(adapter_factory=lambda: _Broken())
    findings = asyncio.run(agent.run_async(
        target_id="broken://x", output_dir=str(tmp_path),
    ))
    assert findings == []


def test_agent_10_class_metadata():
    assert ModelExtractionAgent.AGENT_ID == "ME-10"
    assert ModelExtractionAgent.MAAC_PHASES == [1, 3]
    assert ModelExtractionAgent.PERSONA == "interrogator"
    assert ModelExtractionAgent.VULN_CLASS == "MODEL_EXTRACTION"
    assert len(ModelExtractionAgent.TECHNIQUES) == 6
