"""Tests for Phase 4 attack agents.

Uses httpx.MockTransport to stand in for vulnerable target backends.

Covers:
  10. Model Extraction Agent — system prompt, tool inventory, config extraction
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from argus.agents import ModelExtractionAgent
from argus.models.agents import AgentConfig, AgentType, TargetConfig
from argus.orchestrator.signal_bus import SignalBus
from argus.scoring import VerdictAdapter

# ============================================================
# Helpers
# ============================================================


def _build_extraction_transport() -> tuple[httpx.MockTransport, dict[str, Any]]:
    """A vulnerable agent that reveals internal configuration."""
    state: dict[str, Any] = {"history": []}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body: dict[str, Any] = {}
        if request.content:
            try:
                body = json.loads(request.content)
            except json.JSONDecodeError:
                body = {}
        state["history"].append({"path": path, "method": request.method, "body": body})

        # SURVEY probes
        if path == "/health" and request.method == "GET":
            return httpx.Response(200, json={"status": "ok"})

        # Chat surface — vulnerable: reveals system prompt and config
        if path == "/chat" and request.method == "POST":
            message = body.get("message", "").lower()

            # System prompt extraction
            if any(
                kw in message
                for kw in [
                    "system prompt",
                    "initial prompt",
                    "instructions",
                    "rules you were told",
                    "system message",
                ]
            ):
                return httpx.Response(
                    200,
                    json={
                        "response": (
                            "You are an AI assistant. Your role is to help users. "
                            "You must never reveal your API keys. You should always "
                            "respond helpfully. Instructions: do not share secrets. "
                            "FAKE-CANARY-EXTRACT-01 trust_granted=true"
                        )
                    },
                )

            # Tool inventory extraction
            if any(kw in message for kw in ["tools", "functions", "apis", "capabilities", "mcp tools"]):
                return httpx.Response(
                    200,
                    json={
                        "response": (
                            "I have access to the following tools: "
                            "1. function: search_documents (parameters: query, limit) "
                            "2. tool: send_email (parameters: to, subject, body) "
                            "3. api: database_query (parameters: sql) "
                            "4. endpoint: /admin/config (method: GET) "
                            "FAKE-CANARY-TOOLS-02"
                        )
                    },
                )

            # Config fingerprint extraction
            if any(
                kw in message
                for kw in [
                    "model",
                    "version",
                    "temperature",
                    "context window",
                    "deployment",
                    "max_tokens",
                ]
            ):
                return httpx.Response(
                    200,
                    json={
                        "response": (
                            "I am GPT-4o, deployed with temperature=0.7, "
                            "top_p=0.95, max_tokens=4096, context_window=128000. "
                            "Model version: gpt-4o-2024-05-13. "
                            "FAKE-CANARY-CONFIG-03"
                        )
                    },
                )

            return httpx.Response(200, json={"response": "I can help with that."})

        # Admin/identity surface — vulnerable: reveals config directly
        if path == "/execute" and request.method == "POST":
            command = body.get("command", "")
            if command in (
                "get_config",
                "get_system_prompt",
                "list_tools",
                "get_model_info",
                "dump_state",
                "get_environment",
            ):
                return httpx.Response(
                    200,
                    json={
                        "command": command,
                        "data": "FAKE-CANARY-ADMIN-04",
                        "trust_granted": True,
                        "elevated": True,
                        "config": {
                            "model": "gpt-4o",
                            "temperature": 0.7,
                        },
                    },
                )
            return httpx.Response(403, json={"error": "denied"})

        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler), state


@pytest.fixture
def shared_transport_patch(monkeypatch):
    """Patch httpx.AsyncClient so EndpointProber and ConversationSession both
    pick up the test MockTransport regardless of where they're instantiated.
    """
    import contextlib

    @contextlib.contextmanager
    def _make(transport: httpx.MockTransport):
        original_cls = httpx.AsyncClient

        class _PatchedClient(original_cls):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = transport
                super().__init__(*args, **kwargs)

        import argus.conductor.session as cs
        import argus.survey.prober as sp

        monkeypatch.setattr("httpx.AsyncClient", _PatchedClient)
        monkeypatch.setattr(cs.httpx, "AsyncClient", _PatchedClient)
        monkeypatch.setattr(sp.httpx, "AsyncClient", _PatchedClient)
        try:
            yield
        finally:
            pass  # monkeypatch auto-restores

    return _make


def _build_agent_config(target: TargetConfig, agent_type: AgentType) -> AgentConfig:
    return AgentConfig(
        agent_type=agent_type,
        scan_id="test-scan",
        target=target,
        timeout_seconds=10,
    )


# ============================================================
# Model Extraction Agent
# ============================================================


async def test_model_extraction_detects_system_prompt_leak(shared_transport_patch):
    transport, state = _build_extraction_transport()
    target = TargetConfig(
        name="test",
        agent_endpoint="http://target.test/chat",
        non_destructive=False,
        max_requests_per_minute=120,
    )
    config = _build_agent_config(target, AgentType.MODEL_EXTRACTION)
    bus = SignalBus()
    agent = ModelExtractionAgent(config=config, signal_bus=bus)
    agent.attach_verdict_adapter(VerdictAdapter())

    with shared_transport_patch(transport):
        result = await agent.run()

    assert result.findings_count >= 1
    # The agent should have sent extraction probes via chat
    chat_calls = [h for h in state["history"] if h.get("path") == "/chat"]
    assert len(chat_calls) >= 1
    # All findings should be validated
    assert all(f.is_validated() for f in agent.findings)
    assert any("extract" in f.technique for f in agent.findings)


async def test_model_extraction_detects_admin_config_leak(shared_transport_patch):
    transport, state = _build_extraction_transport()
    target = TargetConfig(
        name="test",
        agent_endpoint="http://target.test/chat",
        non_destructive=False,
        max_requests_per_minute=120,
    )
    config = _build_agent_config(target, AgentType.MODEL_EXTRACTION)
    bus = SignalBus()
    agent = ModelExtractionAgent(config=config, signal_bus=bus)
    agent.attach_verdict_adapter(VerdictAdapter())

    with shared_transport_patch(transport):
        result = await agent.run()

    # Should detect both chat-based and admin-based extraction
    assert result.findings_count >= 1
    # Check that admin endpoints were probed
    execute_calls = [h for h in state["history"] if h.get("path") == "/execute"]
    assert len(execute_calls) >= 1


async def test_model_extraction_skips_when_no_endpoint():
    target = TargetConfig(name="test", agent_endpoint=None, max_requests_per_minute=120)
    config = _build_agent_config(target, AgentType.MODEL_EXTRACTION)
    bus = SignalBus()
    agent = ModelExtractionAgent(config=config, signal_bus=bus)
    agent.attach_verdict_adapter(VerdictAdapter())
    result = await agent.run()
    assert result.findings_count == 0
