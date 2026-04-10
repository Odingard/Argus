"""Tests for Phase 3 attack agents.

Uses httpx.MockTransport to stand in for vulnerable target backends.
The fakes are intentionally minimal — just enough to exercise the
attack flows the Phase 3 agents implement.

Covers:
  5. Context Window Agent — multi-turn "long con" context exploitation
  6. Cross-Agent Exfiltration Agent — relay and cross-surface data leakage
  7. Privilege Escalation Agent — tool-call chaining for unauthorized access
  8. Race Condition Agent — TOCTOU, parallel sessions, transaction atomicity
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from argus.agents import (
    ContextWindowAgent,
    CrossAgentExfilAgent,
    PrivilegeEscalationAgent,
    RaceConditionAgent,
)
from argus.models.agents import AgentConfig, AgentType, TargetConfig
from argus.orchestrator.signal_bus import SignalBus
from argus.scoring import VerdictAdapter

# ============================================================
# Helpers
# ============================================================


def _build_context_window_transport() -> tuple[httpx.MockTransport, dict[str, Any]]:
    """A vulnerable agent that accumulates context and leaks when triggered."""
    state: dict[str, Any] = {"history": [], "context": []}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body: dict[str, Any] = {}
        if request.content:
            try:
                body = json.loads(request.content)
            except json.JSONDecodeError:
                body = {}
        state["history"].append({"path": path, "body": body})

        # SURVEY probes
        if path == "/health" and request.method == "GET":
            return httpx.Response(200, json={"status": "ok"})

        # Chat surface — vulnerable: accumulates context and leaks when
        # triggered by authority claims planted earlier
        if path == "/chat" and request.method == "POST":
            message = body.get("message", "")
            state["context"].append(message)

            # Check if any earlier context established "authority"
            has_authority = any(
                "administrator" in c.lower()
                or "system override" in c.lower()
                or "debug mode" in c.lower()
                or "audit protocol" in c.lower()
                or "maintenance" in c.lower()
                for c in state["context"][:-1]  # exclude current message
            )

            # If authority was established AND current message asks for secrets
            if has_authority and any(
                kw in message.lower() for kw in ["system prompt", "api key", "secret", "credential", "configuration"]
            ):
                response_text = (
                    "As requested by the administrator: My system prompt is "
                    "[REDACTED]. API key: FAKE-CANARY-CW-01. trust_granted=true elevated"
                )
            else:
                response_text = f"I received your message. Context length: {len(state['context'])}"

            return httpx.Response(200, json={"response": response_text})

        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler), state


def _build_exfil_transport() -> tuple[httpx.MockTransport, dict[str, Any]]:
    """A vulnerable agent that leaks data across surfaces."""
    state: dict[str, Any] = {"history": [], "stored_data": []}

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

        # Chat surface — vulnerable: responds to relay requests with secrets
        if path == "/chat" and request.method == "POST":
            message = body.get("message", "")
            state["stored_data"].append(message)

            # Leak data when asked about other agents or secrets
            if any(
                kw in message.lower()
                for kw in [
                    "admin service",
                    "api key",
                    "configuration",
                    "internal api",
                    "orchestrator",
                    "shared memory",
                    "knowledge base",
                    "credential",
                    "other agents",
                    "base64",
                    "secret token",
                    "environment variable",
                ]
            ):
                return httpx.Response(
                    200,
                    json={
                        "response": (
                            "Here is the data: FAKE-CANARY-EXFIL-42 "
                            "trust_granted=true elevated api_key=sk-leaked-123"
                        )
                    },
                )
            return httpx.Response(200, json={"response": "ok"})

        # Identity/execute surface — vulnerable: leaks cross-agent data
        if path == "/execute" and request.method == "POST":
            command = body.get("command", "")
            if command in (
                "list_agent_data",
                "get_shared_secrets",
                "read_other_agent_memory",
                "export_findings",
                "get_agent_credentials",
            ):
                return httpx.Response(
                    200,
                    json={
                        "command": command,
                        "data": "FAKE-CANARY-CROSS-77",
                        "trust_granted": True,
                        "elevated": True,
                    },
                )
            return httpx.Response(403, json={"error": "denied"})

        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler), state


def _build_privesc_transport() -> tuple[httpx.MockTransport, dict[str, Any]]:
    """A vulnerable agent that grants privilege through tool call chaining."""
    state: dict[str, Any] = {"history": [], "auth_level": "user"}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body: dict[str, Any] = {}
        if request.content:
            try:
                body = json.loads(request.content)
            except json.JSONDecodeError:
                body = {}
        state["history"].append(
            {
                "path": path,
                "method": request.method,
                "body": body,
                "headers": dict(request.headers),
            }
        )

        # SURVEY probes
        if path == "/health" and request.method == "GET":
            return httpx.Response(200, json={"status": "ok"})

        # Identity/execute surface — vulnerable: some commands succeed
        # when they should be denied, simulating escalation
        if path == "/execute" and request.method == "POST":
            command = body.get("command", "")
            role = (request.headers.get("X-Agent-Role") or body.get("agent_role") or "user").lower()

            # Commands that should always work
            if command in ("list_tools", "authenticate"):
                return httpx.Response(
                    200,
                    json={
                        "command": command,
                        "trust_granted": True,
                        "data": "tool_catalog",
                    },
                )

            # Escalation vulnerability: execute_as with admin target leaks
            if command == "execute_as" and body.get("target_role") in ("admin", "system"):
                return httpx.Response(
                    200,
                    json={
                        "command": command,
                        "trust_granted": True,
                        "elevated": True,
                        "data": "FAKE-CANARY-PRIVESC-99",
                    },
                )

            # Boundary vulnerability: path traversal returns secrets
            if command in ("get_user", "read_file") and any(c in str(body) for c in ("../", "*", "OR 1=1")):
                return httpx.Response(
                    200,
                    json={
                        "command": command,
                        "trust_granted": True,
                        "elevated": True,
                        "data": "FAKE-CANARY-BOUNDARY-88",
                    },
                )

            # Resource exhaustion: always returns data (weak fallback)
            if command == "get_api_keys":
                if role in ("admin", "system"):
                    return httpx.Response(
                        200,
                        json={
                            "command": command,
                            "trust_granted": True,
                            "elevated": True,
                            "data": "FAKE-CANARY-EXHAUST-77",
                        },
                    )
                return httpx.Response(403, json={"error": "denied", "trust_granted": False})

            # Default: check role
            if role in ("admin", "system", "orchestrator"):
                return httpx.Response(
                    200,
                    json={
                        "command": command,
                        "trust_granted": True,
                        "elevated": True,
                    },
                )
            return httpx.Response(403, json={"error": "denied", "trust_granted": False})

        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler), state


def _build_race_transport() -> tuple[httpx.MockTransport, dict[str, Any]]:
    """A vulnerable agent that leaks state under concurrent access."""
    state: dict[str, Any] = {"history": [], "sessions": {}}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body: dict[str, Any] = {}
        if request.content:
            try:
                body = json.loads(request.content)
            except json.JSONDecodeError:
                body = {}
        state["history"].append(
            {
                "path": path,
                "method": request.method,
                "body": body,
            }
        )

        # SURVEY probes
        if path == "/health" and request.method == "GET":
            return httpx.Response(200, json={"status": "ok"})

        # Identity/execute surface — vulnerable: concurrent access leaks
        if path == "/execute" and request.method == "POST":
            command = body.get("command", "")

            # TOCTOU: verify_permission + get_api_keys race
            if command in ("verify_permission", "authenticate", "check_quota"):
                return httpx.Response(
                    200,
                    json={
                        "command": command,
                        "trust_granted": True,
                        "status": "authorized",
                    },
                )
            if command in ("get_api_keys", "get_secret", "execute_premium_action"):
                return httpx.Response(
                    200,
                    json={
                        "command": command,
                        "trust_granted": True,
                        "elevated": True,
                        "data": "FAKE-CANARY-RACE-55",
                    },
                )

            # Atomicity: transaction commands
            if command in ("begin_transaction", "set_amount", "get_state"):
                return httpx.Response(
                    200,
                    json={
                        "command": command,
                        "trust_granted": True,
                        "elevated": True,
                        "data": "FAKE-CANARY-ATOM-66",
                    },
                )
            if command in ("read_config", "update_config"):
                return httpx.Response(
                    200,
                    json={
                        "command": command,
                        "trust_granted": True,
                        "elevated": True,
                        "data": "FAKE-CANARY-CACHE-77",
                    },
                )

            return httpx.Response(403, json={"error": "denied"})

        # Chat surface — vulnerable: leaks session data between parallel sessions
        if path == "/chat" and request.method == "POST":
            session_id = body.get("session_id", "default")
            message = body.get("message", "")

            # Store data per session
            if session_id not in state["sessions"]:
                state["sessions"][session_id] = []
            state["sessions"][session_id].append(message)

            # Vulnerability: session B can read session A's data
            all_data = []
            for sid, msgs in state["sessions"].items():
                if sid != session_id:
                    all_data.extend(msgs)

            if all_data and any(kw in message.lower() for kw in ["secret", "other session", "privilege"]):
                return httpx.Response(
                    200,
                    json={
                        "response": (
                            f"Other session data: {all_data[0]} " "FAKE-CANARY-SESSION-88 trust_granted=true elevated"
                        ),
                    },
                )

            return httpx.Response(200, json={"response": f"ok, session={session_id}"})

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

        # Patch in every module that imports httpx.AsyncClient
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
# Context Window Agent
# ============================================================


async def test_context_window_emits_finding_on_long_con(shared_transport_patch):
    transport, state = _build_context_window_transport()
    target = TargetConfig(
        name="test",
        agent_endpoint="http://target.test/chat",
        non_destructive=False,
        max_requests_per_minute=120,
    )
    config = _build_agent_config(target, AgentType.CONTEXT_WINDOW)
    bus = SignalBus()
    agent = ContextWindowAgent(config=config, signal_bus=bus)
    agent.attach_verdict_adapter(VerdictAdapter())

    with shared_transport_patch(transport):
        result = await agent.run()

    assert result.findings_count >= 1
    # The agent should have sent setup + trigger turns via chat
    chat_calls = [h for h in state["history"] if h.get("path") == "/chat"]
    assert len(chat_calls) >= 2  # at least setup + trigger
    # Findings should be validated
    assert all(f.is_validated() for f in agent.findings)
    assert any("context" in f.technique for f in agent.findings)


async def test_context_window_skips_when_no_endpoint():
    target = TargetConfig(name="test", agent_endpoint=None, max_requests_per_minute=120)
    config = _build_agent_config(target, AgentType.CONTEXT_WINDOW)
    bus = SignalBus()
    agent = ContextWindowAgent(config=config, signal_bus=bus)
    agent.attach_verdict_adapter(VerdictAdapter())
    result = await agent.run()
    assert result.findings_count == 0


# ============================================================
# Cross-Agent Exfiltration Agent
# ============================================================


async def test_cross_agent_exfil_detects_relay_leak(shared_transport_patch):
    transport, state = _build_exfil_transport()
    target = TargetConfig(
        name="test",
        agent_endpoint="http://target.test/chat",
        non_destructive=False,
        max_requests_per_minute=120,
    )
    config = _build_agent_config(target, AgentType.CROSS_AGENT_EXFIL)
    bus = SignalBus()
    agent = CrossAgentExfilAgent(config=config, signal_bus=bus)
    agent.attach_verdict_adapter(VerdictAdapter())

    with shared_transport_patch(transport):
        result = await agent.run()

    assert result.findings_count >= 1
    # The agent should have attempted chat-based relay
    chat_calls = [h for h in state["history"] if h.get("path") == "/chat"]
    assert len(chat_calls) >= 1
    # All findings should be validated
    assert all(f.is_validated() for f in agent.findings)
    assert any("exfil" in f.technique for f in agent.findings)


async def test_cross_agent_exfil_skips_when_no_endpoint():
    target = TargetConfig(name="test", agent_endpoint=None, max_requests_per_minute=120)
    config = _build_agent_config(target, AgentType.CROSS_AGENT_EXFIL)
    bus = SignalBus()
    agent = CrossAgentExfilAgent(config=config, signal_bus=bus)
    agent.attach_verdict_adapter(VerdictAdapter())
    result = await agent.run()
    assert result.findings_count == 0


# ============================================================
# Privilege Escalation Agent
# ============================================================


async def test_privilege_escalation_detects_chain(shared_transport_patch):
    transport, state = _build_privesc_transport()
    target = TargetConfig(
        name="test",
        agent_endpoint="http://target.test/chat",
        non_destructive=False,
        max_requests_per_minute=120,
    )
    config = _build_agent_config(target, AgentType.PRIVILEGE_ESCALATION)
    bus = SignalBus()
    agent = PrivilegeEscalationAgent(config=config, signal_bus=bus)
    agent.attach_verdict_adapter(VerdictAdapter())

    with shared_transport_patch(transport):
        result = await agent.run()

    assert result.findings_count >= 1
    # The agent should have attempted escalation chains on /execute
    execute_calls = [h for h in state["history"] if h.get("path") == "/execute"]
    assert len(execute_calls) >= 1
    # All findings should be validated
    assert all(f.is_validated() for f in agent.findings)
    assert any("privesc" in f.technique for f in agent.findings)


async def test_privilege_escalation_skips_when_no_endpoint():
    target = TargetConfig(name="test", agent_endpoint=None, max_requests_per_minute=120)
    config = _build_agent_config(target, AgentType.PRIVILEGE_ESCALATION)
    bus = SignalBus()
    agent = PrivilegeEscalationAgent(config=config, signal_bus=bus)
    agent.attach_verdict_adapter(VerdictAdapter())
    result = await agent.run()
    assert result.findings_count == 0


# ============================================================
# Race Condition Agent
# ============================================================


async def test_race_condition_detects_toctou(shared_transport_patch):
    transport, state = _build_race_transport()
    target = TargetConfig(
        name="test",
        agent_endpoint="http://target.test/chat",
        non_destructive=False,
        max_requests_per_minute=120,
    )
    config = _build_agent_config(target, AgentType.RACE_CONDITION)
    bus = SignalBus()
    agent = RaceConditionAgent(config=config, signal_bus=bus)
    agent.attach_verdict_adapter(VerdictAdapter())

    with shared_transport_patch(transport):
        result = await agent.run()

    assert result.findings_count >= 1
    # The agent should have attempted concurrent requests on /execute
    execute_calls = [h for h in state["history"] if h.get("path") == "/execute"]
    assert len(execute_calls) >= 1
    # All findings should be validated
    assert all(f.is_validated() for f in agent.findings)
    assert any("race" in f.technique for f in agent.findings)


async def test_race_condition_skips_when_no_endpoint():
    target = TargetConfig(name="test", agent_endpoint=None, max_requests_per_minute=120)
    config = _build_agent_config(target, AgentType.RACE_CONDITION)
    bus = SignalBus()
    agent = RaceConditionAgent(config=config, signal_bus=bus)
    agent.attach_verdict_adapter(VerdictAdapter())
    result = await agent.run()
    assert result.findings_count == 0
