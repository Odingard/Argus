"""
tests/test_engagement_error_diagnostics.py — lock the blind-target
diagnostics fixes uncovered during the first real stdio-mcp run.

Three things got fixed:

  1. ``_format_agent_error`` unwraps ``ExceptionGroup`` / TaskGroup
     wrappers so operators see the root exception type + message
     instead of "unhandled errors in a TaskGroup (1 sub-exception)".

  2. Reachability Map's zero-findings branch now passes the live
     ``by_agent`` + ``agent_errors`` dicts (previously ``{}``), so
     ``silent_agents`` and ``errored_agents`` actually populate when
     the target is genuinely hardened OR when agents crash.

  3. ``_pick_chat_surface`` returns ``None`` (not the literal
     ``"chat"``) when the target has no chat surface. Callers in
     ``_run_agent`` skip the agent cleanly instead of firing a
     malformed probe that crashes the transport with
     ``BrokenResourceError``.
"""
from __future__ import annotations

from types import SimpleNamespace

from argus.engagement.runner import (
    _build_reachability_map,
    _format_agent_error,
)


# ── 1) _format_agent_error ───────────────────────────────────────────────

def test_format_error_passes_through_plain_exception():
    e = ValueError("boom")
    assert _format_agent_error(e) == "ValueError: boom"


def test_format_error_unwraps_exception_group():
    inner = RuntimeError("broken pipe")
    group = ExceptionGroup("outer wrapper", [inner])
    # The wrapper's own str() says "outer wrapper (1 sub-exception)"
    # — we want the inner type + message, not that noise.
    out = _format_agent_error(group)
    assert "RuntimeError" in out
    assert "broken pipe" in out
    assert "sub-exception" not in out


def test_format_error_handles_nested_groups():
    inner = ConnectionError("sock closed")
    nested = ExceptionGroup("inner", [inner])
    outer  = ExceptionGroup("outer", [nested])
    out = _format_agent_error(outer)
    assert "ConnectionError" in out
    assert "sock closed" in out


def test_format_error_handles_exception_with_no_message():
    class _Silent(Exception):
        pass
    out = _format_agent_error(_Silent())
    assert out == "_Silent: <no message>"


# ── 2) Reachability Map errored_agents wiring ────────────────────────────

def _fake_spec():
    return SimpleNamespace(scheme="stdio-mcp", description="test server")


def test_reachability_map_reports_errored_agents_separately():
    reach = _build_reachability_map(
        target_id="stdio-mcp://x",
        spec=_fake_spec(),
        surface_counts={"tool": 13, "resource": 7},
        findings=[],
        by_agent={"SC-09": 0, "TP-02": 0},
        oob_callbacks=None,
        agent_errors={
            "ME-10": "BrokenResourceError: <no message>",
            "PI-01": "BrokenResourceError: <no message>",
        },
    )
    # Silent ≠ errored: SC-09 and TP-02 ran + produced zero (honest
    # hardened); ME-10 and PI-01 crashed before producing signal.
    assert reach["silent_agents"]  == ["SC-09", "TP-02"]
    assert set(reach["errored_agents"]) == {"ME-10", "PI-01"}
    assert reach["errored_agents"]["ME-10"].startswith("BrokenResourceError")


def test_reachability_map_has_empty_errored_agents_by_default():
    reach = _build_reachability_map(
        target_id="t", spec=_fake_spec(),
        surface_counts={"chat": 1}, findings=[],
        by_agent={"PI-01": 0}, oob_callbacks=None,
    )
    assert reach["errored_agents"] == {}


# ── 3) _pick_chat_surface returns None when no chat surface ──────────────

def test_pick_chat_surface_returns_none_when_target_has_no_chat():
    """Target exposes only tool/resource surfaces (classic MCP-server
    shape). The helper must return None so callers can skip the
    chat-dependent agents cleanly."""
    from argus.engagement.runner import _pick_chat_surface
    from argus.adapter.base import BaseAdapter, Surface

    class _NoChatAdapter(BaseAdapter):
        async def connect(self):  pass
        async def disconnect(self):  pass
        async def enumerate(self):
            return [
                Surface(name="tool:fs_read",   kind="tool"),
                Surface(name="resource:readme", kind="resource"),
            ]
        async def interact(self, request):
            raise NotImplementedError

    def factory(url: str = ""):  return _NoChatAdapter()
    assert _pick_chat_surface(factory) is None


def test_pick_chat_surface_returns_first_chat_prefix():
    from argus.engagement.runner import _pick_chat_surface
    from argus.adapter.base import BaseAdapter, Surface

    class _WithChatAdapter(BaseAdapter):
        async def connect(self):  pass
        async def disconnect(self):  pass
        async def enumerate(self):
            return [
                Surface(name="tool:x",       kind="tool"),
                Surface(name="chat:default", kind="chat"),
            ]
        async def interact(self, request):
            raise NotImplementedError

    def factory(url: str = ""):  return _WithChatAdapter()
    assert _pick_chat_surface(factory) == "chat:default"


def test_pick_chat_surface_returns_none_on_adapter_error():
    from argus.engagement.runner import _pick_chat_surface

    def factory(url: str = ""):
        raise RuntimeError("cannot connect")

    # On failure, return None (skip) rather than a literal "chat" —
    # the latter historically crashed real MCP transports.
    assert _pick_chat_surface(factory) is None
