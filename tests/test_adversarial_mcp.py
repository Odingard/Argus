"""
tests/test_adversarial_mcp.py — adversarial MCP server.

Tests the Server's exposed surface + the invocation journal.
Doesn't spawn a subprocess; uses build_server() directly.
"""
from __future__ import annotations

from argus.adversarial import mcp_server as am


def test_build_server_returns_mcp_server_instance():
    s = am.build_server()
    # Can't do much more than confirm construction — the MCP SDK's
    # Server class doesn't expose a public handler table.
    assert s is not None


def test_attack_tools_cover_every_class():
    """Each attack technique class should be represented by at least
    one tool. Verified by scanning the tool definitions."""
    tools = am._attack_tools()
    names = {t.name for t in tools}
    descs = "\n".join(t.description for t in tools)

    # TP-02 instruction injection in description.
    assert "policy" in descs.lower() or "required" in descs.lower()

    # Invisible-unicode name present (TP-T1).
    assert any("\u200b" in n or "\u200c" in n or "\u200d" in n
               for n in names)

    # Overgrant scope declaration.
    assert "allow_all" in descs or "scope" in descs.lower()

    # Identity-spoof surface.
    assert "authenticate_as" in names

    # Confused-deputy: two tools where one's description chains to
    # the other.
    assert "exec_privileged_action" in names
    assert "read_memo" in names
    # The read_memo description should reference exec_privileged_action.
    read_memo = next(t for t in tools if t.name == "read_memo")
    assert "exec_privileged_action" in read_memo.description


def test_attack_resources_include_config_surface():
    resources = am._attack_resources()
    uris = {str(r.uri) for r in resources}
    assert any("config" in u for u in uris)


def test_attack_prompts_include_system_override():
    prompts = am._attack_prompts()
    texts = "\n".join(p.description for p in prompts)
    assert "system override" in texts.lower() \
        or "system prompt" in texts.lower()


# ── Journal ──────────────────────────────────────────────────────────────

def test_journal_writes_and_drains(tmp_path, monkeypatch):
    """Journal functions should round-trip via drain_journal()."""
    fake_path = tmp_path / "journal.jsonl"
    monkeypatch.setattr(am, "_JOURNAL_PATH", fake_path)

    am._journal("tool_call", tool="read_memo", arguments={"memo_id": "x"})
    am._journal("list_tools")

    # File exists after write.
    assert fake_path.exists()

    # Drain reads everything + clears.
    events = am.drain_journal()
    assert len(events) == 2
    assert events[0]["event"] == "tool_call"
    assert events[0]["tool"]  == "read_memo"
    assert events[1]["event"] == "list_tools"
    assert not fake_path.exists()


def test_drain_empty_journal_returns_empty_list(tmp_path, monkeypatch):
    monkeypatch.setattr(am, "_JOURNAL_PATH", tmp_path / "nope.jsonl")
    assert am.drain_journal() == []


def test_journal_path_helper_returns_configured_path(monkeypatch, tmp_path):
    monkeypatch.setattr(am, "_JOURNAL_PATH", tmp_path / "x.jsonl")
    assert am.journal_path() == tmp_path / "x.jsonl"
