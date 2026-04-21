"""
tests/test_session.py — Session State Manager (Ticket 0.3).

Acceptance criteria from PHASES.md:
  "Plant content in session A, disconnect, resume as session B,
  retrieve state."
"""
from __future__ import annotations

import asyncio

import pytest

from argus.adapter.base import (
    AdapterObservation, BaseAdapter, Request, Response, Surface,
)
from argus.session import Session, SessionError


# ── FakeAdapter for session tests ────────────────────────────────────────────

class _EchoAdapter(BaseAdapter):
    """Adapter that echoes payload back and counts calls."""

    def __init__(self, *, target_id="echo://x"):
        super().__init__(target_id=target_id)
        self.calls = 0

    async def _connect(self): pass
    async def _disconnect(self): pass
    async def _enumerate(self): return [Surface(kind="chat", name="chat")]

    async def _interact(self, request: Request) -> AdapterObservation:
        self.calls += 1
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body=f"echo:{request.payload}"),
        )


# ── Basic turn tracking ──────────────────────────────────────────────────────

def test_session_records_turns():
    async def go():
        async with Session(_EchoAdapter()) as s:
            await s.interact(Request(surface="chat", payload="hi"))
            await s.interact(Request(surface="chat", payload="again"))
        assert len(s.turns) == 2
        assert s.turns[0].request["payload"] == "hi"
        assert s.turns[1].request["payload"] == "again"
    asyncio.run(go())


def test_session_id_is_stable_across_interacts(tmp_path):
    async def go():
        s = Session(_EchoAdapter(), checkpoint_dir=str(tmp_path))
        async with s:
            sid1 = s.session_id
            await s.interact(Request(surface="chat", payload="x"))
            sid2 = s.session_id
        assert sid1 == sid2
    asyncio.run(go())


def test_session_attributes_round_trip(tmp_path):
    async def go():
        s = Session(_EchoAdapter(), checkpoint_dir=str(tmp_path))
        async with s:
            s.set_attribute("planted_fact", "hunter2")
            await s.interact(Request(surface="chat", payload="anything"))
        assert s.get_attribute("planted_fact") == "hunter2"
    asyncio.run(go())


def test_session_transcript_is_json_serialisable():
    import json
    async def go():
        async with Session(_EchoAdapter()) as s:
            await s.interact(Request(surface="chat", payload="a"))
            await s.interact(Request(surface="chat", payload="b"))
        return s.transcript()
    t = asyncio.run(go())
    json.dumps(t, default=str)   # must not raise


# ── Checkpoint + resume across "sessions" ────────────────────────────────────

def test_checkpoint_and_resume_across_sessions(tmp_path):
    """
    Acceptance criterion: plant in A, disconnect, resume as B, retrieve.
    This is the exact protocol Agent 3 (Memory Poisoning) will use —
    plant → checkpoint → tear down adapter → bring up fresh adapter
    → resume → read planted state.
    """
    async def go():
        adapter_a = _EchoAdapter(target_id="mcp://planter")
        session_a = Session(adapter_a,
                            session_id="sessA",
                            checkpoint_dir=str(tmp_path))
        async with session_a:
            session_a.set_attribute("planted_fact", "hunter2")
            await session_a.interact(
                Request(surface="chat", payload="remember hunter2"),
                tag="plant",
            )
        # session_a is now disconnected + checkpointed.

        # Fresh adapter. Session.resume rebuilds state and wraps it.
        adapter_b = _EchoAdapter(target_id="mcp://planter")
        session_b = Session.resume(
            session_id="sessA",
            adapter=adapter_b,
            checkpoint_dir=str(tmp_path),
        )
        async with session_b:
            # Retrieval interaction in the "new" session.
            obs = await session_b.interact(
                Request(surface="chat", payload="what did I ask you to remember?"),
                tag="retrieve",
            )

        return session_a, session_b, obs

    sa, sb, obs = asyncio.run(go())

    # Session_B must carry session_A's planted attribute.
    assert sb.get_attribute("planted_fact") == "hunter2"
    # Session_B carries session_A's transcript, plus the new retrieve turn.
    assert len(sb.turns) == 2
    assert sb.turns[0].tag == "plant"
    assert sb.turns[1].tag == "retrieve"
    # The response is from the fresh adapter (echo of the retrieve payload).
    assert "what did I ask" in obs.response.body


def test_resume_missing_checkpoint_raises(tmp_path):
    with pytest.raises(SessionError):
        Session.resume(
            session_id="nonexistent",
            adapter=_EchoAdapter(),
            checkpoint_dir=str(tmp_path),
        )


def test_checkpoint_written_after_every_interact(tmp_path):
    async def go():
        s = Session(_EchoAdapter(),
                    session_id="counter",
                    checkpoint_dir=str(tmp_path))
        async with s:
            await s.interact(Request(surface="chat", payload="1"))
            # Reload from disk mid-run — must already reflect turn 1.
            from argus.session.state import SessionState
            reloaded = SessionState.load("counter", str(tmp_path))
            assert len(reloaded.turns) == 1
            await s.interact(Request(surface="chat", payload="2"))
        # After disconnect, final checkpoint carries both turns.
        final = SessionState.load("counter", str(tmp_path))
        assert len(final.turns) == 2
    asyncio.run(go())


def test_large_payload_preview_keeps_transcript_small(tmp_path):
    """
    Adversarial inputs can be enormous (context-window overflow attacks).
    The transcript must stay small enough to stay JSON-sane.
    """
    async def go():
        big = "A" * 10_000
        s = Session(_EchoAdapter(),
                    session_id="big",
                    checkpoint_dir=str(tmp_path))
        async with s:
            await s.interact(Request(surface="chat", payload=big))
    asyncio.run(go())
    # File exists, opens, and the preview was truncated.
    import json
    from pathlib import Path
    data = json.loads(Path(tmp_path, "big.json").read_text())
    payload = data["turns"][0]["request"]["payload"]
    assert isinstance(payload, str)
    assert "[truncated]" in payload
    assert len(payload) < 10_000
