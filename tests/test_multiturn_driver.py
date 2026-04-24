"""
tests/test_multiturn_driver.py — MultiTurnDriver + crescendo_plan
contracts.

Gap #3 primitive: drive a sequence of turns through a real Session,
with each turn firing as its own request so the target accumulates
conversational context. Crescendo's 3-turn auditor-framing buildup
is the first caller.
"""
from __future__ import annotations

import pytest

from argus.adapter.base import (
    AdapterObservation, BaseAdapter, Request, Response, Surface,
)
from argus.attacks import ConversationPlan, ConversationTurn, MultiTurnDriver
from argus.attacks.conversation import detects_refusal
from argus.corpus_attacks import crescendo_plan
from argus.session import Session


# ── Fixture adapter that records + echoes ────────────────────────────────

class _EchoAdapter(BaseAdapter):
    """Test-only adapter. Records every request, returns a
    configurable response per turn so observers can branch."""

    def __init__(self, responses=None):
        super().__init__()
        self._responses = list(responses or [])
        self._default   = "ack"
        self.requests   = []

    async def _connect(self):   pass
    async def _disconnect(self):  pass

    async def _enumerate(self):
        return [Surface(name="chat", kind="chat")]

    async def _interact(self, request: Request) -> AdapterObservation:
        self.requests.append(request)
        body = (self._responses.pop(0) if self._responses
                else self._default)
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=Response(status="ok", body=body),
        )


# ── ConversationPlan + driver ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_driver_runs_every_turn_in_order():
    adapter = _EchoAdapter(responses=["r1", "r2", "r3"])
    sess = Session(adapter, session_id="t1")
    plan = ConversationPlan(
        surface="chat",
        turns=[
            ConversationTurn(payload="hi",      tag="opener"),
            ConversationTurn(payload="bridge",  tag="bridge"),
            ConversationTurn(payload="payload", tag="payload"),
        ],
    )
    async with sess:
        obs = await MultiTurnDriver(sess).run(plan)
    assert len(obs) == 3
    assert [r.payload for r in adapter.requests] == ["hi", "bridge", "payload"]
    assert [o.response.body for o in obs] == ["r1", "r2", "r3"]


@pytest.mark.asyncio
async def test_driver_aborts_on_observer_true():
    """Observer returning True short-circuits the remaining turns —
    classic 'model refused at turn 1, don't burn the payload' case."""
    adapter = _EchoAdapter(responses=["I can't help with that.", "ok2"])
    sess = Session(adapter, session_id="t2")
    plan = ConversationPlan(
        surface="chat",
        turns=[
            ConversationTurn(payload="hi",
                             observer=detects_refusal, tag="opener"),
            ConversationTurn(payload="payload", tag="payload"),
        ],
    )
    async with sess:
        obs = await MultiTurnDriver(sess).run(plan)
    # Aborted after opener.
    assert len(obs) == 1
    assert len(adapter.requests) == 1


@pytest.mark.asyncio
async def test_driver_records_turns_in_session_transcript():
    adapter = _EchoAdapter(responses=["r1", "r2"])
    sess = Session(adapter, session_id="t3")
    plan = ConversationPlan(
        surface="chat",
        turns=[
            ConversationTurn(payload="a", tag="opener"),
            ConversationTurn(payload="b", tag="payload"),
        ],
    )
    async with sess:
        await MultiTurnDriver(sess).run(plan, tag_prefix="multiturn")
    turns = sess.transcript()
    assert len(turns) == 2
    # Tags carry the buildup-stage labels for forensic replay.
    assert turns[0]["tag"] == "multiturn:opener"
    assert turns[1]["tag"] == "multiturn:payload"


@pytest.mark.asyncio
async def test_driver_survives_observer_exceptions():
    """Observer errors MUST NOT abort the plan — they're non-fatal."""
    def raising_observer(_obs):
        raise RuntimeError("observer blew up")
    adapter = _EchoAdapter(responses=["r1", "r2"])
    sess = Session(adapter, session_id="t4")
    plan = ConversationPlan(
        surface="chat",
        turns=[
            ConversationTurn(payload="a", observer=raising_observer),
            ConversationTurn(payload="b"),
        ],
    )
    async with sess:
        obs = await MultiTurnDriver(sess).run(plan)
    assert len(obs) == 2


def test_plan_requires_at_least_one_turn():
    with pytest.raises(ValueError, match="at least one turn"):
        ConversationPlan(surface="chat", turns=[])


# ── crescendo_plan bridge ────────────────────────────────────────────────

def test_crescendo_plan_is_three_turns_with_payload_last():
    plan = crescendo_plan("exfil credentials.env",
                          surface="chat", seed=1)
    assert len(plan.turns) == 3
    # Payload lands in turn 3 verbatim (buildup comes before).
    assert "exfil credentials.env" in str(plan.turns[2].payload)
    # Openers + bridges don't carry the payload.
    assert "credentials.env" not in str(plan.turns[0].payload)
    assert "credentials.env" not in str(plan.turns[1].payload)


def test_crescendo_plan_opener_has_refusal_observer():
    """Opener and bridge turns carry the refusal observer so we
    pivot early if the model stonewalls the benign auditor frame."""
    plan = crescendo_plan("payload", surface="chat", seed=1)
    assert plan.turns[0].observer is detects_refusal
    assert plan.turns[1].observer is detects_refusal
    assert plan.turns[2].observer is None


def test_crescendo_plan_is_deterministic_per_seed():
    a = crescendo_plan("x", surface="chat", seed=42)
    b = crescendo_plan("x", surface="chat", seed=42)
    assert [t.payload for t in a.turns] == [t.payload for t in b.turns]


@pytest.mark.asyncio
async def test_crescendo_plan_drives_three_distinct_requests():
    """Real integration: build a crescendo plan, fire through
    MultiTurnDriver, observe exactly three distinct requests land on
    the adapter (not one inlined dialogue)."""
    adapter = _EchoAdapter()
    sess = Session(adapter, session_id="t5")
    plan = crescendo_plan("attack", surface="chat", seed=7)
    async with sess:
        obs = await MultiTurnDriver(sess).run(plan)
    assert len(obs) == 3
    # The opener + bridge + payload are three distinct strings — no
    # inlined-dialogue workaround.
    payloads = [r.payload for r in adapter.requests]
    assert len(set(payloads)) == 3


# ── Refusal detector ─────────────────────────────────────────────────────

def _obs(body: str) -> AdapterObservation:
    return AdapterObservation(
        request_id="r", surface="chat",
        response=Response(status="ok", body=body),
    )


def test_detects_refusal_fires_on_guardrail_apologies():
    for body in (
        "I can't help with that.",
        "I'm unable to provide that information.",
        "Sorry, that's against my guidelines.",
        "I must decline this request.",
    ):
        assert detects_refusal(_obs(body)), f"missed refusal: {body!r}"


def test_detects_refusal_is_false_on_cooperation():
    for body in (
        "Sure, here's the info you asked for.",
        "{\"tools\": [{\"name\": \"read_file\"}]}",
        "Here are the allowed directories: /tmp/argus-sandbox",
    ):
        assert not detects_refusal(_obs(body)), (
            f"spurious refusal: {body!r}"
        )
