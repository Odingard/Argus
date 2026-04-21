"""
argus/adapter/a2a.py — Agent-to-Agent channel adapter.

Phase 2 brings this out of stub. Real A2A transports vary (Google A2A,
CrewAI handoffs, LangGraph state-edge hops, peer-agent message buses),
so ``A2AAdapter`` is a thin shell around a pluggable ``A2ABackend`` —
the transport-specific client lives in the backend, the shared
adapter contract lives here.

Surface convention: each peer agent the target fabric knows about is
exposed as a surface of the form ``handoff:<peer_id>``. A Request
payload for that surface carries the hop envelope:

    {
      "from_agent":      "planner",
      "to_agent":        "executor",
      "identity":        "user:alice",      # the claimed identity
      "content":         "the message",
      "signature":       "…",               # optional
      "metadata":        { … },
    }

Agent 4 (Identity Spoof) builds adversarial variants of this envelope
— spoofed ``from_agent``, fabricated ``identity``, unsigned claims,
replayed signatures — and the Observation Engine decides whether the
handoff destination honoured them.

For tests and labrat: ``InMemoryA2ABackend`` ships with this module and
implements the backend contract against an in-process peer graph. Real
backends (Google A2A client, CrewAI session, LangGraph checkpointer)
subclass ``A2ABackend`` and override ``_connect`` / ``_send`` /
``_list_peers``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol

from argus.adapter.base import (
    AdapterError, AdapterObservation, BaseAdapter, Request, Response, Surface,
)


# ── Backend contract ─────────────────────────────────────────────────────────

@dataclass
class Peer:
    """One peer-agent node in the target's A2A fabric."""
    peer_id:     str
    description: str = ""
    metadata:    dict = field(default_factory=dict)


class A2ABackend(Protocol):
    """Transport-specific backend the adapter delegates to."""

    async def connect(self) -> None: ...
    async def disconnect(self) -> None: ...
    async def list_peers(self) -> list[Peer]: ...
    async def send(self, *, to_agent: str, envelope: dict) -> Response: ...


# ── In-memory backend (tests + labrat) ───────────────────────────────────────

HandlerFn = Callable[[dict], "Response | dict | str"]
"""A peer handler receives the hop envelope and returns either a
ready-made Response, a dict body (wrapped in status=ok), or a string."""


class InMemoryA2ABackend:
    """
    Minimal in-process backend. Register peer handlers; the adapter
    will route envelopes to them. Useful for testing identity-spoof
    scenarios without standing up a real multi-agent fabric.
    """

    def __init__(
        self,
        peers: Optional[dict[str, HandlerFn]] = None,
        *,
        descriptions: Optional[dict[str, str]] = None,
    ) -> None:
        self._handlers:     dict[str, HandlerFn] = dict(peers or {})
        self._descriptions: dict[str, str]       = dict(descriptions or {})
        self._connected = False

    def register_peer(
        self, peer_id: str, handler: HandlerFn, *, description: str = "",
    ) -> None:
        self._handlers[peer_id] = handler
        if description:
            self._descriptions[peer_id] = description

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def list_peers(self) -> list[Peer]:
        return [
            Peer(peer_id=pid,
                 description=self._descriptions.get(pid, ""))
            for pid in self._handlers
        ]

    async def send(self, *, to_agent: str, envelope: dict) -> Response:
        handler = self._handlers.get(to_agent)
        if handler is None:
            return Response(
                status="error", body=f"unknown peer: {to_agent}",
            )
        try:
            out = handler(envelope)
        except Exception as e:
            return Response(
                status="error",
                body=f"peer {to_agent} raised {type(e).__name__}: {e}",
            )
        if isinstance(out, Response):
            return out
        if isinstance(out, (dict, list)):
            return Response(status="ok", body=out)
        return Response(status="ok", body=str(out))


# ── A2AAdapter ───────────────────────────────────────────────────────────────

class A2AAdapter(BaseAdapter):
    """
    Agent-to-Agent channel adapter. Thin wrapper over an
    ``A2ABackend`` — the transport-specific work lives in the backend,
    the BaseAdapter contract lives here.
    """

    def __init__(
        self,
        *,
        backend:         A2ABackend,
        target_id:       str = "",
        connect_timeout: float = 15.0,
        request_timeout: float = 30.0,
    ) -> None:
        super().__init__(
            target_id=target_id or "a2a://in-memory",
            connect_timeout=connect_timeout,
            request_timeout=request_timeout,
        )
        if backend is None:
            raise AdapterError(
                "A2AAdapter requires a backend (A2ABackend). Pass "
                "InMemoryA2ABackend(peers=...) for tests or a real "
                "protocol client for live targets."
            )
        self._backend = backend

    async def _connect(self) -> None:
        await self._backend.connect()

    async def _disconnect(self) -> None:
        await self._backend.disconnect()

    async def _enumerate(self) -> list[Surface]:
        peers = await self._backend.list_peers()
        return [
            Surface(
                kind="handoff",
                name=f"handoff:{p.peer_id}",
                description=p.description or f"A2A handoff to {p.peer_id}",
                schema={
                    "envelope": {
                        "from_agent": "string",
                        "to_agent":   p.peer_id,
                        "identity":   "string",
                        "content":    "any",
                        "signature":  "string",
                    },
                    "meta": p.metadata or {},
                },
            )
            for p in peers
        ]

    async def _interact(self, request: Request) -> AdapterObservation:
        # Extract the to_agent from the surface name.
        if not request.surface.startswith("handoff:"):
            return AdapterObservation(
                request_id=request.id, surface=request.surface,
                response=Response(
                    status="error",
                    body=(f"A2AAdapter only routes handoff:* surfaces, got "
                          f"{request.surface!r}"),
                ),
            )
        to_agent = request.surface.split(":", 1)[1]

        # Coerce payload into an envelope dict.
        envelope = self._envelope(request.payload, to_agent=to_agent)

        response = await self._backend.send(
            to_agent=to_agent, envelope=envelope,
        )
        return AdapterObservation(
            request_id=request.id, surface=request.surface,
            response=response,
            side_channel={"envelope": envelope},
        )

    @staticmethod
    def _envelope(payload: Any, *, to_agent: str) -> dict:
        if isinstance(payload, dict):
            envelope = dict(payload)
            envelope.setdefault("to_agent", to_agent)
            return envelope
        # Tolerate raw strings — wrap them as an envelope.
        return {"to_agent": to_agent, "content": payload}
