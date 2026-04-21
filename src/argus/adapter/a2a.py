"""
argus/adapter/a2a.py — Agent-to-Agent channel adapter (Phase 2 stub).

Phase 2 builds this out for Google A2A, CrewAI handoffs, LangGraph
state-edge hops, and peer-agent message buses. Right now the stub
exists so the adapter framework has a seat saved for it — any Phase-1
code that says "if this is an A2A target..." degrades cleanly rather
than crashing on an unknown adapter type.

NotImplementedError is used deliberately; future-dated asserts are
checked by pytest below.
"""
from __future__ import annotations

from argus.adapter.base import AdapterError, BaseAdapter


class A2AAdapter(BaseAdapter):
    """
    Stub Agent-to-Agent adapter.

    Raises on construction to make accidental use loud. Remove the raise
    in Phase 2 Ticket 2.X when the real implementation lands.
    """

    def __init__(self, **_kwargs) -> None:
        raise AdapterError(
            "A2AAdapter is a Phase-2 stub; not yet implemented. "
            "See PHASES.md § Phase 2 — Agent 4 Identity Spoof."
        )

    async def _connect(self) -> None:
        raise NotImplementedError

    async def _disconnect(self) -> None:
        raise NotImplementedError

    async def _enumerate(self):
        raise NotImplementedError

    async def _interact(self, request):
        raise NotImplementedError
