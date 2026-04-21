"""
argus/session/session.py — the async Session wrapper around a BaseAdapter.
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Optional

from argus.adapter.base import AdapterObservation, BaseAdapter, Request
from argus.session.state import SessionState, Turn, utcnow_iso


class Session:
    """
    Wraps a BaseAdapter with per-session state. All transport calls go
    through the wrapped adapter; the Session records them, optionally
    checkpoints after each turn, and lets later-phase agents resume a
    prior session against a fresh adapter (the multi-session protocol
    Agent 3 Memory Poisoning needs).
    """

    def __init__(
        self,
        adapter:         BaseAdapter,
        *,
        session_id:      Optional[str] = None,
        checkpoint_dir:  Optional[str] = None,
        state:           Optional[SessionState] = None,
    ) -> None:
        self.adapter = adapter

        if state is not None:
            self._state = state
        else:
            sid = session_id or uuid.uuid4().hex[:16]
            self._state = SessionState(
                session_id=sid,
                target_id=getattr(adapter, "target_id", "") or "",
                started_at=utcnow_iso(),
                last_activity=utcnow_iso(),
            )

        self.checkpoint_dir = checkpoint_dir
        if checkpoint_dir:
            Path(checkpoint_dir).mkdir(parents=True, exist_ok=True)

    # ── Public async surface ──────────────────────────────────────────────

    async def connect(self) -> None:
        await self.adapter.connect()

    async def disconnect(self) -> None:
        await self.adapter.disconnect()
        if self.checkpoint_dir:
            self.checkpoint()

    async def interact(
        self,
        request: Request,
        *,
        tag: str = "",
    ) -> AdapterObservation:
        obs = await self.adapter.interact(request)

        turn = Turn(
            index=len(self._state.turns),
            timestamp=utcnow_iso(),
            request={"id": request.id, "surface": request.surface,
                     "payload": _safe_preview(request.payload),
                     "meta": dict(request.meta or {})},
            observation=obs.to_dict(),
            tag=tag,
        )
        self._state.turns.append(turn)
        self._state.last_activity = turn.timestamp

        if self.checkpoint_dir:
            self.checkpoint()

        return obs

    async def __aenter__(self) -> "Session":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.disconnect()

    # ── Persistence ──────────────────────────────────────────────────────

    def checkpoint(self) -> Optional[Path]:
        """Flush state to disk. No-op when no checkpoint_dir configured."""
        if not self.checkpoint_dir:
            return None
        return self._state.save(self.checkpoint_dir)

    @classmethod
    def resume(
        cls,
        session_id:     str,
        adapter:        BaseAdapter,
        checkpoint_dir: str,
    ) -> "Session":
        """
        Load a previously-checkpointed session and wrap it around a
        fresh adapter. This is the Plant→Disconnect→Retrieve enabler
        Agent 3 needs: the attacker plants state in session_A, ARGUS
        tears the adapter down, and later spins up a "new" session_B
        that references the prior state.
        """
        state = SessionState.load(session_id, checkpoint_dir)
        return cls(
            adapter=adapter,
            session_id=state.session_id,
            checkpoint_dir=checkpoint_dir,
            state=state,
        )

    # ── Accessors ────────────────────────────────────────────────────────

    @property
    def session_id(self) -> str:
        return self._state.session_id

    @property
    def target_id(self) -> str:
        return self._state.target_id

    @property
    def turns(self) -> list[Turn]:
        return list(self._state.turns)

    def transcript(self) -> list[dict]:
        """Full turn record (list of dicts) suitable for observers + reports."""
        return [t.to_dict() for t in self._state.turns]

    def set_attribute(self, key: str, value: Any) -> None:
        """Persist adversary-supplied context for later turns / resumed sessions."""
        self._state.attributes[key] = value
        if self.checkpoint_dir:
            self.checkpoint()

    def get_attribute(self, key: str, default: Any = None) -> Any:
        return self._state.attributes.get(key, default)

    def __repr__(self) -> str:
        return (f"<Session id={self.session_id} target={self.target_id!r} "
                f"turns={len(self._state.turns)} "
                f"checkpoint={'on' if self.checkpoint_dir else 'off'}>")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _safe_preview(payload: Any, cap: int = 4000) -> Any:
    """
    Keep the transcript serialisable. Large or exotic payloads get a
    truncated string preview rather than bloating the checkpoint.
    """
    if payload is None or isinstance(payload, (int, float, bool)):
        return payload
    if isinstance(payload, str):
        return payload if len(payload) <= cap else payload[:cap] + "...[truncated]"
    if isinstance(payload, (list, dict)):
        try:
            import json as _json
            s = _json.dumps(payload, default=str)
            if len(s) <= cap:
                return payload
            return {"_truncated": True, "preview": s[:cap] + "..."}
        except (TypeError, ValueError):
            return {"_repr": repr(payload)[:cap]}
    return {"_repr": repr(payload)[:cap]}
