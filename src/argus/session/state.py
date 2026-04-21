"""
argus/session/state.py — session data shapes.

Kept in a small standalone module so resume-from-disk doesn't need to
import the full Session class (which depends on an async adapter).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


class SessionError(Exception):
    """Raised on session-layer failures (bad checkpoint, missing session)."""


# ── Turn ──────────────────────────────────────────────────────────────────────

@dataclass
class Turn:
    """One request/response pair in a session."""
    index:       int
    timestamp:   str
    request:     dict        # Request.to_dict-equivalent
    observation: dict        # AdapterObservation.to_dict()
    tag:         str = ""    # free-form label for the turn

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Turn":
        return cls(
            index=int(d.get("index", 0)),
            timestamp=str(d.get("timestamp", "")),
            request=dict(d.get("request", {}) or {}),
            observation=dict(d.get("observation", {}) or {}),
            tag=str(d.get("tag", "")),
        )


# ── SessionState ──────────────────────────────────────────────────────────────

@dataclass
class SessionState:
    """Pure data — safe to serialise, safe to pickle-free JSON round-trip."""
    session_id:    str
    target_id:     str
    started_at:    str
    last_activity: str = ""
    turns:         list[Turn] = field(default_factory=list)
    attributes:    dict[str, Any] = field(default_factory=dict)
    version:       int = 1   # bump on schema change

    def to_dict(self) -> dict:
        return {
            "session_id":    self.session_id,
            "target_id":     self.target_id,
            "started_at":    self.started_at,
            "last_activity": self.last_activity,
            "turns":         [t.to_dict() for t in self.turns],
            "attributes":    dict(self.attributes),
            "version":       self.version,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SessionState":
        return cls(
            session_id=d["session_id"],
            target_id=d.get("target_id", ""),
            started_at=d.get("started_at", ""),
            last_activity=d.get("last_activity", ""),
            turns=[Turn.from_dict(t) for t in d.get("turns", []) or []],
            attributes=dict(d.get("attributes", {}) or {}),
            version=int(d.get("version", 1)),
        )

    # ── Persistence ──────────────────────────────────────────────────────

    def save(self, checkpoint_dir: str) -> Path:
        path = Path(checkpoint_dir) / f"{self.session_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        return path

    @classmethod
    def load(cls, session_id: str, checkpoint_dir: str) -> "SessionState":
        path = Path(checkpoint_dir) / f"{session_id}.json"
        if not path.exists():
            raise SessionError(
                f"no checkpoint for session {session_id!r} "
                f"in {checkpoint_dir}"
            )
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise SessionError(f"failed to read checkpoint: {e}") from e
        return cls.from_dict(raw)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
