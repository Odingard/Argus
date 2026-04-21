"""
argus.session — per-session conversation state + multi-session state mgmt.

Wraps a ``BaseAdapter`` with turn-by-turn bookkeeping. Three lifecycles:

    ephemeral      new Session, no checkpoint dir, dies with process.
                   Used by single-shot attacks.

    checkpointed   new Session, checkpoint_dir set. State is flushed to
                   disk after every interact() so crashes don't lose
                   evidence.

    resumed        Session.resume(session_id, adapter, checkpoint_dir)
                   loads a prior checkpoint and continues against a
                   fresh adapter — this is how Agent 3 (Memory
                   Poisoning) runs its Plant→Disconnect→Retrieve
                   protocol across "different sessions".

No finding detection happens here. Session only records. The Phase 0.4
Observation Engine is the judge.
"""
from argus.session.state import Turn, SessionState, SessionError
from argus.session.session import Session

__all__ = ["Turn", "SessionState", "SessionError", "Session"]
