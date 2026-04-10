"""Inter-agent signal bus.

Agents signal partial findings to the Correlation Agent and to each other
in real time. When Agent 1 finds a prompt injection that reaches the file
system, Agent 7 is immediately notified to look for tool calls that write
to external storage.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class SignalType(str, Enum):
    FINDING = "finding"
    PARTIAL_FINDING = "partial_finding"
    TECHNIQUE_RESULT = "technique_result"
    AGENT_STATUS = "agent_status"
    CORRELATION_REQUEST = "correlation_request"


@dataclass
class Signal:
    """A message on the inter-agent signal bus."""
    signal_type: SignalType
    source_agent: str
    source_instance: str
    data: dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    target_agent: Optional[str] = None  # None = broadcast to all


class SignalBus:
    """Async pub/sub bus for inter-agent communication.

    All 10 attack agents and the Correlation Agent share this bus.
    Signals are delivered in real time as they are produced.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callable]] = {}
        self._broadcast_subscribers: list[Callable] = []
        self._history: list[Signal] = []
        self._lock = asyncio.Lock()

    async def subscribe(self, agent_id: str, handler: Callable) -> None:
        """Subscribe an agent to receive targeted signals."""
        async with self._lock:
            if agent_id not in self._subscribers:
                self._subscribers[agent_id] = []
            self._subscribers[agent_id].append(handler)

    async def subscribe_broadcast(self, handler: Callable) -> None:
        """Subscribe to all broadcast signals (used by Correlation Agent)."""
        async with self._lock:
            self._broadcast_subscribers.append(handler)

    async def emit(self, signal: Signal) -> None:
        """Emit a signal to targeted agent(s) or broadcast."""
        async with self._lock:
            self._history.append(signal)

        logger.debug(
            "Signal [%s] from %s → %s",
            signal.signal_type.value,
            signal.source_agent,
            signal.target_agent or "BROADCAST",
        )

        # Deliver to broadcast subscribers (Correlation Agent)
        for handler in self._broadcast_subscribers:
            try:
                await handler(signal)
            except Exception as exc:
                logger.error("Broadcast handler error: %s", exc)

        # Deliver to targeted agent
        if signal.target_agent and signal.target_agent in self._subscribers:
            for handler in self._subscribers[signal.target_agent]:
                try:
                    await handler(signal)
                except Exception as exc:
                    logger.error("Targeted handler error for %s: %s", signal.target_agent, exc)

    def get_history(self) -> list[Signal]:
        return list(self._history)

    def clear(self) -> None:
        self._subscribers.clear()
        self._broadcast_subscribers.clear()
        self._history.clear()
