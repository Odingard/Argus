"""Sandbox Environment.

Provides isolated execution environments for ARGUS attack agents.
Each agent runs in a sandbox that:
- Prevents modification of production data
- Isolates agent state from other agents
- Captures all I/O for audit trail
- Enforces resource limits (time, requests, data)
"""

from __future__ import annotations

import asyncio
import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class SandboxConfig:
    """Configuration for a sandbox environment."""
    # Resource limits
    max_requests: int = 1000
    max_request_rate: int = 60  # per minute
    max_data_bytes: int = 50 * 1024 * 1024  # 50MB
    timeout_seconds: int = 300

    # Network controls
    allowed_hosts: list[str] = field(default_factory=list)
    blocked_hosts: list[str] = field(default_factory=list)

    # Filesystem
    workspace_dir: Optional[str] = None  # auto-created if None
    persist_workspace: bool = False

    # Safety
    non_destructive: bool = True
    dry_run: bool = False


class SandboxEnvironment:
    """Isolated execution environment for a single attack agent.

    Tracks all operations, enforces limits, and provides a clean
    workspace that is destroyed after the agent completes.
    """

    def __init__(self, agent_id: str, config: Optional[SandboxConfig] = None) -> None:
        self.agent_id = agent_id
        self.config = config or SandboxConfig()
        self._workspace: Optional[Path] = None
        self._request_count = 0
        self._data_bytes = 0
        self._audit_log: list[dict[str, Any]] = []
        self._active = False
        self._rate_limiter: Optional[asyncio.Semaphore] = None
        self._request_timestamps: list[float] = []

    async def __aenter__(self) -> SandboxEnvironment:
        await self.setup()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.teardown()

    async def setup(self) -> None:
        """Initialize the sandbox environment."""
        if self.config.workspace_dir:
            self._workspace = Path(self.config.workspace_dir)
            self._workspace.mkdir(parents=True, exist_ok=True)
        else:
            self._workspace = Path(tempfile.mkdtemp(prefix=f"argus-{self.agent_id[:8]}-"))

        self._rate_limiter = asyncio.Semaphore(self.config.max_request_rate)
        self._active = True

        logger.info("Sandbox %s initialized — workspace: %s", self.agent_id[:8], self._workspace)

    async def teardown(self) -> None:
        """Clean up the sandbox environment."""
        if self._workspace and not self.config.persist_workspace:
            import shutil
            try:
                shutil.rmtree(self._workspace)
                logger.info("Sandbox %s workspace cleaned up", self.agent_id[:8])
            except OSError as exc:
                logger.warning("Failed to clean workspace %s: %s", self._workspace, exc)

        self._active = False

    @property
    def workspace(self) -> Path:
        if not self._workspace:
            raise RuntimeError("Sandbox not initialized")
        return self._workspace

    @property
    def audit_log(self) -> list[dict[str, Any]]:
        return list(self._audit_log)

    async def check_request_allowed(self) -> bool:
        """Check if a request is allowed within sandbox limits."""
        if not self._active:
            return False

        if self._request_count >= self.config.max_requests:
            self._log_audit("request_denied", {"reason": "max_requests_exceeded"})
            return False

        if self._data_bytes >= self.config.max_data_bytes:
            self._log_audit("request_denied", {"reason": "max_data_exceeded"})
            return False

        # Rate limiting
        now = asyncio.get_event_loop().time()
        cutoff = now - 60.0
        self._request_timestamps = [t for t in self._request_timestamps if t > cutoff]
        if len(self._request_timestamps) >= self.config.max_request_rate:
            self._log_audit("request_denied", {"reason": "rate_limit_exceeded"})
            return False

        return True

    async def record_request(self, method: str, target: str, data_bytes: int = 0) -> None:
        """Record a request made by the agent."""
        self._request_count += 1
        self._data_bytes += data_bytes
        self._request_timestamps.append(asyncio.get_event_loop().time())

        self._log_audit("request", {
            "method": method,
            "target": target,
            "data_bytes": data_bytes,
            "total_requests": self._request_count,
        })

    def check_host_allowed(self, host: str) -> bool:
        """Check if a host is allowed by the sandbox network controls."""
        if self.config.blocked_hosts and host in self.config.blocked_hosts:
            self._log_audit("host_blocked", {"host": host})
            return False
        if self.config.allowed_hosts and host not in self.config.allowed_hosts:
            self._log_audit("host_not_allowed", {"host": host})
            return False
        return True

    def _log_audit(self, event_type: str, data: dict[str, Any]) -> None:
        self._audit_log.append({
            "agent_id": self.agent_id,
            "event": event_type,
            **data,
        })

    def stats(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "requests_made": self._request_count,
            "data_bytes": self._data_bytes,
            "audit_entries": len(self._audit_log),
            "active": self._active,
        }
