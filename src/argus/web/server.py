"""ARGUS Web Server.

FastAPI backend that runs scans and streams live events to the browser
via Server-Sent Events. The frontend is a single-page HTML app served
from the static/ directory.

Endpoints:
- GET /                 → dashboard HTML
- GET /api/status       → current scan status snapshot
- POST /api/scan/start  → kick off a new scan
- POST /api/scan/stop   → cancel running scan
- GET /api/events       → SSE stream of all scan events (signal bus + findings)
- GET /api/findings     → all findings from the most recent scan
- GET /api/health       → service liveness
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from argus.agents import PromptInjectionHunter, SupplyChainAgent, ToolPoisoningAgent
from argus.models.agents import AgentType, TargetConfig
from argus.orchestrator.engine import Orchestrator, ScanResult
from argus.orchestrator.signal_bus import Signal, SignalType

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"


class ScanRequest(BaseModel):
    """Request body for starting a scan."""

    target_name: str = "Untitled Target"
    mcp_urls: list[str] = []
    agent_endpoint: str | None = None
    timeout: float = 300.0
    demo_pace_seconds: float = 0.4


class ScanState:
    """In-memory state for the currently running (or last) scan."""

    def __init__(self) -> None:
        self.scan_id: str | None = None
        self.target_name: str = ""
        self.target_endpoints: list[str] = []
        self.started_at: float | None = None
        self.completed_at: float | None = None
        self.status: str = "idle"  # idle, running, completed, failed
        self.agents: dict[str, dict[str, Any]] = {}
        self.findings: list[dict[str, Any]] = []
        self.signals: list[dict[str, Any]] = []
        self.events_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.subscribers: list[asyncio.Queue[dict[str, Any]]] = []
        self.scan_task: asyncio.Task | None = None
        self.orchestrator: Orchestrator | None = None
        self.last_result: ScanResult | None = None

    def reset(self) -> None:
        self.scan_id = None
        self.target_name = ""
        self.target_endpoints = []
        self.started_at = None
        self.completed_at = None
        self.status = "idle"
        self.agents = {}
        self.findings = []
        self.signals = []
        # Don't clear subscribers — they're long-lived

    @property
    def elapsed_seconds(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.completed_at or time.monotonic()
        return end - self.started_at

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def validated_findings(self) -> int:
        return sum(1 for f in self.findings if f.get("status") == "validated")

    @property
    def agents_running(self) -> int:
        return sum(1 for a in self.agents.values() if a.get("status") == "running")

    @property
    def agents_completed(self) -> int:
        return sum(1 for a in self.agents.values() if a.get("status") == "completed")

    def snapshot(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_name": self.target_name,
            "target_endpoints": self.target_endpoints,
            "status": self.status,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "total_findings": self.total_findings,
            "validated_findings": self.validated_findings,
            "agents_running": self.agents_running,
            "agents_completed": self.agents_completed,
            "agents_total": len(self.agents),
            "agents": self.agents,
            "recent_findings": self.findings[-20:],
            "signal_count": len(self.signals),
        }

    async def broadcast(self, event_type: str, payload: Any) -> None:
        """Push an event to all SSE subscribers."""
        event = {"type": event_type, "data": payload, "ts": time.time()}
        # Push to all live subscribers
        for queue in list(self.subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass


def create_app() -> FastAPI:
    """Create and configure the ARGUS FastAPI application."""
    app = FastAPI(
        title="ARGUS Web Dashboard",
        description="Autonomous AI Red Team Platform — live web dashboard",
        version="0.1.0",
    )

    state = ScanState()
    app.state.scan_state = state

    # Mount static assets
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    # ------------------------------------------------------------------
    # Page routes
    # ------------------------------------------------------------------

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    # ------------------------------------------------------------------
    # API routes
    # ------------------------------------------------------------------

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "argus-web", "version": "0.1.0"}

    @app.get("/api/status")
    async def status() -> Response:
        body = json.dumps(state.snapshot(), default=str)
        return Response(content=body, media_type="application/json")

    @app.get("/api/findings")
    async def findings() -> Response:
        # Use json.dumps with default=str to handle datetime objects
        body = json.dumps({"findings": state.findings}, default=str)
        return Response(content=body, media_type="application/json")

    @app.post("/api/scan/start")
    async def scan_start(request: ScanRequest) -> dict[str, Any]:
        if state.status == "running":
            raise HTTPException(status_code=409, detail="Scan already running")

        state.reset()
        state.target_name = request.target_name
        state.target_endpoints = list(request.mcp_urls)
        if request.agent_endpoint:
            state.target_endpoints.append(request.agent_endpoint)
        state.status = "running"
        state.started_at = time.monotonic()

        target = TargetConfig(
            name=request.target_name,
            mcp_server_urls=request.mcp_urls,
            agent_endpoint=request.agent_endpoint,
            non_destructive=True,
            max_requests_per_minute=120,
        )

        orchestrator = Orchestrator()
        orchestrator.register_agent(AgentType.PROMPT_INJECTION, PromptInjectionHunter)
        orchestrator.register_agent(AgentType.TOOL_POISONING, ToolPoisoningAgent)
        orchestrator.register_agent(AgentType.SUPPLY_CHAIN, SupplyChainAgent)
        state.orchestrator = orchestrator

        # Initialize agent state cards
        for agent_type in orchestrator.get_registered_agents():
            state.agents[agent_type.value] = {
                "type": agent_type.value,
                "status": "pending",
                "findings_count": 0,
                "validated_count": 0,
                "current_action": "Waiting to deploy...",
                "techniques_attempted": 0,
                "started_at": None,
                "completed_at": None,
            }

        # Subscribe handler to capture signal bus events
        async def signal_handler(signal: Signal) -> None:
            state.signals.append(
                {
                    "type": signal.signal_type.value,
                    "source_agent": signal.source_agent,
                    "ts": signal.timestamp.isoformat(),
                }
            )

            agent_id = signal.source_agent
            if agent_id in state.agents:
                agent = state.agents[agent_id]

                if signal.signal_type == SignalType.AGENT_STATUS:
                    new_status = signal.data.get("status", "")
                    if new_status == "running":
                        agent["status"] = "running"
                        agent["started_at"] = time.time()
                        agent["current_action"] = "Deployed — beginning attack..."
                    elif new_status == "completed":
                        agent["status"] = "completed"
                        agent["completed_at"] = time.time()
                        agent["current_action"] = "Mission complete"

                elif signal.signal_type == SignalType.FINDING:
                    finding_data = signal.data.get("finding", {})
                    agent["findings_count"] += 1
                    if finding_data.get("status") == "validated":
                        agent["validated_count"] += 1
                    title = finding_data.get("title", "")
                    agent["current_action"] = f"Found: {title[:80]}"

                    state.findings.append(finding_data)

                    await state.broadcast("finding", finding_data)

                elif signal.signal_type == SignalType.PARTIAL_FINDING:
                    data_summary = str(signal.data.get("type", "probing"))[:60]
                    agent["current_action"] = f"Probing: {data_summary}"

            await state.broadcast("signal", state.snapshot())

        await orchestrator.signal_bus.subscribe_broadcast(signal_handler)

        # Run the scan in the background
        async def _run() -> None:
            try:
                result = await orchestrator.run_scan(
                    target=target,
                    timeout=request.timeout,
                    demo_pace_seconds=request.demo_pace_seconds,
                )
                state.last_result = result
                state.status = "completed"
                state.completed_at = time.monotonic()
                await state.broadcast("complete", state.snapshot())
            except Exception as exc:
                logger.exception("Scan failed: %s", exc)
                state.status = "failed"
                state.completed_at = time.monotonic()
                await state.broadcast("failed", {"error": str(exc)[:300]})

        state.scan_task = asyncio.create_task(_run())

        await state.broadcast("scan_started", state.snapshot())
        return {"status": "started", "scan_id": state.scan_id}

    @app.post("/api/scan/stop")
    async def scan_stop() -> dict[str, str]:
        if state.scan_task and not state.scan_task.done():
            state.scan_task.cancel()
            state.status = "cancelled"
            state.completed_at = time.monotonic()
            await state.broadcast("cancelled", state.snapshot())
            return {"status": "cancelled"}
        return {"status": "no_active_scan"}

    @app.get("/api/events")
    async def events() -> EventSourceResponse:
        """SSE stream of all scan events for the dashboard frontend."""
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1000)
        state.subscribers.append(queue)

        async def event_generator():
            try:
                # Send initial snapshot
                yield {
                    "event": "snapshot",
                    "data": json.dumps(state.snapshot()),
                }

                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15.0)
                        yield {
                            "event": event["type"],
                            "data": json.dumps(event["data"], default=str),
                        }
                    except TimeoutError:
                        # Heartbeat to keep connection alive
                        yield {"event": "ping", "data": "{}"}
            finally:
                if queue in state.subscribers:
                    state.subscribers.remove(queue)

        return EventSourceResponse(event_generator())

    return app
