"""ARGUS Live Dashboard.

Rich-powered streaming terminal UI that shows the attack swarm in action:
- Each agent as a live status panel
- Findings streaming in real time
- Signal bus events
- Progress bars per agent
- Live score tracking

Usage:
    dashboard = LiveDashboard()
    await dashboard.run(orchestrator, target)
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from argus.models.agents import AgentType, TargetConfig
from argus.models.findings import FindingSeverity
from argus.orchestrator.engine import Orchestrator, ScanResult
from argus.orchestrator.signal_bus import Signal, SignalType
from argus.ui.colors import AGENT_COLORS

SEVERITY_STYLES = {
    FindingSeverity.CRITICAL: "bold red on white",
    FindingSeverity.HIGH: "bold red",
    FindingSeverity.MEDIUM: "bold yellow",
    FindingSeverity.LOW: "cyan",
    FindingSeverity.INFO: "dim",
}


BANNER = r"""[bold red]
     █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
    ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
    ███████║██████╔╝██║  ███╗██║   ██║███████╗
    ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
    ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚══════╝
[/bold red][bright_red]
       AUTONOMOUS AI RED TEAM PLATFORM[/bright_red]
[dim]       Odingard Security · Six Sense[/dim]
"""


class AgentState:
    """Tracks live state of a single attack agent."""

    def __init__(self, agent_type: AgentType) -> None:
        self.agent_type = agent_type
        self.status = "PENDING"
        self.techniques_attempted = 0
        self.techniques_succeeded = 0
        self.findings_count = 0
        self.validated_count = 0
        self.signals_emitted = 0
        self.current_action = "Initializing..."
        self.started_at: float | None = None
        self.completed_at: float | None = None

    @property
    def duration(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.completed_at or time.monotonic()
        return end - self.started_at


class LiveDashboard:
    """Live terminal dashboard for ARGUS scans."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self.agents: dict[str, AgentState] = {}
        self.recent_signals: list[Signal] = []
        self.recent_findings: list[dict[str, Any]] = []
        self.scan_started: float | None = None
        self.target_name: str = ""
        self.target_urls: list[str] = []
        self.total_signals = 0
        self.total_findings = 0
        self.total_validated = 0
        self._max_recent = 12

    def _ensure_agent(self, agent_type_str: str) -> AgentState:
        if agent_type_str not in self.agents:
            try:
                at = AgentType(agent_type_str)
            except ValueError:
                at = AgentType.CORRELATION
            self.agents[agent_type_str] = AgentState(at)
        return self.agents[agent_type_str]

    async def _on_signal(self, signal: Signal) -> None:
        """Handler attached to the signal bus — updates dashboard state."""
        self.total_signals += 1
        self.recent_signals.append(signal)
        if len(self.recent_signals) > self._max_recent:
            self.recent_signals = self.recent_signals[-self._max_recent :]

        agent = self._ensure_agent(signal.source_agent)
        agent.signals_emitted += 1

        if signal.signal_type == SignalType.AGENT_STATUS:
            status = signal.data.get("status", "")
            if status == "running":
                agent.status = "RUNNING"
                agent.started_at = time.monotonic()
            elif status == "completed":
                agent.status = "COMPLETED"
                agent.completed_at = time.monotonic()

        elif signal.signal_type == SignalType.FINDING:
            self.total_findings += 1
            agent.findings_count += 1
            finding_data = signal.data.get("finding", {})
            if finding_data.get("status") == "validated":
                agent.validated_count += 1
                self.total_validated += 1

            self.recent_findings.append(finding_data)
            if len(self.recent_findings) > self._max_recent:
                self.recent_findings = self.recent_findings[-self._max_recent :]

            agent.current_action = f"Found: {finding_data.get('title', '')[:50]}"

        elif signal.signal_type == SignalType.PARTIAL_FINDING:
            agent.current_action = f"Probing: {str(signal.data)[:50]}"

    def _build_header(self) -> Panel:
        elapsed = time.monotonic() - self.scan_started if self.scan_started else 0.0
        header_text = Text()
        header_text.append("ARGUS LIVE SCAN  ", style="bold red")
        header_text.append("|  Target: ", style="dim")
        header_text.append(f"{self.target_name}", style="bold white")
        header_text.append("  |  Elapsed: ", style="dim")
        header_text.append(f"{elapsed:.1f}s", style="bold cyan")
        header_text.append("  |  ", style="dim")
        header_text.append(f"Findings: {self.total_findings}", style="bold yellow")
        header_text.append("  |  Validated: ", style="dim")
        header_text.append(f"{self.total_validated}", style="bold green")
        header_text.append("  |  Signals: ", style="dim")
        header_text.append(f"{self.total_signals}", style="bold magenta")
        return Panel(Align.center(header_text), border_style="red", style="on grey11")

    def _build_agent_panel(self) -> Panel:
        table = Table.grid(expand=True)
        table.add_column(justify="left", ratio=2)
        table.add_column(justify="left", ratio=2)
        table.add_column(justify="right", ratio=1)
        table.add_column(justify="right", ratio=1)
        table.add_column(justify="right", ratio=1)
        table.add_column(justify="left", ratio=4)

        # Header row
        table.add_row(
            Text("AGENT", style="bold"),
            Text("STATUS", style="bold"),
            Text("FIND", style="bold"),
            Text("VAL", style="bold"),
            Text("SIG", style="bold"),
            Text("CURRENT ACTION", style="bold"),
        )

        for agent_state in self.agents.values():
            color = AGENT_COLORS.get(agent_state.agent_type, "white")
            status_color = {
                "RUNNING": "bright_green",
                "COMPLETED": "green",
                "FAILED": "red",
                "TIMED_OUT": "yellow",
                "PENDING": "dim",
            }.get(agent_state.status, "white")

            status_icon = {
                "RUNNING": "● ",
                "COMPLETED": "✓ ",
                "FAILED": "✗ ",
                "TIMED_OUT": "⊘ ",
                "PENDING": "○ ",
            }.get(agent_state.status, "")

            table.add_row(
                Text(agent_state.agent_type.value, style=f"bold {color}"),
                Text(f"{status_icon}{agent_state.status}", style=status_color),
                Text(str(agent_state.findings_count), style="yellow"),
                Text(str(agent_state.validated_count), style="green"),
                Text(str(agent_state.signals_emitted), style="magenta"),
                Text(agent_state.current_action[:60], style="dim white"),
            )

        return Panel(
            table,
            title="[bold red]ATTACK SWARM[/]",
            border_style="red",
            padding=(0, 1),
        )

    def _build_findings_panel(self) -> Panel:
        if not self.recent_findings:
            content = Align.center(Text("Waiting for findings...", style="dim"))
        else:
            table = Table.grid(expand=True, padding=(0, 1))
            table.add_column(width=10)
            table.add_column(ratio=2)
            table.add_column(ratio=4)

            for finding in reversed(self.recent_findings[-self._max_recent :]):
                severity_str = finding.get("severity", "info")
                try:
                    severity = FindingSeverity(severity_str)
                except ValueError:
                    severity = FindingSeverity.INFO
                sev_style = SEVERITY_STYLES.get(severity, "white")

                agent_type = finding.get("agent_type", "unknown")
                agent_color = "white"
                for at in AgentType:
                    if at.value == agent_type:
                        agent_color = AGENT_COLORS.get(at, "white")
                        break

                title = finding.get("title", "")[:80]
                table.add_row(
                    Text(f" {severity_str.upper()} ", style=sev_style),
                    Text(agent_type[:18], style=agent_color),
                    Text(title, style="white"),
                )
            content = table

        return Panel(
            content,
            title=f"[bold yellow]LIVE FINDINGS  ({self.total_findings} total · {self.total_validated} validated)[/]",
            border_style="yellow",
            padding=(0, 1),
        )

    def _build_signal_panel(self) -> Panel:
        if not self.recent_signals:
            content = Align.center(Text("Waiting for signals...", style="dim"))
        else:
            table = Table.grid(expand=True, padding=(0, 1))
            table.add_column(width=18)
            table.add_column(ratio=1)

            for signal in reversed(self.recent_signals[-self._max_recent :]):
                signal_color = {
                    SignalType.FINDING: "yellow",
                    SignalType.PARTIAL_FINDING: "cyan",
                    SignalType.AGENT_STATUS: "green",
                    SignalType.CORRELATION_REQUEST: "magenta",
                    SignalType.TECHNIQUE_RESULT: "blue",
                }.get(signal.signal_type, "white")

                table.add_row(
                    Text(signal.signal_type.value[:18], style=signal_color),
                    Text(f"{signal.source_agent}", style="dim"),
                )
            content = table

        return Panel(
            content,
            title=f"[bold magenta]SIGNAL BUS  ({self.total_signals} signals)[/]",
            border_style="magenta",
            padding=(0, 1),
        )

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
        )
        layout["body"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1),
        )
        layout["left"].split_column(
            Layout(name="agents", size=12),
            Layout(name="findings"),
        )
        layout["right"].update(self._build_signal_panel())
        layout["agents"].update(self._build_agent_panel())
        layout["findings"].update(self._build_findings_panel())
        layout["header"].update(self._build_header())
        return layout

    async def run(
        self,
        orchestrator: Orchestrator,
        target: TargetConfig,
        timeout: float = 300.0,
        refresh_per_second: int = 8,
        demo_pace_seconds: float = 0.0,
    ) -> ScanResult:
        """Run a scan with the live dashboard active.

        Args:
            demo_pace_seconds: Inter-event delay in seconds for live demos.
                0 = production speed. 0.3-0.8 = visible UI updates.
        """
        self.target_name = target.name
        self.target_urls = list(target.mcp_server_urls)
        if target.agent_endpoint:
            self.target_urls.append(target.agent_endpoint)
        self.scan_started = time.monotonic()

        # Pre-populate agent states for all registered agents
        for agent_type in orchestrator.get_registered_agents():
            self.agents[agent_type.value] = AgentState(agent_type)

        # Subscribe to all signals via the orchestrator's signal bus
        await orchestrator.signal_bus.subscribe_broadcast(self._on_signal)

        # Print banner before starting Live
        self.console.print(BANNER)
        self.console.print()

        with Live(
            self._build_layout(),
            console=self.console,
            refresh_per_second=refresh_per_second,
            screen=False,
            transient=False,
        ) as live:
            # Start the scan as a task and refresh the layout while it runs
            scan_task = asyncio.create_task(
                orchestrator.run_scan(
                    target=target,
                    timeout=timeout,
                    demo_pace_seconds=demo_pace_seconds,
                )
            )

            while not scan_task.done():
                live.update(self._build_layout())
                await asyncio.sleep(1.0 / refresh_per_second)

            # Final refresh
            live.update(self._build_layout())
            result = await scan_task

        # Final summary
        self._print_final_summary(result)
        return result

    def _print_final_summary(self, result: ScanResult) -> None:
        summary = result.summary()
        self.console.print()
        self.console.print(
            Panel(
                Group(
                    Text.from_markup(
                        f"[bold green]SCAN COMPLETE[/]  ·  "
                        f"[white]{summary['duration_seconds']:.2f}s[/]  ·  "
                        f"[bold yellow]{summary['total_findings']} findings[/]  ·  "
                        f"[bold green]{summary['validated_findings']} validated[/]  ·  "
                        f"[bold magenta]{summary['signals_exchanged']} signals[/]"
                    ),
                ),
                title="[bold red]ARGUS[/]",
                border_style="green",
            )
        )
