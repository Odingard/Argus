"""ARGUS CLI — command-line interface for the autonomous AI red team platform.

Security: validates all user input (URLs, file paths) before use.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from urllib.parse import urlparse

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from argus import __version__
from argus.agents import PromptInjectionHunter, SupplyChainAgent, ToolPoisoningAgent
from argus.corpus.manager import AttackCorpus
from argus.models.agents import AgentType, TargetConfig
from argus.orchestrator.engine import Orchestrator
from argus.reporting.renderer import ReportRenderer


def _create_orchestrator() -> Orchestrator:
    """Create an orchestrator with all Phase 1 agents registered."""
    orch = Orchestrator()
    orch.register_agent(AgentType.PROMPT_INJECTION, PromptInjectionHunter)
    orch.register_agent(AgentType.TOOL_POISONING, ToolPoisoningAgent)
    orch.register_agent(AgentType.SUPPLY_CHAIN, SupplyChainAgent)
    return orch


console = Console()

ALLOWED_URL_SCHEMES = frozenset({"http", "https"})


BANNER = r"""
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║     █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗    ║
    ║    ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝    ║
    ║    ███████║██████╔╝██║  ███╗██║   ██║███████╗    ║
    ║    ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║    ║
    ║    ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║    ║
    ║    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚══════╝    ║
    ║                                                   ║
    ║       Autonomous AI Red Team Platform             ║
    ║       Odingard Security · Six Sense               ║
    ║                                                   ║
    ╚═══════════════════════════════════════════════════╝
"""


def _validate_url(url: str) -> None:
    """Validate URL has allowed scheme and valid hostname. Prevents SSRF."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_URL_SCHEMES:
        raise click.BadParameter(f"URL scheme '{parsed.scheme}' not allowed. Use http:// or https://")
    if not parsed.netloc:
        raise click.BadParameter("URL must have a valid hostname")


def _validate_output_path(path_str: str) -> Path:
    """Validate output file path — must be within CWD, no symlink attacks."""
    output_path = Path(path_str).resolve()
    cwd = Path.cwd().resolve()

    if not str(output_path).startswith(str(cwd)):
        raise click.BadParameter(f"Output path must be within current directory ({cwd})")

    # Reject if parent directory is a symlink
    if output_path.parent.is_symlink():
        raise click.BadParameter("Output path parent is a symlink")

    return output_path


@click.group()
@click.version_option(version=__version__, prog_name="ARGUS")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
def main(verbose: bool) -> None:
    """ARGUS — Autonomous AI Red Team Platform."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@main.command()
def banner() -> None:
    """Display the ARGUS banner."""
    console.print(BANNER, style="bold red")


@main.command()
def status() -> None:
    """Show ARGUS system status."""
    orch = _create_orchestrator()
    agent_count = len(orch.get_registered_agents())
    agent_names = [a.value for a in orch.get_registered_agents()]

    console.print(
        Panel.fit(
            f"[bold red]ARGUS[/] v{__version__}\n\n"
            f"[bold]Phase:[/] 1 — First Wave Agents\n"
            f"[bold]Agents Registered:[/] {agent_count}\n"
            f"[bold]Agents:[/] {', '.join(agent_names)}\n"
            "[bold]Corpus Status:[/] Checking...",
            title="System Status",
        )
    )

    corpus = AttackCorpus()
    corpus.load()
    stats = corpus.stats()

    table = Table(title="Attack Corpus")
    table.add_column("Category", style="cyan")
    table.add_column("Patterns", justify="right", style="green")
    for cat, num in sorted(stats["by_category"].items()):
        table.add_row(cat, str(num))
    table.add_row("[bold]Total[/]", f"[bold]{stats['total_patterns']}[/]")
    console.print(table)


@main.command()
@click.argument("target_name")
@click.option("--mcp-url", multiple=True, help="MCP server URL(s) to test")
@click.option("--agent-endpoint", help="Target agent endpoint URL")
@click.option("--timeout", default=600, help="Scan timeout in seconds")
@click.option(
    "--demo",
    is_flag=True,
    help="Enable demo pacing (0.4s between findings) so updates are visible",
)
@click.option(
    "--pace",
    type=float,
    default=0.0,
    help="Custom inter-event delay in seconds (overrides --demo)",
)
def live(
    target_name: str,
    mcp_url: tuple[str, ...],
    agent_endpoint: str | None,
    timeout: int,
    demo: bool,
    pace: float,
) -> None:
    """Run an ARGUS scan with the LIVE streaming dashboard.

    Watch the attack swarm work in real time — agent status, findings,
    signal bus events, all updating live in your terminal.
    """
    for url in mcp_url:
        _validate_url(url)
    if agent_endpoint:
        _validate_url(agent_endpoint)

    target = TargetConfig(
        name=target_name,
        mcp_server_urls=list(mcp_url),
        agent_endpoint=agent_endpoint,
    )

    from argus.ui import LiveDashboard

    orchestrator = _create_orchestrator()
    dashboard = LiveDashboard(console=console)

    pace_seconds = pace if pace > 0 else (0.4 if demo else 0.0)
    asyncio.run(
        dashboard.run(
            orchestrator,
            target,
            timeout=float(timeout),
            demo_pace_seconds=pace_seconds,
        )
    )


@main.command()
@click.argument("target_name")
@click.option("--mcp-url", multiple=True, help="MCP server URL(s) to test")
@click.option("--agent-endpoint", help="Target agent endpoint URL")
@click.option("--timeout", default=600, help="Scan timeout in seconds")
@click.option("--output", "-o", help="Output file path for JSON report")
def scan(
    target_name: str,
    mcp_url: tuple[str, ...],
    agent_endpoint: str | None,
    timeout: int,
    output: str | None,
) -> None:
    """Run an ARGUS scan against a target AI system."""
    # Validate all URLs
    for url in mcp_url:
        _validate_url(url)
    if agent_endpoint:
        _validate_url(agent_endpoint)

    # Validate output path
    output_path = None
    if output:
        output_path = _validate_output_path(output)

    console.print(BANNER, style="bold red")
    console.print(f"\n[bold]Target:[/] {target_name}")
    console.print(f"[bold]MCP URLs:[/] {', '.join(mcp_url) if mcp_url else 'None'}")
    console.print(f"[bold]Agent Endpoint:[/] {agent_endpoint or 'None'}")
    console.print(f"[bold]Timeout:[/] {timeout}s\n")

    target = TargetConfig(
        name=target_name,
        mcp_server_urls=list(mcp_url),
        agent_endpoint=agent_endpoint,
    )

    orchestrator = _create_orchestrator()
    registered = orchestrator.get_registered_agents()

    console.print(f"[bold]Deploying {len(registered)} agents simultaneously...[/]\n")

    result = asyncio.run(orchestrator.run_scan(target=target, timeout=timeout))

    renderer = ReportRenderer()
    console.print(renderer.render_summary(result))

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(renderer.render_json(result))
        console.print(f"\n[green]Full report written to {output_path}[/]")


@main.command()
def corpus() -> None:
    """Show attack corpus statistics."""
    c = AttackCorpus()
    c.load()
    stats = c.stats()

    console.print(
        Panel.fit(
            f"[bold]Total Patterns:[/] {stats['total_patterns']}\n"
            f"[bold]With Usage Data:[/] {stats['patterns_with_usage']}",
            title="Attack Corpus v0.1",
        )
    )

    table = Table(title="Patterns by Category")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right", style="green")
    for cat, num in sorted(stats["by_category"].items()):
        table.add_row(cat, str(num))
    console.print(table)


@main.command()
@click.argument("mcp_url")
def probe(mcp_url: str) -> None:
    """Probe an MCP server — enumerate tools and scan for hidden content."""
    _validate_url(mcp_url)

    from argus.mcp_client import MCPAttackClient, MCPServerConfig

    config = MCPServerConfig(
        name="probe-target",
        transport="streamable-http",
        url=mcp_url,
    )

    async def _probe() -> None:
        client = MCPAttackClient(config)
        try:
            await client.connect()
            tools = await client.enumerate_tools()

            table = Table(title=f"MCP Tools — {mcp_url}")
            table.add_column("Tool", style="cyan")
            table.add_column("Description", style="white", max_width=50)
            table.add_column("Params", justify="right")
            table.add_column("Hidden Content", style="red")

            for tool in tools:
                table.add_row(
                    tool.name,
                    (tool.description or "")[:50],
                    str(len(tool.parameters)),
                    "YES" if tool.hidden_content_detected else "-",
                )

            console.print(table)

            hidden = [t for t in tools if t.hidden_content_detected]
            if hidden:
                console.print(f"\n[bold red]{len(hidden)} tool(s) with hidden content detected![/]")
                for t in hidden:
                    console.print(f"  - {t.name}: {t.hidden_content}")

        finally:
            await client.disconnect()

    asyncio.run(_probe())


if __name__ == "__main__":
    main()
