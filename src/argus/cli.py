"""ARGUS CLI — command-line interface for the autonomous AI red team platform."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from argus import __version__
from argus.corpus.manager import AttackCorpus
from argus.models.agents import TargetConfig
from argus.orchestrator.engine import Orchestrator
from argus.reporting.renderer import ReportRenderer

console = Console()


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
    console.print(Panel.fit(
        f"[bold red]ARGUS[/] v{__version__}\n\n"
        "[bold]Phase:[/] 0 — Orchestration Foundation\n"
        "[bold]Agents Registered:[/] 0 (Phase 1 builds first 3)\n"
        "[bold]Corpus Status:[/] Checking...",
        title="System Status",
    ))

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
@click.option("--output", "-o", help="Output file path for JSON report")
def scan(
    target_name: str,
    mcp_url: tuple[str, ...],
    agent_endpoint: str | None,
    timeout: int,
    output: str | None,
) -> None:
    """Run an ARGUS scan against a target AI system."""
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

    orchestrator = Orchestrator()
    registered = orchestrator.get_registered_agents()

    if not registered:
        console.print(
            "[yellow]No attack agents registered yet.[/]\n"
            "Phase 0 provides the orchestration framework.\n"
            "Phase 1 (next) builds the first 3 attack agents:\n"
            "  1. Prompt Injection Hunter\n"
            "  2. Tool Poisoning Agent\n"
            "  3. Supply Chain Agent\n"
        )
        return

    result = asyncio.run(orchestrator.run_scan(target=target, timeout=timeout))

    renderer = ReportRenderer()
    console.print(renderer.render_summary(result))

    if output:
        Path(output).write_text(renderer.render_json(result))
        console.print(f"\n[green]Full report written to {output}[/]")


@main.command()
def corpus() -> None:
    """Show attack corpus statistics."""
    c = AttackCorpus()
    c.load()
    stats = c.stats()

    console.print(Panel.fit(
        f"[bold]Total Patterns:[/] {stats['total_patterns']}\n"
        f"[bold]With Usage Data:[/] {stats['patterns_with_usage']}",
        title="Attack Corpus v0.1",
    ))

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
                    "⚠ YES" if tool.hidden_content_detected else "—",
                )

            console.print(table)

            hidden = [t for t in tools if t.hidden_content_detected]
            if hidden:
                console.print(f"\n[bold red]⚠ {len(hidden)} tool(s) with hidden content detected![/]")
                for t in hidden:
                    console.print(f"  • {t.name}: {t.hidden_content}")

        finally:
            await client.disconnect()

    asyncio.run(_probe())


if __name__ == "__main__":
    main()
