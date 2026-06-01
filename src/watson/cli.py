"""Watson CLI — the command-line interface for OSINT investigations."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.markdown import Markdown
from rich import box

from . import __version__
from .core.engine import Engine
from .core.models import FindingSeverity, FindingSource
from .tools.registry import registry
from .tools import *  # noqa: F401, F403 — load tool modules to register them

console = Console()


SEVERITY_COLORS = {
    FindingSeverity.CRITICAL: "bold red",
    FindingSeverity.HIGH: "red",
    FindingSeverity.MEDIUM: "yellow",
    FindingSeverity.LOW: "dim",
    FindingSeverity.INFO: "blue",
}


def _severity_icon(sev: FindingSeverity) -> str:
    icons = {
        FindingSeverity.CRITICAL: "🚨",
        FindingSeverity.HIGH: "🔴",
        FindingSeverity.MEDIUM: "🟡",
        FindingSeverity.LOW: "⚪",
        FindingSeverity.INFO: "ℹ️",
    }
    return icons.get(sev, "•")


async def _run_investigation(query: str, tools: list[str] | None, output: str | None) -> None:
    """Run the investigation and render results."""
    engine = Engine()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"[bold gold1]Investigating: {query[:80]}...", total=None
        )
        report = await engine.investigate(query, tools=tools)
        progress.remove_task(task)

    # Render report
    console.print()
    console.rule("[bold gold1]🔍 WATSON INVESTIGATION REPORT")
    console.print()

    # Summary panel
    stats = f"Findings: [bold]{report.total_findings}[/bold] | Sources: [bold]{len(report.by_source)}[/bold] categories"
    if report.by_severity:
        sev_parts = []
        for sev, count in sorted(report.by_severity.items()):
            icon = _severity_icon(FindingSeverity(sev))
            sev_parts.append(f"{icon} {count} {sev}")
        stats += " | " + " ".join(sev_parts)

    console.print(Panel(stats, title="Summary", border_style="gold1"))

    # Findings by severity
    if report.findings:
        console.print()
        console.print("[bold]Findings[/bold]", style="underline")
        for finding in report.findings:
            icon = _severity_icon(finding.severity)
            color = SEVERITY_COLORS.get(finding.severity, "")
            console.print(f"  {icon} [bold]{finding.title}[/bold] [{finding.source.value}]")
            if finding.description:
                for line in finding.description.split("\n"):
                    console.print(f"    {line}")
            if finding.evidence:
                for ev in finding.evidence[:2]:
                    console.print(f"    → [dim link={ev}]{ev[:80]}[/dim link]")
            console.print()

    # Cross-references
    if report.cross_references:
        console.print()
        console.print("[bold]Cross-References[/bold]", style="underline")
        for cr in report.cross_references:
            console.print(f"  🔗 [bold]{cr.title}[/bold]")
            console.print(f"    {cr.description[:120]}")

    # Tool stats
    if report.tool_stats:
        console.print()
        table = Table(title="Tool Statistics", box=box.SIMPLE)
        table.add_column("Tool", style="cyan")
        table.add_column("Findings", justify="right", style="green")
        for tool_name, count in sorted(report.tool_stats.items(), key=lambda x: -x[1]):
            table.add_row(tool_name, str(count))
        console.print(table)

    # Save to file if requested
    if output:
        output_path = Path(output)
        report_data = report.model_dump(mode="json")
        output_path.write_text(json.dumps(report_data, indent=2, default=str))
        console.print(f"\n[green]✓ Report saved to {output_path}[/green]")

    console.print()
    console.rule("[dim]End of report")


@click.group()
@click.version_option(__version__, prog_name="watson")
def main():
    """🔍 Watson — OSINT Research Agent.

    Deploy the Bellingcat investigation toolkit.
    Investigate anything, everywhere, in parallel.
    """
    pass


@main.command()
@click.argument("query")
@click.option(
    "--tools", "-t",
    multiple=True,
    help="Specific tool categories to use (e.g., websites, corporate, people)",
)
@click.option(
    "--output", "-o",
    help="Save report to JSON file",
)
def investigate(query: str, tools: tuple[str, ...], output: str | None):
    """Run an OSINT investigation.

    \b
    Examples:
      watson investigate "who owns suspicious-domain.com?"
      watson investigate "company name ltd" --tools corporate websites
      watson investigate "@username" -o report.json
    """
    tool_list = list(tools) if tools else None
    try:
        asyncio.run(_run_investigation(query, tool_list, output))
    except KeyboardInterrupt:
        console.print("\n[yellow]Investigation cancelled[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


@main.command()
def tools():
    """List all available OSINT tools."""
    console.print()
    console.rule("[bold gold1]🛠 AVAILABLE OSINT TOOLS")
    console.print()

    table = Table(box=box.SIMPLE)
    table.add_column("Category", style="cyan")
    table.add_column("Tool", style="green")
    table.add_column("Description")
    table.add_column("Free", justify="center")

    for info in registry.list_categories():
        category = info["category"]
        for tool_name in info["tools"]:
            tool = registry.get(tool_name)
            if tool:
                table.add_row(
                    category,
                    tool.name,
                    tool.description,
                    "✅" if tool.free_tier_available else "🔑",
                )

    console.print(table)
    console.print()
    console.print(f"[dim]{registry.tool_count} tools across {len(registry.list_categories())} categories[/dim]")


@main.command()
@click.argument("tool_name")
def tool_info(tool_name: str):
    """Show detailed info about a specific tool."""
    tool = registry.get(tool_name)
    if not tool:
        console.print(f"[red]Tool '{tool_name}' not found.[/red]")
        console.print(f"Available: {', '.join(registry._tools.keys())}")
        return

    console.print()
    console.print(Panel(
        f"[bold]{tool.name}[/bold]\n"
        f"Category: {tool.category.value}\n"
        f"{tool.description}\n\n"
        f"Free tier: {'✅ Yes' if tool.free_tier_available else '🔑 Requires API key'}\n"
        f"Rate limit: {tool.rate_limit_rps} req/s",
        title="Tool Info",
        border_style="gold1",
    ))


@main.command()
@click.argument("image_path")
@click.option("--api-base", help="API base URL (default: DeepSeek)")
@click.option("--api-key", help="API key (default: $OPENAI_API_KEY)")
@click.option("--model", default="deepseek-v4-pro", help="Vision model to use")
def captcha(image_path: str, api_base: str | None, api_key: str | None, model: str):
    """Solve a CAPTCHA image using vision AI.

    \b
    Examples:
      watson captcha ~/Desktop/captcha.png
      watson captcha captcha.jpg --model gpt-4o --api-key sk-...
    """
    from .tools.captcha import CaptchaSolver

    solver = CaptchaSolver(
        api_base=api_base,
        api_key=api_key,
        model=model,
    )

    with console.status("[bold gold1]Solving CAPTCHA..."):
        result = solver.solve(image_path)

    if result["success"]:
        console.print()
        console.print(Panel(
            f"[bold green]Answer: {result['answer']}[/bold green]\n"
            f"Type: {result.get('captcha_type', 'unknown')}",
            title="✅ CAPTCHA Solved",
            border_style="green",
        ))
    else:
        console.print(f"\n[red]❌ Failed: {result.get('error', 'Unknown error')}[/red]")


def cli():
    """Entry point for console_scripts."""
    main()
