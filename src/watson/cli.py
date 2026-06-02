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
from .banner import BANNER_TEXT, WELCOME_QUOTES
from .core.models import FindingSeverity, FindingSource
from .tools.registry import registry
from .tools import *  # noqa: F401, F403 — load tool modules to register them
from . import config
from . import setup as setup_module

console = Console()


def _check_first_run() -> None:
    """On first run: show silhouette, welcome, and launch setup wizard."""
    if not config.is_first_run():
        return

    # In non-interactive mode, init default config and skip wizard
    if not sys.stdin.isatty():
        config.init_config()
        return

    # Show silhouette on every startup regardless
    console.clear()
    console.print()

    import random
    quote = random.choice(WELCOME_QUOTES)
    console.print(f"  [dim italic]{quote}[/dim italic]")

    console.print()
    console.print(
        Panel.fit(
            "[bold]Welcome to Watson, the open-source OSINT investigator.[/bold]\n\n"
            "It looks like this is your first run. Let's get you set up.\n"
            "[dim]You can skip any step — defaults work out of the box.[/dim]",
            title="🕵️  First Run Detected",
            border_style="gold1",
        )
    )
    console.print()

    setup_module.run_setup()


def _show_banner() -> None:
    """Show the Sherlock silhouette + Watson banner on terminal launch."""
    console.clear()
    console.print()
    console.print(
        BANNER_TEXT.format(
            version=__version__,
            tool_count=registry.tool_count,
        ),
        style="bold white",
    )


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


async def _run_investigation(query: str, depth: int, output: str | None) -> None:
    """Run autonomous investigation with real-time progress."""
    from .agent import OSINTAgent

    agent = OSINTAgent(depth=depth)
    events = await agent.investigate(query)

    for evt in events:
        etype = evt["event"]
        data = evt["data"]

        if etype == "progress":
            console.print(f"  [dim]⏳ {data['message']}[/dim]")
        elif etype == "plan":
            console.print(Panel(
                f"Target: [bold]{data['seed']}[/bold] ({data['type']})\n"
                f"Categories: {', '.join(data['categories'][:6])}\n"
                f"Depth: {data['depth']}",
                title="📋 Investigation Plan", border_style="gold1"
            ))
        elif etype == "findings":
            tgt = data['target']
            cnt = data['count']
            depth_d = data['depth']
            console.print(f"  [bold cyan]🔍 {tgt}[/bold cyan] — [green]{cnt} findings[/green] at depth {depth_d}")
            for f in data.get("findings", [])[:5]:
                sev = f.get("severity", "info")
                icon = _severity_icon(FindingSeverity(sev) if sev in [s.value for s in FindingSeverity] else FindingSeverity.INFO)
                console.print(f"    {icon} {f.get('title','')[:100]}")
        elif etype == "leads":
            leads = data.get("leads", [])
            if leads:
                lead_str = " ".join(f"[dim]{l['value'][:30]}[/dim]" for l in leads[:5])
                console.print(f"  [yellow]🔗 {data['count']} leads:[/yellow] {lead_str}")
        elif etype == "done":
            console.print()
            console.print(Panel(
                f"Findings: [bold green]{data['total_findings']}[/bold green] | "
                f"Leads: [bold yellow]{data['total_leads']}[/bold yellow]\n"
                f"Graph: {data['graph_stats']['nodes']} entities, {data['graph_stats']['edges']} relations\n"
                f"Depth reached: {data['depth_reached']}",
                title="✅ Investigation Complete", border_style="green"
            ))
        elif etype == "graph":
            pass  # Silent graph updates
        elif etype == "error":
            console.print(f"  [red]⚠️ {data.get('message', 'Unknown error')}[/red]")

    console.rule("[dim]End of investigation")

    # Save if requested
    if output:
        from pathlib import Path
        import json as _json
        opath = Path(output)
        findings = []
        for e in events:
            if e["event"] == "findings":
                findings.extend(e["data"].get("findings", []))
        opath.write_text(_json.dumps({
            "query": query, "depth": depth,
            "findings": findings, "graph": agent.get_graph()
        }, indent=2, default=str))
        console.print(f"\n[green]✓ Report saved to {opath}[/green]")


@click.group()
@click.version_option(__version__, prog_name="watson")
def main():
    """🕵️  Watson — OSINT Research Agent.

    "When you have eliminated the impossible,
    whatever remains, however improbable,
    must be the truth." — Sherlock Holmes

    Autonomous open-source intelligence with 338 Bellingcat tools.
    Knowledge graph, lead tracking, recursive investigation.
    """
    pass


@main.command()
@click.argument("query")
@click.option("--depth", "-d", default=1, type=int, help="Recursion depth (1-3). Higher = more leads investigated")
@click.option("--output", "-o", help="Save report to JSON file")
def investigate(query: str, depth: int, output: str | None):
    """Run an autonomous OSINT investigation.

    \b
    Examples:
      watson investigate "Elon Musk"
      watson investigate "openai.com" --depth 2
      watson investigate "Tesla Inc" -d 1 -o report.json
    """
    _check_first_run()
    try:
        asyncio.run(_run_investigation(query, depth, output))
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


@main.command()
def setup():
    """Configure Watson — API keys, defaults, and preferences."""
    from . import config as cfg
    from . import setup as setup_mod

    if not cfg.is_first_run():
        console.print()
        console.print(
            Panel.fit(
                f"Config already exists at [bold]{cfg.config_path()}[/bold]\n"
                "Running setup will update your existing settings.",
                title="🕵️  Watson Setup",
                border_style="gold1",
            )
        )
        console.print()

    setup_mod.run_setup()


@main.command()
@click.option("--port", "-p", default=8777, help="Port to serve on")
@click.option("--host", "-h", default="0.0.0.0", help="Host to bind to")
def web(port: int, host: str):
    """Launch the Watson investigation dashboard."""
    import os
    import webbrowser
    from pathlib import Path

    _check_first_run()
    _show_banner()

    # Make sure the web package is importable
    web_dir = Path(__file__).parent.parent / "web"
    sys.path.insert(0, str(web_dir.parent))

    try:
        from web.app import app as flask_app
    except ImportError:
        console.print()
        console.print("[red]Flask is not installed.[/red]")
        console.print("Install it with: [bold]pip install flask[/bold]")
        return

    url = f"http://localhost:{port}"
    console.print(f"  🖥  Dashboard: [bold link={url}]{url}[/bold link]")
    console.print(f"  💬 Chat Agent: [bold link={url}/chat]{url}/chat[/bold link]")
    console.print(f"  🔧 Tools: {registry.tool_count} modules · 338 Bellingcat tools")
    console.print(f"  🧠 Knowledge Graph: persistent entity tracking")
    console.print()
    console.print("[dim]Press Ctrl+C to stop[/dim]")

    # Open browser
    try:
        webbrowser.open(url)
    except Exception:
        pass

    flask_app.run(host=host, port=port, debug=False, threaded=True)


@main.command()
@click.option("--port", "-p", default=8777, help="Port to serve on")
@click.option("--host", "-h", default="0.0.0.0", help="Host to bind to")
def chat(port: int, host: str):
    """Launch the Watson chat agent (alias for web)."""
    import os
    import webbrowser
    from pathlib import Path

    _check_first_run()
    _show_banner()

    web_dir = Path(__file__).parent.parent / "web"
    sys.path.insert(0, str(web_dir.parent))

    try:
        from web.app import app as flask_app
    except ImportError:
        console.print()
        console.print("[red]Flask is not installed.[/red]")
        console.print("Install it with: [bold]pip install flask[/bold]")
        return

    url = f"http://localhost:{port}/chat"
    console.print(f"  💬 Chat Agent: [bold link={url}]{url}[/bold link]")
    console.print(f"  🖥  Dashboard: [bold link=http://localhost:{port}]{'http://localhost:' + str(port)}[/bold link]")
    console.print()
    console.print("[dim]Opening browser... Press Ctrl+C to stop[/dim]")

    try:
        webbrowser.open(url)
    except Exception:
        pass

    flask_app.run(host=host, port=port, debug=False, threaded=True)


def cli():
    """Entry point for console_scripts."""
    main()


if __name__ == "__main__":
    main()
