"""
Watson CLI — branded terminal with onboarding and investigation commands.
Watson owns its entire identity: banner, colors, and personality.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# ANSI color codes for Watson branding
W = "\033[38;5;208m"  # Watson amber/orange
B = "\033[1m"          # Bold
D = "\033[2m"          # Dim
G = "\033[32m"         # Green
R = "\033[31m"         # Red
Y = "\033[33m"         # Yellow
C = "\033[36m"         # Cyan
X = "\033[0m"          # Reset

WATSON_BANNER = f"""
{W}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   {B}██╗    ██╗ █████╗ ████████╗███████╗ ██████╗ ███╗   ██╗{W}   ║
║   {B}██║    ██║██╔══██╗╚══██╔══╝██╔════╝██╔═══██╗████╗  ██║{W}   ║
║   {B}██║ █╗ ██║███████║   ██║   ███████╗██║   ██║██╔██╗ ██║{W}   ║
║   {B}██║███╗██║██╔══██║   ██║   ╚════██║██║   ██║██║╚██╗██║{W}   ║
║   {B}╚███╔███╔╝██║  ██║   ██║   ███████║╚██████╔╝██║ ╚████║{W}   ║
║   {B} ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝{W}   ║
║                                                              ║
║   {D}The OSINT investigation engine.{W}                              ║
║   {D}Bellingcat-inspired. Graph-native. Community-powered.{W}         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{X}
"""


def onboarding() -> dict:
    """Run first-time onboarding flow. Returns config dict."""
    print(WATSON_BANNER)
    print(f"{G}Welcome to Watson. Let's set up your investigation environment.{X}\n")
    
    config = {
        "agent": "hermes",
        "hermes_api_url": "http://localhost:8778",
        "cases_dir": os.path.expanduser("~/watson-cases"),
        "publish_to_mcp": True,
    }
    
    # ── Agent engine selection ──────────────────────────────────
    print(f"{Y}→ Choose your agent engine:{X}")
    print(f"  [1] {B}Hermes{X} — local, full toolset (web, browser, vision, terminal)")
    print(f"  [2] {D}Direct LLM{X} — API key only, no local install needed")
    print(f"  [3] {D}OpenClaw{X}")
    print(f"  [4] {D}OpenHuman (coming soon){X}")
    print()
    
    choice = input(f"  {G}Your choice [1]:{X} ").strip() or "1"
    
    agent_map = {"1": "hermes", "2": "direct", "3": "openclaw"}
    config["agent"] = agent_map.get(choice, "hermes")
    
    # ── Hermes-specific config ──────────────────────────────────
    if config["agent"] == "hermes":
        url = input(f"\n{Y}  Hermes API URL [{config['hermes_api_url']}]:{X} ").strip()
        if url:
            config["hermes_api_url"] = url
    
    # ── Direct LLM config ───────────────────────────────────────
    if config["agent"] == "direct":
        key = input(f"\n{Y}  API Key (or set WATSON_API_KEY env var):{X} ").strip()
        if key:
            config["api_key"] = key
        model = input(f"  {Y}Model [deepseek-chat]:{X} ").strip() or "deepseek-chat"
        config["model"] = model
    
    # ── Cases directory ─────────────────────────────────────────
    cases = input(f"\n{Y}  Cases directory [{config['cases_dir']}]:{X} ").strip()
    if cases:
        config["cases_dir"] = os.path.expanduser(cases)
    
    # ── MCP publishing ──────────────────────────────────────────
    publish = input(f"\n{Y}  Publish public cases to community MCP? [Y/n]:{X} ").strip().lower()
    config["publish_to_mcp"] = publish != "n"
    
    # ── Save config ─────────────────────────────────────────────
    import json
    config_dir = Path.home() / ".watson"
    config_dir.mkdir(exist_ok=True)
    config_file = config_dir / "config.json"
    config_file.write_text(json.dumps(config, indent=2))
    
    print(f"\n{G}✓ Watson is ready.{X}")
    print(f"  Agent: {B}{config['agent']}{X}")
    print(f"  Cases: {D}{config['cases_dir']}{X}")
    print(f"  MCP publishing: {G if config['publish_to_mcp'] else R}{'on' if config['publish_to_mcp'] else 'off'}{X}")
    print(f"\n{D}Type {B}/investigate <target>{D} to begin.{X}")
    print(f"{D}Or just describe what you want to investigate.{X}")
    
    return config


def load_config() -> dict:
    """Load saved config or run onboarding."""
    config_file = Path.home() / ".watson" / "config.json"
    if config_file.exists():
        import json
        return json.loads(config_file.read_text())
    return {}


def create_agent(config: dict):
    """Create an agent adapter from config."""
    agent_type = config.get("agent", "hermes")
    
    if agent_type == "hermes":
        from watson.agents import HermesAdapter
        return HermesAdapter(api_url=config.get("hermes_api_url"))
    elif agent_type == "direct":
        from watson.agents.direct import DirectAdapter
        return DirectAdapter(
            api_key=config.get("api_key", os.environ.get("WATSON_API_KEY", "")),
            model=config.get("model", "deepseek-chat"),
        )
    elif agent_type == "openclaw":
        raise NotImplementedError("OpenClaw adapter — coming soon")
    else:
        raise ValueError(f"Unknown agent type: {agent_type}")


async def main():
    """Watson CLI entry point."""
    config = load_config()
    if not config:
        config = onboarding()
    
    # ── Agent health check ──────────────────────────────────────
    agent = create_agent(config)
    
    print(f"\n{D}Checking {agent.name} connection...{X}", end=" ")
    healthy = await agent.health_check()
    if healthy:
        print(f"{G}✓{X}")
    else:
        print(f"{R}✗{X}")
        print(f"{R}Cannot reach {agent.name}. Is it running?{X}")
        print(f"  {D}Hermes: {R}hermes api-server --port 8778{X}")
        sys.exit(1)
    
    # ── REPL ────────────────────────────────────────────────────
    from watson.engine import InvestigationEngine
    
    engine = InvestigationEngine(
        agent=agent,
        cases_dir=config["cases_dir"],
    )
    
    print()
    while True:
        try:
            query = input(f"{G}watson>{X} ").strip()
            
            if not query:
                continue
            
            if query.lower() in ("exit", "quit", "q"):
                print(f"{D}Shutting down Watson. Cases saved to {config['cases_dir']}{X}")
                break
            
            if query.startswith("/investigate"):
                query = query.replace("/investigate", "").strip()
            
            if query:
                print(f"\n{C}🔍 Investigating: {query}{X}\n")
                print(f"{D}Angles dispatched in parallel...{X}")
                
                case = await engine.investigate(query)
                
                print(f"\n{G}✓ Investigation complete.{X}")
                print(f"  Case: {B}{case.id}{X}")
                print(f"  Findings: {len(case.findings)}")
                print(f"  Angles: {len(case.angles)}")
                print(f"  Saved: {config['cases_dir']}/{case.id}.md")
                print(f"\n{case.markdown}")
                
        except KeyboardInterrupt:
            print(f"\n{D}Shutting down Watson...{X}")
            break
        except Exception as e:
            print(f"{R}Error: {e}{X}")


if __name__ == "__main__":
    asyncio.run(main())
