"""
Watson CLI — terminal interface with character.
"""

from __future__ import annotations

import asyncio
import os
import random
import sys
from pathlib import Path

# ANSI colors
W = "\033[38;5;208m"  # amber
B = "\033[1m"
D = "\033[2m"
G = "\033[32m"
R = "\033[31m"
Y = "\033[33m"
C = "\033[36m"
X = "\033[0m"

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
║   {D}Open-source intelligence. Bellingcat methodology.{W}              ║
║   {D}Graph-native. Community-powered.{W}                             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{X}
"""

SHERLOCK_QUOTES = [
    '"It is a capital mistake to theorize before one has data."',
    '"The world is full of obvious things which nobody by any chance ever observes."',
    '"There is nothing more deceptive than an obvious fact."',
    '"You see, but you do not observe."',
    '"Data! Data! Data! I can\'t make bricks without clay."',
    '"When you have eliminated the impossible, whatever remains, however improbable, must be the truth."',
    '"The little things are infinitely the most important."',
    '"What one man can invent, another can discover."',
]


def _quote() -> str:
    return f"{D}{random.choice(SHERLOCK_QUOTES)}{X}"


def onboarding() -> dict:
    """First-time setup with personality."""
    print(WATSON_BANNER)
    print(f"  {_quote()}")
    print(f"\n{G}Welcome. Let's set up your investigation environment.{X}\n")

    config = {
        "agent": "hermes",
        "api_key": "",
        "api_base": "",
        "model": "",
        "cases_dir": os.path.expanduser("~/watson-cases"),
        "publish_to_mcp": True,
    }

    # ── Agent engine ───────────────────────────────────────────
    print(f"{Y}→ Pick your engine:{X}")
    print(f"  [1] {B}Hermes{X} — local, full toolset (web, browser, vision, terminal)")
    print(f"  [2] {D}LLM API{X} — any OpenAI-compatible provider, API key only")
    print()

    choice = input(f"  {G}Choice [1]:{X} ").strip() or "1"
    config["agent"] = "hermes" if choice == "1" else "direct"

    # ── LLM API config ─────────────────────────────────────────
    if config["agent"] == "direct":
        print(f"\n  {_quote()}")
        key = input(f"\n{Y}  API key (or WATSON_API_KEY env var):{X} ").strip()
        if key:
            config["api_key"] = key

        base = input(f"  {Y}API base URL [https://api.openai.com/v1]:{X} ").strip()
        if base:
            config["api_base"] = base

        model = input(f"  {Y}Model [gpt-4o]:{X} ").strip() or "gpt-4o"
        config["model"] = model

    # ── Cases ──────────────────────────────────────────────────
    cases = input(f"\n{Y}  Case files directory [{config['cases_dir']}]:{X} ").strip()
    if cases:
        config["cases_dir"] = os.path.expanduser(cases)

    # ── Community graph ────────────────────────────────────────
    publish = input(f"\n{Y}  Contribute to community knowledge graph? [Y/n]:{X} ").strip().lower()
    config["publish_to_mcp"] = publish != "n"

    # ── Save ───────────────────────────────────────────────────
    import json
    config_dir = Path.home() / ".watson"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.json").write_text(json.dumps(config, indent=2))

    print(f"\n{G}✓ Ready.{X}")
    print(f"  {_quote()}")
    print(f"\n  Engine: {B}{config['agent']}{X}")
    print(f"  Cases:  {D}{config['cases_dir']}{X}")
    print(f"  Graph:  {G if config['publish_to_mcp'] else R}{'contributing' if config['publish_to_mcp'] else 'local only'}{X}")
    print(f"\n{D}Type a target to investigate, or /help.{X}")

    return config


def load_config() -> dict:
    config_file = Path.home() / ".watson" / "config.json"
    if config_file.exists():
        import json
        return json.loads(config_file.read_text())
    return {}


def create_agent(config: dict):
    agent_type = config.get("agent", "hermes")

    if agent_type == "hermes":
        from watson.agents import HermesAdapter
        return HermesAdapter()
    elif agent_type == "direct":
        from watson.agents.direct import DirectAdapter
        return DirectAdapter(
            api_key=config.get("api_key", os.environ.get("WATSON_API_KEY", "")),
            model=config.get("model") or "gpt-4o",
            api_base=config.get("api_base") or None,
        )
    else:
        raise ValueError(f"Unknown engine: {agent_type}")


async def main():
    config = load_config()
    if not config:
        config = onboarding()

    agent = create_agent(config)

    print(f"\n{D}Checking {agent.name}...{X}", end=" ")
    healthy = await agent.health_check()
    if healthy:
        print(f"{G}connected{X}")
    else:
        print(f"{R}unavailable{X}")
        print(f"{R}Is {agent.name} running? Check config in ~/.watson/config.json{X}")
        sys.exit(1)

    from watson.engine import InvestigationEngine
    engine = InvestigationEngine(agent=agent, cases_dir=config["cases_dir"])

    print()
    while True:
        try:
            query = input(f"{G}watson>{X} ").strip()

            if not query:
                continue

            if query.lower() in ("exit", "quit", "q"):
                print(f"\n  {_quote()}")
                print(f"{D}Cases saved to {config['cases_dir']}{X}")
                break

            if query.startswith("/help"):
                print(f"""
{C}Commands:{X}
  {B}<target>{X}         Investigate a person, domain, company, email, or topic
  {B}/help{X}           This message
  {B}/cases{X}          List past investigations
  {B}/graph{X}          Knowledge graph stats
  {B}/exit{X}           Goodbye
""")
                continue

            if query.startswith("/cases"):
                cases = engine.list_cases()
                if cases:
                    for c in cases[:10]:
                        print(f"  {C}{c['id']}{X} — {D}{c['modified'][:10]}{X}")
                else:
                    print(f"  {D}No cases yet.{X}")
                continue

            if query.startswith("/graph"):
                stats = engine.graph.stats()
                print(f"  Entities: {stats['entity_count']} | Relations: {stats['relation_count']} | Cases: {stats['case_count']}")
                continue

            # Strip "investigate" prefix if present
            clean = query
            for prefix in ("investigate ", "research ", "look up ", "find "):
                if clean.lower().startswith(prefix):
                    clean = clean[len(prefix):]
                    break

            print(f"\n{C}🔍 Investigating: {clean}{X}")
            print(f"{D}  {_quote()}{X}\n")

            case = await engine.investigate(clean)

            print(f"\n{G}✓ Case {case.id}{X} · {len(case.findings)} findings · {len(case.angles)} angles")
            print(f"{case.markdown}")

        except KeyboardInterrupt:
            print(f"\n  {_quote()}")
            print(f"{D}Shutting down.{X}")
            break
        except Exception as e:
            print(f"{R}Error: {e}{X}")


if __name__ == "__main__":
    asyncio.run(main())
