"""
Watson CLI — terminal interface for the OSINT investigation engine.

Commands:
  watson setup        First-time setup wizard
  watson onboard      Same as setup
  watson doctor       System health check
  watson tools        List available APIs
  watson config       Show/edit configuration
  watson web          Start the web interface
  watson chat         Open browser to the web interface
  watson investigate  Run a single investigation
  watson graph        Show knowledge graph stats
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path

# Ensure src/ is on path so `from src.watson...` imports work
# without requiring PYTHONPATH=.:src in the shell.
_src = Path(__file__).resolve().parent.parent / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

# ANSI colors
W = "\033[38;5;208m"  # amber
B = "\033[1m"
D = "\033[2m"
G = "\033[32m"
R = "\033[31m"
Y = "\033[33m"
C = "\033[36m"
M = "\033[35m"  # magenta — for graph/MCP
X = "\033[0m"

VERSION = "1.0.0"
CODENAME = "A Study in Scarlet"

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
║   {D}{VERSION} · {CODENAME}{W}                                         ║
║   {D}Multi-source OSINT. Graph-native. Community-powered.{W}          ║
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
    '"There is nothing more stimulating than a case where everything goes against you."',
    '"I am not the law, but I represent justice so far as my feeble powers go."',
]


def _quote() -> str:
    return f"{D}{random.choice(SHERLOCK_QUOTES)}{X}"


def _config_dir() -> Path:
    return Path.home() / ".watson"


def _config_path() -> Path:
    return _config_dir() / "config.json"


def _load_config() -> dict:
    if _config_path().exists():
        return json.loads(_config_path().read_text())
    return {}


def _save_config(config: dict):
    _config_dir().mkdir(exist_ok=True)
    _config_path().write_text(json.dumps(config, indent=2))


# ═══════════════════════════════════════════════════════════════════
# ONBOARDING
# ═══════════════════════════════════════════════════════════════════


def _check_agent_available(name: str) -> bool:
    """Check if an agent backend is available on the system."""
    if name == "direct":
        return True  # Built-in, no external binary needed
    return shutil.which(name) is not None


def _discover_agents() -> list[dict]:
    """Auto-discover available agent adapters from watson/agents/."""
    agents_dir = Path(__file__).resolve().parent / "agents"
    discovered: list[dict] = []

    # Always include Direct as built-in
    discovered.append({
        "name": "direct",
        "description": "Any OpenAI-compatible API (OpenAI, Anthropic, DeepSeek, Groq)",
        "available": True,
    })

    for f in sorted(agents_dir.glob("*.py")):
        if f.name.startswith("_") or f.name == "base.py" or f.name == "direct.py":
            continue
        try:
            spec = importlib.util.spec_from_file_location(
                f"watson.agents.{f.stem}", str(f)
            )
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if (isinstance(attr, type) and
                        hasattr(attr, "name") and
                        attr_name.endswith("Adapter") and
                        attr_name != "AgentAdapter"):
                        agent_name = getattr(attr, "name", "")
                        if not agent_name or agent_name == "base":
                            continue
                        discovered.append({
                            "name": agent_name,
                            "description": getattr(attr, "description", f"{agent_name.title()} agent"),
                            "available": _check_agent_available(agent_name),
                        })
                        break
        except Exception:
            pass

    return discovered


def cmd_onboard():
    """First-time setup wizard — v1 'A Study in Scarlet'."""
    print(WATSON_BANNER)
    print(f"  {_quote()}")
    print(f"\n{G}Welcome to Watson {VERSION} — {CODENAME}.{X}")
    print(f"{D}Everything you need ships free. Premium features scale when you do.{X}\n")

    existing = _load_config()
    config = {
        "agent": existing.get("agent", "direct"),
        "api_key": existing.get("api_key", ""),
        "api_base": existing.get("api_base", ""),
        "model": existing.get("model", ""),
        "cases_dir": existing.get("cases_dir", os.path.expanduser("~/watson-cases")),
        "mcp_url": existing.get("mcp_url", "http://localhost:8700"),
        "mcp_api_key": existing.get("mcp_api_key", ""),
        "publish_to_mcp": existing.get("publish_to_mcp", False),
        "paid_api_keys": existing.get("paid_api_keys", {}),
    }

    # ── Step 1: Engine ──
    print(f"{Y}═══ Step 1/4: Choose Your Engine{X}\n")
    
    agents = _discover_agents()
    
    for i, agent in enumerate(agents):
        idx = i + 1
        status = f"{G}available{X}" if agent["available"] else f"{Y}not detected{X}"
        print(f"  [{idx}] {B}{agent['name'].title()}{X} — {agent['description']}")
        print(f"       {D}Status: {status}{X}")
        if not agent["available"]:
            print(f"       {Y}⚠ Install {agent['name']} first, or choose a different engine.{X}")
        print()
    
    # Default: match existing config, or first available agent
    default_idx = 1
    for i, agent in enumerate(agents):
        if agent["available"] and agent["name"] == existing.get("agent", "direct"):
            default_idx = i + 1
            break
    else:
        for i, agent in enumerate(agents):
            if agent["available"]:
                default_idx = i + 1
                break
    
    choice = input(f"  {G}Choice [{default_idx}]:{X} ").strip() or str(default_idx)
    try:
        chosen_idx = int(choice) - 1
        if 0 <= chosen_idx < len(agents):
            chosen = agents[chosen_idx]
            if not chosen["available"]:
                print(f"\n  {Y}⚠ {chosen['name'].title()} is not installed. Using Direct.{X}\n")
                config["agent"] = "direct"
            else:
                config["agent"] = chosen["name"]
        else:
            config["agent"] = agents[0]["name"]
    except ValueError:
        config["agent"] = agents[0]["name"]

    if config["agent"] == "direct":
        print()
        api_key = os.environ.get("WATSON_API_KEY", config.get("api_key", ""))
        masked = f"{api_key[:8]}..." if len(api_key) > 8 else "(not set)"
        print(f"  {D}API key (env WATSON_API_KEY): {masked}{X}")
        key = input(f"  {Y}Enter or paste new key [skip to keep current]:{X} ").strip()
        if key:
            config["api_key"] = key
        
        base = input(f"  {Y}API base URL [https://api.openai.com/v1]:{X} ").strip()
        if base:
            config["api_base"] = base
        elif config.get("api_base"):
            pass  # keep existing
        else:
            config["api_base"] = "https://api.openai.com/v1"
        
        model = input(f"  {Y}Model [gpt-4o]:{X} ").strip() or config.get("model") or "gpt-4o"
        config["model"] = model

    # ── Step 2: OSINT API keys (optional) ──
    print(f"\n{Y}═══ Step 2/4: OSINT API Keys {D}(optional — free tier works without any){X}\n")
    print(f"  {D}Paid APIs unlock deeper investigations. All are optional.{X}")
    print(f"  {D}Without any keys, Watson still uses 10+ free sources.{X}\n")

    paid_keys = config.get("paid_api_keys", {})
    apis = [
        ("OpenSanctions", "opensanctions", "Sanctions, entities, corporate registry"),
        ("VirusTotal", "virustotal", "Domain/IP reputation, malware analysis"),
        ("OpenCorporates", "opencorporates", "Company registries worldwide"),
        ("HIBP", "hibp", "Have I Been Pwned — breach data"),
    ]
    for name, slug, desc in apis:
        current = paid_keys.get(slug, "")
        status = f"{G}set{X}" if current else f"{D}not set{X}"
        print(f"  [{name}] {desc} — {status}")
        key = input(f"  {Y}  Key [skip]:{X} ").strip()
        if key:
            paid_keys[slug] = key
    
    config["paid_api_keys"] = paid_keys

    # ── Step 3: Community Graph (MCP) ──
    print(f"\n{Y}═══ Step 3/4: Community Graph{X}\n")
    print(f"  {B}The Watson Knowledge Graph{X} connects investigations across users.")
    print(f"  {D}When you publish a case, entities are shared so others can discover")
    print(f"  {D}connections from your work — and you benefit from theirs.{X}\n")
    print(f"  {D}By default, your graph is local to this machine. Nothing is shared")
    print(f"  {D}unless you opt in per-investigation.{X}\n")

    mcp_url = input(f"  {Y}MCP server URL [{config['mcp_url']}]:{X} ").strip()
    if mcp_url:
        config["mcp_url"] = mcp_url
    
    if "localhost" in config["mcp_url"] or "127.0.0.1" in config["mcp_url"]:
        print(f"  {D}→ Local graph — your data stays on this machine.{X}")
    else:
        print(f"  {D}→ Remote graph at {config['mcp_url']} — cases publish to shared instance.{X}")
        mcp_key = input(f"  {Y}MCP API key (for publishing):{X} ").strip()
        if mcp_key:
            config["mcp_api_key"] = mcp_key

    # ── Step 4: Case storage ──
    print(f"\n{Y}═══ Step 4/4: Case Storage{X}\n")
    cases = input(f"  {Y}Case files directory [{config['cases_dir']}]:{X} ").strip()
    if cases:
        config["cases_dir"] = os.path.expanduser(cases)
    Path(config["cases_dir"]).mkdir(parents=True, exist_ok=True)

    # ── Save ──
    _save_config(config)

    print(f"\n{G}═══ Configuration Complete ═══{X}\n")
    print(f"  Engine:     {B}{config['agent']}{X}")
    print(f"  Model:      {D}{config.get('model','(hermes)')}{X}")
    print(f"  Cases:      {D}{config['cases_dir']}{X}")
    print(f"  Graph:      {D}{config['mcp_url']}{X}")
    paid_count = sum(1 for v in config.get("paid_api_keys", {}).values() if v)
    print(f"  Paid APIs:  {G if paid_count else D}{paid_count}/4 configured{X}")
    print(f"\n  {_quote()}")
    print(f"\n  {G}Watson is ready.{X}")

    # Offer to launch interface immediately
    launch = input(f"\n  {Y}Launch the web interface now? [Y/n]:{X} ").strip().lower()
    if launch in ("", "y", "yes"):
        print(f"\n  {G}Starting Watson...{X}\n")
        _launch_web("127.0.0.1", 8777)
    else:
        py = sys.executable
        print(f"\n  {D}Start anytime with:{X}")
        print(f"    {B}{py} -m watson.cli web{X}")
        print(f"\n  {D}Other commands:{X}")
        print(f"    {B}{py} -m watson.cli doctor{D}   — system health check{X}")
        print(f"    {B}{py} -m watson.cli tools{D}    — list available APIs{X}")
        print(f"    {B}{py} -m watson.cli chat{D}     — open the web interface{X}\n")


# ═══════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════


def cmd_config(args):
    """Show or update configuration."""
    if not _config_path().exists():
        print(f"{R}No config found. Run '{B}watson onboard{R}' first.{X}")
        sys.exit(1)

    config = _load_config()

    if args.key and args.value:
        # Nested keys: paid_api_keys.opensanctions
        keys = args.key.split(".")
        target = config
        for k in keys[:-1]:
            target = target.setdefault(k, {})
        target[keys[-1]] = args.value
        _save_config(config)
        print(f"{G}✓ {args.key} = {args.value}{X}")
        return

    if args.key:
        keys = args.key.split(".")
        target = config
        for k in keys:
            target = target.get(k, {}) if isinstance(target, dict) else target
        val = target if target != {} else f"{R}(not set){X}"
        print(f"{args.key}: {val}")
        return

    # Show all
    print(f"{B}Watson {VERSION} Configuration{X}\n")
    for k, v in config.items():
        if k in ("api_key", "mcp_api_key"):
            masked = v[:8] + "..." if v else "(not set)"
            print(f"  {C}{k}{X}: {masked}")
        elif k == "paid_api_keys":
            print(f"  {C}{k}{X}:")
            for slug, key in v.items():
                status = f"{G}●●●●{X}" if key else f"{D}(not set){X}"
                print(f"    {slug}: {status}")
        else:
            print(f"  {C}{k}{X}: {v}")
    print(f"\n  {D}Config file: {_config_path()}{X}")


def _launch_web(host: str = "127.0.0.1", port: int = 8777) -> None:
    """Start the web server in background and open browser when ready."""
    import webbrowser
    import time

    project_root = Path(__file__).resolve().parent.parent
    config = _load_config()
    mcp_url = config.get("mcp_url", "http://localhost:8700")

    env = os.environ.copy()
    env["PYTHONPATH"] = f"src:{project_root}:{env.get('PYTHONPATH', '')}"
    env["WATSON_MCP_URL"] = mcp_url
    if config.get("mcp_api_key"):
        env["MCP_API_KEY"] = config["mcp_api_key"]

    print(f"  {D}Starting server on http://{host}:{port} ...{X}")

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "watson.web.app:app",
         "--host", host, "--port", str(port)],
        cwd=str(project_root),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for server to be ready
    import socket
    for _ in range(15):
        time.sleep(0.5)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex((host, port)) == 0:
            sock.close()
            break
        sock.close()
    else:
        print(f"  {Y}Server may still be starting — open http://{host}:{port}{X}")
        return

    print(f"  {G}Server ready. Opening browser...{X}")
    time.sleep(0.5)
    webbrowser.open(f"http://{host}:{port}")

    # Keep running until Ctrl+C
    try:
        print(f"  {D}Press Ctrl+C to stop.{X}")
        proc.wait()
    except KeyboardInterrupt:
        print(f"\n  {Y}Shutting down...{X}")
        proc.terminate()
        proc.wait()


# ═══════════════════════════════════════════════════════════════════
# WEB
# ═══════════════════════════════════════════════════════════════════


def cmd_web(args):
    """Start the web UI."""
    if not _config_path().exists():
        print(f"{Y}No config found — running onboarding first...{X}\n")
        cmd_onboard()

    host = args.host or "0.0.0.0"
    port = args.port or 8777

    print(WATSON_BANNER)
    print(f"  {_quote()}")
    print(f"\n  {G}Starting Watson web interface...{X}")

    _launch_web("127.0.0.1", port)


# ═══════════════════════════════════════════════════════════════════
# GRAPH — show knowledge graph status
# ═══════════════════════════════════════════════════════════════════


def cmd_graph(args):
    """Show knowledge graph stats and recent entities."""
    config = _load_config()
    mcp_url = config.get("mcp_url", "http://localhost:8700")
    
    print(f"{B}Watson Knowledge Graph{X}\n")
    
    try:
        import httpx
        resp = httpx.get(f"{mcp_url}/api/stats", timeout=5)
        if resp.status_code == 200:
            stats = resp.json()
            print(f"  {G}Server:{X}    {mcp_url}")
            print(f"  {G}Entities:{X}  {stats.get('entity_count', 0)}")
            print(f"  {G}Relations:{X} {stats.get('relation_count', 0)}")
            print(f"  {G}Cases:{X}     {stats.get('case_count', 0)}")
            
            types = stats.get("entity_types", {})
            if types:
                print(f"\n  {B}Entity types:{X}")
                for t, count in sorted(types.items(), key=lambda x: -x[1]):
                    print(f"    {t}: {count}")
            
            top = stats.get("top_entities", [])
            if top:
                print(f"\n  {B}Most-connected entities:{X}")
                for e in top[:5]:
                    print(f"    {e['value'][:60]} ({e['type']}) — {e['case_count']} cases")
        else:
            print(f"  {Y}Graph server returned {resp.status_code}{X}")
    except Exception as e:
        print(f"  {R}Graph not reachable at {mcp_url}{X}")
        print(f"  {D}Start Watson with '{B}watson web{D}' to auto-start a local graph.{X}")
        if "localhost" in mcp_url:
            print(f"  {D}  or run: {B}uvicorn watson.mcp_server:mcp --port 8700{X}")
    
    print(f"\n  {D}MCP tools: watson_search, watson_traverse, watson_context, watson_case, watson_stats{X}")
    print(f"  {D}Self-hosting: see SELF_HOSTING.md{X}")


# ═══════════════════════════════════════════════════════════════════
# INVESTIGATE — CLI mode (for headless/scripted runs)
# ═══════════════════════════════════════════════════════════════════


def cmd_investigate(args):
    """Run a single investigation from the terminal."""
    if not args.query:
        print(f"{R}Usage: watson investigate <target>{X}")
        print(f"  Example: watson investigate \"Elon Musk\"")
        print(f"  Target types: person, company, domain, email, IP, wallet")
        sys.exit(1)

    config = _load_config()
    if not config:
        print(f"{Y}No config found — running onboarding first...{X}\n")
        cmd_onboard()
        config = _load_config()

    async def _run():
        from src.watson.orchestration import get_engine

        engine = get_engine()
        query = args.query

        print(WATSON_BANNER)
        print(f"  {_quote()}")
        print(f"\n{C}🔍 Investigating: {query}{X}\n")

        def on_event(event_type, data):
            if event_type == "progress":
                msg = data.get("message", "")
                print(f"  {D}{msg}{X}")
            elif event_type == "finding":
                title = data.get("title", "")[:120]
                confidence = data.get("confidence", 0)
                bar = "🟢" if confidence > 0.7 else "🟡" if confidence > 0.4 else "🔴"
                print(f"  {bar} {title}")

        result = await engine.investigate(
            query=query,
            focus="",
            on_event=on_event,
            mode="deep_investigation",
        )
        
        print(f"\n{G}═══ Investigation Complete ═══{X}")
        print(f"  Case:  {result['case_id']}")
        print(f"  Findings: {result['findings_count']} ({result['confirmed_count']} confirmed)")
        print(f"  Verifiability: {result['verifiability_score']:.0%}")
        print(f"  Saved to: {config.get('cases_dir', '~/watson-cases')}")
        print()

    asyncio.run(_run())


# ═══════════════════════════════════════════════════════════════════
# SETUP
# ═══════════════════════════════════════════════════════════════════


def cmd_setup(args):
    """First-time setup wizard — alias for onboard."""
    cmd_onboard()


# ═══════════════════════════════════════════════════════════════════
# CHAT
# ═══════════════════════════════════════════════════════════════════


def cmd_chat(args):
    """Open the web interface — starts server if needed, opens browser."""
    import webbrowser

    print(WATSON_BANNER)
    print(f"  {_quote()}\n")

    host = args.host or "127.0.0.1"
    port = args.port or 8777

    # Check if server already running
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    server_running = sock.connect_ex(("127.0.0.1", port)) == 0
    sock.close()

    if server_running:
        url = f"http://{host}:{port}"
        print(f"  {G}Watson is already running at {C}{url}{X}")
        print(f"  Opening in your browser now...\n")
        webbrowser.open(url)
    else:
        print(f"  {Y}No server detected on port {port}. Starting one now...{X}\n")
        # Start in background and open browser
        subprocess.Popen(
            [sys.executable, "-m", "watson.cli", "web", "--host", host, "--port", str(port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        import time
        time.sleep(2)
        url = f"http://{host}:{port}"
        print(f"  {G}Opening {C}{url}{X} in your browser...\n")
        webbrowser.open(url)


# ═══════════════════════════════════════════════════════════════════
# DOCTOR
# ═══════════════════════════════════════════════════════════════════


def cmd_doctor(args):
    """System health check — deps, config, APIs, graph, frontend."""
    print(WATSON_BANNER)
    print(f"  {_quote()}")
    print(f"\n{G}═══ Watson System Health Check ═══{X}\n")

    all_ok = True

    # ── Python ──
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 10)
    icon = f"{G}✓{X}" if py_ok else f"{R}✗{X}"
    print(f"  {icon} Python {py_ver}")
    if not py_ok:
        all_ok = False

    # ── Dependencies ──
    deps = ["fastapi", "uvicorn", "aiohttp", "httpx", "pydantic", "PIL", "jinja2"]
    for dep in deps:
        try:
            __import__(dep if dep != "PIL" else "PIL")
            print(f"  {G}✓{X} {dep}")
        except ImportError:
            print(f"  {R}✗{X} {dep} {D}(run: pip install -r requirements.txt){X}")
            all_ok = False

    # ── Config ──
    config = _load_config()
    if config:
        paid = sum(1 for v in config.get("paid_api_keys", {}).values() if v)
        print(f"  {G}✓{X} Config found — engine: {config.get('agent','?')}, {paid}/4 paid APIs")
    else:
        print(f"  {Y}○{X} No config — run {B}{sys.executable} -m watson.cli onboard{X}")
        all_ok = False

    # ── API connectivity ──
    if config:
        paid_keys = config.get("paid_api_keys", {})
        apis = {
            "OpenSanctions": paid_keys.get("opensanctions"),
            "VirusTotal": paid_keys.get("virustotal"),
            "OpenCorporates": paid_keys.get("opencorporates"),
            "HIBP": paid_keys.get("hibp"),
        }
        for name, key in apis.items():
            if key:
                print(f"  {G}✓{X} {name} key configured")
            else:
                print(f"  {D}○{X} {name} {D}(no key — free tier only){X}")

    # ── Graph server ──
    mcp_url = config.get("mcp_url", "http://localhost:8700") if config else "http://localhost:8700"
    try:
        import httpx
        r = httpx.get(f"{mcp_url}/api/stats", timeout=3)
        if r.status_code == 200:
            stats = r.json()
            print(f"  {G}✓{X} Graph server — {stats.get('entity_count', 0)} entities, {stats.get('case_count', 0)} cases")
        else:
            print(f"  {Y}○{X} Graph server returned {r.status_code}")
    except Exception:
        print(f"  {Y}○{X} Graph server not reachable at {mcp_url}")
        print(f"     {D}Start with: {sys.executable} -m watson.cli web{D} (auto-starts local graph){X}")

    # ── Frontend ──
    static_dir = Path(__file__).resolve().parent / "web" / "static"
    index_html = static_dir / "index.html"
    assets_dir = static_dir / "assets"
    if index_html.exists() and assets_dir.exists() and list(assets_dir.glob("*.js")):
        print(f"  {G}✓{X} Frontend built ({len(list(assets_dir.glob('*')))} files)")
    else:
        print(f"  {Y}○{X} Frontend not built — {D}run: cd frontend && npm run build{X}")
        all_ok = False

    # ── Bellingcat toolkit ──
    csv_path = Path(__file__).resolve().parent.parent / "data" / "bellingcat_toolkit.csv"
    if csv_path.exists():
        print(f"  {G}✓{X} Bellingcat toolkit loaded")
    else:
        print(f"  {D}○{X} Bellingcat CSV not found (toolkit search disabled){X}")

    # ── Tools count ──
    try:
        from .toolkit import DIRECT_APIS
        free_count = sum(1 for v in DIRECT_APIS.values() if not v.get("requires_key"))
        paid_count = sum(1 for v in DIRECT_APIS.values() if v.get("requires_key"))
        print(f"  {G}✓{X} {len(DIRECT_APIS)} direct APIs ({free_count} free, {paid_count} paid)")
    except Exception:
        pass

    print()
    if all_ok:
        print(f"  {G}All checks passed. Watson is ready.{X}")
        print(f"  {D}Run {B}{sys.executable} -m watson.cli web{D} to start.{X}")
    else:
        print(f"  {Y}Some checks need attention. Run {B}{sys.executable} -m watson.cli onboard{D} to fix.{X}")
    print()


# ═══════════════════════════════════════════════════════════════════
# TOOLS
# ═══════════════════════════════════════════════════════════════════


def cmd_tools(args):
    """List available OSINT APIs and tools with configuration status."""
    config = _load_config()
    paid_keys = config.get("paid_api_keys", {}) if config else {}

    print(WATSON_BANNER)
    print(f"  {_quote()}")
    print(f"\n{G}═══ Available OSINT APIs ═══{X}\n")

    try:
        from .toolkit import DIRECT_APIS
        print(f"  {B}── Direct API Integrations ({len(DIRECT_APIS)}) ──{X}\n")
        for name, cfg in sorted(DIRECT_APIS.items()):
            needs_key = cfg.get("requires_key", False)
            if needs_key:
                slug = name.lower().replace(" ", "").replace(".", "")
                # map to config slugs
                key_map = {
                    "opensanctions": "opensanctions",
                    "opencorporates": "opencorporates",
                    "virustotal": "virustotal",
                    "hibp": "hibp",
                }
                configured = bool(paid_keys.get(key_map.get(slug, slug)))
                status = f"{G}key set{X}" if configured else f"{Y}key needed{X}"
                cost = "Paid"
            else:
                status = f"{G}free — no key needed{X}"
                cost = "Free"
            print(f"  {B}{name}{X}")
            print(f"     {D}Cost: {cost}  |  Status: {status}{X}")
    except Exception as e:
        print(f"  {R}Could not load API registry: {e}{X}\n")

    # Bellingcat toolkit stats
    try:
        from .toolkit_registry import registry
        summary = registry.summary()
        print(f"\n  {B}── Bellingcat OSINT Toolkit ──{X}")
        print(f"  {D}{summary['total_tools']} tools across {len(summary['categories'])} categories{X}")
        print(f"  {D}{summary['free_tools']} free · {summary['paid_tools']} paid · {summary['partial_tools']} partially free{X}")
        print(f"  {D}{summary['url_templates']} tools have URL templates for direct querying{X}")
        print(f"\n  {D}Target types supported: {', '.join(summary['target_types'])}{X}")
    except Exception:
        print(f"\n  {D}Bellingcat toolkit not loaded (CSV not found){X}")

    print(f"\n  {D}Configure API keys with: {B}{sys.executable} -m watson.cli onboard{X}")
    print(f"  {D}Run doctor to verify: {B}{sys.executable} -m watson.cli doctor{X}\n")


# ═══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════


def main_entry():
    parser = argparse.ArgumentParser(
        prog="watson",
        description=f"Watson OSINT {VERSION} — {CODENAME}. Multi-source investigation engine.",
    )
    sub = parser.add_subparsers(dest="command", help="Command")

    # onboard
    sub.add_parser("onboard", help="First-time setup wizard")
    # setup (alias)
    sub.add_parser("setup", help="First-time setup wizard (alias for onboard)")

    # config
    p_config = sub.add_parser("config", help="Show or update configuration")
    p_config.add_argument("key", nargs="?", help="Config key to get/set (use dots for nested: paid_api_keys.opensanctions)")
    p_config.add_argument("value", nargs="?", help="New value (omit to read)")

    # web
    p_web = sub.add_parser("web", help="Start the web interface")
    p_web.add_argument("--host", help="Bind address (default: 0.0.0.0)")
    p_web.add_argument("--port", type=int, help="Port (default: 8777)")

    # investigate
    p_inv = sub.add_parser("investigate", help="Run a single investigation")
    p_inv.add_argument("query", nargs="?", help="Target: person, company, domain, email, IP, wallet")

    # graph
    p_graph = sub.add_parser("graph", help="Show knowledge graph stats and entities")

    # chat
    p_chat = sub.add_parser("chat", help="Open the web interface (starts server if needed)")
    p_chat.add_argument("--host", help="Server host (default: 127.0.0.1)")
    p_chat.add_argument("--port", type=int, help="Port (default: 8777)")

    # doctor
    sub.add_parser("doctor", help="Run system health check — deps, config, APIs, graph")

    # tools
    sub.add_parser("tools", help="List available OSINT APIs and their status")

    args = parser.parse_args()

    if args.command in ("onboard", "setup"):
        cmd_onboard()
    elif args.command == "config":
        cmd_config(args)
    elif args.command == "web":
        cmd_web(args)
    elif args.command == "investigate":
        cmd_investigate(args)
    elif args.command == "graph":
        cmd_graph(args)
    elif args.command == "chat":
        cmd_chat(args)
    elif args.command == "doctor":
        cmd_doctor(args)
    elif args.command == "tools":
        cmd_tools(args)
    else:
        print(WATSON_BANNER)
        print(f"  {_quote()}\n")
        print(f"  {G}First time? Run {B}{sys.executable} -m watson.cli setup{X}")
        print(f"  {D}Already set up? Run {B}{sys.executable} -m watson.cli chat{D} to open the interface{X}\n")
        parser.print_help()


if __name__ == "__main__":
    main_entry()
