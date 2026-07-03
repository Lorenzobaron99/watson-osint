# Contributing to Watson

Watson is an open-source OSINT investigation engine built on Bellingcat methodology. Contributions welcome.

## Getting Started

```bash
git clone https://github.com/Lorenzobaron99/watson-osint.git
cd watson-osint
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Running

```bash
# Web UI
watson web

# CLI
watson investigate "Elon Musk"

# Terminal chat
watson chat
```

## Architecture

```
src/watson/
  orchestration/    # Investigation engine, synthesis, resolution
  tools/            # OSINT tool modules (people, corporate, websites, etc.)
  agents/           # Agent adapters (Hermes, Direct LLM)
watson/
  web/              # FastAPI server + React frontend
  cli.py            # Terminal interface
frontend/           # React app (builds to watson/web/static/)
```

## Before Submitting

- TypeScript: `cd frontend && npx tsc --noEmit`
- Frontend build: `cd frontend && npm run build`
- Python imports should work from both `src/` and project root

## License

Apache 2.0. All contributions are under the same license.
