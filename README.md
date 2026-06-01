# 🔍 Watson — OSINT Research Agent

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**Deploy the Bellingcat investigation toolkit. Investigate anything, everywhere, in parallel.**

Watson is an open-source OSINT research agent that decomposes investigation queries, dispatches them across 8+ tool categories simultaneously, cross-references findings, and produces structured reports — all from the command line.

```bash
$ watson investigate "who owns shady-domain.com and what else do they control?"

🔍 WATSON INVESTIGATION REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📚 Wayback Machine: shady-domain.com
  First archived: Mar 15, 2022. Latest snapshot: May 28, 2026.

🔒 SSL certs: 17 subdomains found for shady-domain.com
  Discovered via certificate transparency logs.

🏢 Company records: 3 matches
  - ACME Holdings Ltd (UK, #12345678)
  - ACME Services Inc (US, #87654321)

🚨 Sanctions check: 1 match for 'ACME Holdings'
  - ACME Holdings Ltd [Company] (Russia)

🔗 Link: shady-domain.com ↔ ACME Holdings Ltd
  Findings from websites and corporate share common elements: acme, holdings
```

## Why Watson?

Most OSINT tools do one thing. Watson does everything — at once.

- **Parallel dispatch**: All 8 tool categories run concurrently, not sequentially
- **Bellingcat toolkit**: Satellite imagery, geolocation, reverse image search, domain history, corporate records, sanctions, social media — every tool in the investigative arsenal
- **Zero configuration**: `pip install` → `watson investigate` — that's it. All tools use free/public APIs
- **Cross-referencing**: Watson doesn't just collect data — it finds connections between findings from different sources
- **Plugin architecture**: Adding a new tool is one Python class. Community contributions welcome
- **Structured output**: Markdown reports, JSON export, confidence scores, evidence links

## Quick Start

```bash
pip install watson-osint
watson investigate "your investigation query here"
```

### Examples

```bash
# Investigate a suspicious domain
watson investigate "who owns paypa1-secure-login.com?"

# Research a company and its owners
watson investigate "acme corporation directors and subsidiaries"

# Find a person across social media
watson investigate "@john_doe social media presence"

# Geolocate from coordinates
watson investigate "48.8566, 2.3522" --tools satellite geolocation

# Check an email for breaches
watson investigate "user@example.com" --tools people

# Monitor a conflict zone
watson investigate "recent incidents in khartoum"

# Save report to JSON
watson investigate "company name ltd" -o report.json
```

## Tool Categories

| Category | Capabilities | APIs Used |
|---|---|---|
| 🛰 **Satellite/Maps** | Satellite imagery, terrain, coordinate lookup | OpenStreetMap Nominatim, Google Earth |
| 📍 **Geolocation** | Reverse geocoding, POI search, address verification | Nominatim, Overpass API |
| 🖼 **Image/Video** | Reverse image search, verification | Google Lens, Yandex, TinEye |
| 👤 **Social Media** | Cross-platform profile discovery (14+ platforms) | Direct HTTP checks |
| 🔍 **People** | Email breach check, disposable detection, username enumeration | Have I Been Pwned, MailCheck.ai |
| 🌐 **Websites/Domains** | WHOIS, Wayback history, SSL certs, DNS records | Internet Archive CDX, crt.sh, Google DNS |
| 🏢 **Corporate/Finance** | Company records, sanctions, SEC filings | OpenCorporates, OpenSanctions, SEC EDGAR |
| ⚔️ **Conflict** | Live conflict maps, incident data, resource aggregation | LiveUAMap, ACLED, NASA FIRMS |

**All tools work with free/public APIs.** No API keys required.

## Architecture

```
User Query
    │
    ▼
┌──────────────────────────────┐
│       Intent Detection       │  ← Maps query to tool categories
└──────────────────────────────┘
    │
    ▼
┌──────────────────────────────┐
│    Parallel Dispatcher       │  ← Runs all relevant tools concurrently
│  ┌─────┐ ┌─────┐ ┌─────┐   │
│  │🌐   │ │👤   │ │🏢   │   │
│  │Web  │ │Peop │ │Corp │···│
│  └─────┘ └─────┘ └─────┘   │
└──────────────────────────────┘
    │
    ▼
┌──────────────────────────────┐
│     Findings Collection      │  ← Gathers results from all tools
└──────────────────────────────┘
    │
    ▼
┌──────────────────────────────┐
│     Cross-Referencing        │  ← Finds connections between sources
└──────────────────────────────┘
    │
    ▼
┌──────────────────────────────┐
│       Report Generation      │  ← Structured markdown/JSON output
└──────────────────────────────┘
```

## CLI Commands

```bash
# Main investigation command
watson investigate QUERY [--tools TOOL...] [--output FILE.json]

# List all available tools
watson tools

# Get detailed info about a specific tool
watson tool-info websites-domains

# Version
watson --version
```

## Installing for Development

```bash
git clone https://github.com/Lorenzobaron99/watson-osint.git
cd watson-osint
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/
```

## Adding a New Tool

Watson is built for community contributions. Adding a new investigation tool takes 3 steps:

1. **Create the tool class** — inherit from `OSINTTool`:

```python
# src/watson/tools/my_tool.py
from .base import OSINTTool
from .registry import registry
from ..core.models import Finding, FindingSource

class MyTool(OSINTTool):
    category = FindingSource.WEBSITES  # or add a new category
    name = "my-new-tool"
    description = "What my tool investigates"

    async def investigate(self, query: str, context: str = "") -> list[Finding]:
        # Your investigation logic here
        return [
            self._make_finding(
                title="Finding title",
                description="What was found",
                evidence=["https://source.url"],
                confidence=0.85,
            )
        ]

# Register
my_tool = MyTool()
registry.register(my_tool)
```

2. **Register it** — add `from . import my_tool` to `src/watson/tools/__init__.py`

3. **Submit a PR!** See [CONTRIBUTING.md](docs/contributing.md)

## Roadmap

- [ ] WHOIS integration (python-whois for parsed output)
- [ ] Full EXIF extraction for uploaded images
- [ ] LLM-powered finding synthesis and narrative generation
- [ ] Web UI dashboard for visual investigation
- [ ] API server mode for integration with other tools
- [ ] More tool categories: flight tracking, maritime, cryptocurrency, dark web
- [ ] Community tool marketplace

## License

MIT © Lorenzo Baron

---

*"How often have I said to you that when you have eliminated the impossible, whatever remains, however improbable, must be the truth?" — Sherlock Holmes*
