---
name: watson-osint
description: "OSINT research agent deploying the Bellingcat investigation toolkit — investigate domains, people, companies, conflicts, and more in parallel."
version: 0.1.0
author: Lorenzo Baron
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [osint, investigation, bellingcat, research, journalism, open-source-intelligence]
    related_skills: []
---

# Watson — OSINT Research Agent

## Overview

Watson deploys the Bellingcat investigation toolkit across parallel investigation streams. Give it a target — domain, person, company, location, image, username — and it dispatches every relevant OSINT tool simultaneously, then cross-references the findings into a structured report.

**Built for journalists, researchers, and investigators who need answers fast.**

## When to Use

Trigger Watson when the user asks to:

- Investigate a domain: "who owns this?" "what's behind this site?"
- Research a person: "find this person online" "what's known about X?"
- Look up a company: "check this company" "any sanctions on X?"
- Verify a location: "where is this?" "what's near these coordinates?"
- Reverse search an image: "find where this image came from"
- Monitor a conflict: "what's happening in region X?"
- Cross-reference findings: "what connects X and Y?"

## How It Works

1. User provides an investigation query (natural language)
2. Watson detects intent and maps to relevant tool categories
3. All matching tools run **in parallel** — satellite, domain history, social media, corporate records, sanctions, etc.
4. Findings are cross-referenced for connections
5. A structured report is delivered to the user

## Usage from Hermes

When the user asks for an OSINT investigation, invoke Watson:

```bash
# Full investigation with auto-detected tools
watson investigate "<user query>"

# Target specific tools
watson investigate "<query>" --tools websites --tools corporate --tools people

# Save report to JSON
watson investigate "<query>" -o findings.json

# List available tools
watson tools

# Get info on a specific tool
watson tool-info websites-domains
```

## Tool Categories

| Category | What it does | Free? |
|---|---|---|
| **Satellite/Maps** | Satellite imagery, terrain, coordinate lookup | ✅ |
| **Geolocation** | Reverse geocoding, POI search, address verification | ✅ |
| **Image/Video** | Reverse image search (Google/Yandex/TinEye), verification | ✅ |
| **Social Media** | Cross-platform profile discovery (14+ platforms) | ✅ |
| **People** | Email breach check (HIBP), disposable email detection, username enumeration | ✅ |
| **Websites/Domains** | WHOIS, Wayback Machine, SSL certs (crt.sh), DNS | ✅ |
| **Corporate/Finance** | OpenCorporates, OpenSanctions (sanctions), SEC EDGAR | ✅ |
| **Conflict** | LiveUAMap, ACLED, NASA FIRMS, flight/maritime tracking | ✅ |

All tools work with free APIs — no API keys required for v0.1.

## Report Format

Watson produces a structured report with:
- Summary statistics (findings, sources, severity distribution)
- Individual findings with confidence scores
- Evidence links (URLs to source data)
- Cross-references (connections between findings from different sources)
- Tool statistics (which tools found what)

## Installation

```bash
pip install watson-osint
```

Or for development:
```bash
git clone https://github.com/Lorenzobaron99/watson-osint
cd watson-osint
pip install -e ".[dev]"
```

## Extending Watson

To add a new tool:
1. Create a new Python file in `src/watson/tools/`
2. Inherit from `OSINTTool` and implement `async investigate(query, context)`
3. Import and register it in `tools/__init__.py`
4. Submit a PR

See [CONTRIBUTING.md](https://github.com/Lorenzobaron99/watson-osint/blob/main/docs/contributing.md) for details.
