# Self-Hosting the Watson MCP Server

Run your own Watson community knowledge graph. Agents connected to your instance can query investigative findings, traverse entity connections, and contribute new cases — all via MCP.

*Last updated: July 3, 2026*

---

## Quick Start

```bash
cd ~/Desktop/watson-osint
PYTHONPATH=.:src .venv/bin/uvicorn watson.mcp_server:mcp --port 8700 --host 0.0.0.0
```

That's it. No database, no Docker, no API keys required for the graph itself.

Verify it's running:

```bash
curl http://localhost:8700/ | jq .stats
# → {"nodes": 143, "edges": 312, "cases": 8}
```

---

## Architecture

The MCP server is a standalone FastAPI app (`watson/mcp_server.py`) separate from the main Watson investigation engine. It exposes the knowledge graph as a read+write API.

```
┌─────────────────────┐        MCP / REST        ┌──────────────┐
│  Hermes Agent        │ ◄──────────────────────► │  MCP Server  │
│  (or any MCP client) │                          │  :8700       │
└─────────────────────┘                           └──────┬───────┘
                                                         │
                                                  ┌──────▼───────┐
                                                  │  JSON files   │
                                                  │  ~/watson-    │
                                                  │  graph/       │
                                                  └──────────────┘
```

**Data storage:** Everything lives in `~/watson-graph/` — JSON files for entities, edges, and case metadata. No database server required. Directory is auto-created on first upsert.

**Separation from main Watson:** The MCP server runs independently on its own port (default 8700). The main Watson webapp on `:8777` handles investigations; it calls the graph's Python module directly (same process), not via the MCP HTTP API. The MCP HTTP endpoint is for external agents.

---

## MCP Protocol Endpoints

### Tool Discovery

```
GET /.well-known/mcp
```

Returns the 5 available tools with their JSON schemas.

### Tool Invocation

```
POST /mcp/call-tool
Content-Type: application/json

{"name": "watson_search", "arguments": {"query": "example.com"}}
```

### Available Tools

| Tool | Description |
|:---|:---|
| `watson_search` | Search entities in the knowledge graph by value or type. Returns matching nodes with case provenance. |
| `watson_traverse` | Explore connections from an entity — see what other entities, cases, and relations link to it. |
| `watson_case` | Retrieve a published investigation case report (markdown). |
| `watson_stats` | Get graph statistics — node count, edge count, cases published. |
| `watson_context` | Check if an investigation target has prior findings in the graph. Returns existing entities and related cases. |

#### Tool Call Examples

**watson_search:**
```json
{
  "name": "watson_search",
  "arguments": {"query": "offshore", "limit": 10}
}
```
→ Returns matching entities with `type`, `value`, `case_ids`, confidence tier.

**watson_traverse:**
```json
{
  "name": "watson_traverse",
  "arguments": {"entity_value": "example.com", "entity_type": "domain"}
}
```
→ Returns entity node + all connected entities, edges with provenance info.

**watson_context** (check before investigating):
```json
{
  "name": "watson_context",
  "arguments": {"query": "Acme Corp"}
}
```
→ Returns `{"existing_entities": [...], "related_cases": [...]}` — use this to avoid redundant investigations.

---

## REST API

For non-MCP clients, the same endpoints are available as plain REST:

```bash
# Search
curl "http://localhost:8700/api/search?q=binance&limit=5"

# Traverse from entity
curl "http://localhost:8700/api/traverse/binance.com?entity_type=domain"

# Stats
curl "http://localhost:8700/api/stats"

# List published cases
curl "http://localhost:8700/api/cases"

# Get a specific case
curl "http://localhost:8700/api/cases/CASE-ABC12345"

# Publish a case (entities ingested into graph)
curl -X POST http://localhost:8700/api/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "case_id": "CASE-ABC12345",
    "target": "example.com",
    "target_type": "domain",
    "entities": [
      {"value": "example.com", "type": "domain", "tier": "CONFIRMED"},
      {"value": "John Doe", "type": "person", "tier": "PROBABLE"}
    ]
  }'

# List ingested (published) cases
curl "http://localhost:8700/api/published"
```

---

## Connecting Hermes Agent

Add to your Hermes config (`~/.hermes/config.yaml`):

```yaml
mcp_servers:
  watson-local:
    command: python
    args:
      - "-m"
      - "watson.mcp_server"
    env:
      PYTHONPATH: ".:src"
    workdir: /Users/you/Desktop/watson-osint
    transport: http
    url: "http://localhost:8700"
```

Or if the MCP server is already running as a standalone process (recommended for production):

```yaml
mcp_servers:
  watson-local:
    transport: http
    url: "http://localhost:8700"
```

After adding, Hermes will auto-discover the 5 Watson MCP tools on next start.

---

## Production Deployment

### systemd (Linux)

```ini
# /etc/systemd/system/watson-mcp.service
[Unit]
Description=Watson MCP Server
After=network.target

[Service]
Type=simple
User=watson
WorkingDirectory=/opt/watson-osint
Environment=PYTHONPATH=.:src
ExecStart=/opt/watson-osint/.venv/bin/uvicorn watson.mcp_server:mcp --host 0.0.0.0 --port 8700
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now watson-mcp
```

### launchd (macOS)

```xml
<!-- ~/Library/LaunchAgents/com.watson.mcp.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.watson.mcp</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/watson-osint/.venv/bin/uvicorn</string>
        <string>watson.mcp_server:mcp</string>
        <string>--host</string>
        <string>0.0.0.0</string>
        <string>--port</string>
        <string>8700</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/Users/lorenzobaron/Desktop/watson-osint</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHONPATH</key>
        <string>.:src</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

```bash
launchctl load ~/Library/LaunchAgents/com.watson.mcp.plist
```

### nginx reverse proxy (SSL + API key auth)

```nginx
server {
    listen 443 ssl;
    server_name watson-mcp.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/watson-mcp.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/watson-mcp.yourdomain.com/privkey.pem;

    location / {
        # Require an API key for write operations
        if ($request_method = POST) {
            set $auth "required";
        }
        if ($http_x_api_key = "your-secret-key") {
            set $auth "ok";
        }
        if ($auth = "required") {
            return 401;
        }

        proxy_pass http://127.0.0.1:8700;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

The MCP server itself has **no built-in authentication**. Put it behind a reverse proxy for access control. The ingest endpoint (`POST /api/ingest`) is the only write path — restrict it if exposing publicly.

---

## Data Storage & Backup

Everything lives in `~/watson-graph/`:

```
~/watson-graph/
├── entities.json     # All entity nodes (sha256 IDed)
├── edges.json        # All relationships with provenance
├── cases.json        # Case metadata index
└── index.json        # Search index
```

**Backup:**

```bash
cp -r ~/watson-graph ~/backups/watson-graph-$(date +%Y%m%d)
```

**Reset:**

```bash
rm -rf ~/watson-graph
# Directory auto-recreates on next upsert
```

---

## Per-Case Consent Flow

The main Watson investigation engine (webapp on `:8777`) supports per-case opt-in publishing:

1. User runs an investigation with the **"Publish to community graph"** checkbox enabled.
2. After the investigation completes, only `CONFIRMED` and `PROBABLE` tier findings are published.
3. Entities are upserted into the local `KnowledgeGraph` instance (same JSON files the MCP server reads).
4. `PROBABLE_CROSSREF` and `UNVERIFIED` findings are never published.

If the checkbox is off (default), nothing is published — the investigation stays private.

This is separate from the MCP server's `POST /api/ingest` endpoint, which is for external agents to publish their own findings into the same graph.

---

## Troubleshooting

**"Address already in use" on port 8700:**
```bash
lsof -ti :8700 | xargs kill
```

**MCP server returns 404 for a tool call:**
Check the request format — must be `POST /mcp/call-tool` with `{"name": "...", "arguments": {...}}`.

**Graph directory not created:**
First `upsert_entity()` call creates it. If it never happens, the directory stays empty. Run a search or stats call first — a 200 with empty results means the server is up but the graph is empty.

**Hermes doesn't discover tools:**
Ensure the MCP server is running and accessible from Hermes. Test with:
```bash
curl http://localhost:8700/.well-known/mcp | jq .tools[].name
```

**Ingest with 0 entities:**
Only `CONFIRMED` and `PROBABLE` tier entities are ingested. Check your entity tier values.

**Watson webapp not publishing to graph:**
The webapp publishes directly to the local graph module (same Python process), not via the MCP HTTP API. Ensure the investigation had the `publish_to_graph` checkbox enabled and produced at least one CONFIRMED or PROBABLE finding.
