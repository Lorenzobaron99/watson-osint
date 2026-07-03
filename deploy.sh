#!/bin/bash
# Watson Production Deploy Script
# Run on a fresh Ubuntu 22.04+ droplet or any Linux server.
# Assumes watson-osint is cloned to /opt/watson-osint
set -euo pipefail

APP_DIR="/opt/watson-osint"
VENV="$APP_DIR/.venv"

# ── Generate API key if not set ──
if [ -z "${MCP_API_KEY:-}" ]; then
    MCP_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    echo "🔑 Generated MCP_API_KEY: $MCP_API_KEY"
    echo "   Save this! You'll need it for Watson instances to publish to this graph."
fi

# ── Install dependencies ──
echo "📦 Installing dependencies..."
cd "$APP_DIR"
python3 -m venv "$VENV" --clear
"$VENV/bin/pip" install -q -r requirements.txt uvicorn
"$VENV/bin/pip" install -q -e .

# ── Env file ──
cat > "$APP_DIR/.env" <<EOF
# Watson Production Environment
WATSON_MCP_URL=http://localhost:8700
MCP_API_KEY=$MCP_API_KEY
PYTHONPATH=.:src
EOF
echo "✅ .env written"

# ── Systemd services ──
echo "🔧 Installing systemd units..."

sudo tee /etc/systemd/system/watson-web.service > /dev/null <<'UNIT'
[Unit]
Description=Watson Webapp
After=network.target
Wants=watson-mcp.service

[Service]
Type=simple
User=watson
WorkingDirectory=/opt/watson-osint
EnvironmentFile=/opt/watson-osint/.env
ExecStart=/opt/watson-osint/.venv/bin/uvicorn watson.web.app:app --host 0.0.0.0 --port 8777
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

sudo tee /etc/systemd/system/watson-mcp.service > /dev/null <<'UNIT'
[Unit]
Description=Watson MCP Knowledge Graph
After=network.target

[Service]
Type=simple
User=watson
WorkingDirectory=/opt/watson-osint
EnvironmentFile=/opt/watson-osint/.env
ExecStart=/opt/watson-osint/.venv/bin/uvicorn watson.mcp_server:mcp --host 0.0.0.0 --port 8700
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable watson-mcp.service watson-web.service
sudo systemctl restart watson-mcp.service watson-web.service

# ── Nginx config (optional — uncomment if using nginx) ──
if command -v nginx &>/dev/null; then
    sudo tee /etc/nginx/sites-available/watson > /dev/null <<'NGINX'
# Watson — reverse proxy with SSL
# Run: sudo certbot --nginx -d your-domain.com
server {
    listen 80;
    server_name watson-graph.example.com;  # ← CHANGE THIS

    # Watson webapp
    location / {
        proxy_pass http://127.0.0.1:8777;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;  # Investigations can take minutes
    }

    # MCP graph — public reads, auth-gated writes
    location /mcp/ {
        rewrite ^/mcp/(.*) /$1 break;
        proxy_pass http://127.0.0.1:8700;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
NGINX
    echo "⚠️  Nginx config written to /etc/nginx/sites-available/watson"
    echo "   Edit server_name, then: sudo ln -s /etc/nginx/sites-available/watson /etc/nginx/sites-enabled/"
    echo "   Then: sudo certbot --nginx -d your-domain.com && sudo systemctl reload nginx"
fi

# ── Verify ──
sleep 3
echo ""
echo "═══ Deployment Summary ═══"
curl -sf http://localhost:8777/health > /dev/null && echo "✅ Watson webapp: OK (:8777)" || echo "❌ Watson webapp: DOWN"
curl -sf http://localhost:8700/ > /dev/null && echo "✅ MCP graph:     OK (:8700)" || echo "❌ MCP graph:     DOWN"
echo ""
echo "🔑 MCP API Key: $MCP_API_KEY"
echo "   Clients set: export MCP_API_KEY=$MCP_API_KEY"
echo "   Watson instances set: export WATSON_MCP_URL=https://your-domain.com/mcp"
echo "   Hermes config: mcp_servers.watson.url = https://your-domain.com/mcp"
echo ""
echo "📊 Graph stats:"
curl -s http://localhost:8700/api/stats 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "   (MCP not responding)"
