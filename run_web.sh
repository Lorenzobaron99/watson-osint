#!/bin/bash
# Watson Web — launch the OSINT investigation dashboard
# Usage: ./run_web.sh [port]

PORT="${1:-8777}"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "  🕵️  Watson OSINT Dashboard"
echo "  ========================="
echo ""

# Use Homebrew Python which has all deps installed
PYTHON=/opt/homebrew/bin/python3

if [ ! -f "$PYTHON" ]; then
  echo "❌ Homebrew Python 3 not found at $PYTHON"
  echo "   Install it with: brew install python@3.12"
  exit 1
fi

# Quick dep check
$PYTHON -c "import flask, pydantic, click, rich, httpx, aiohttp" 2>/dev/null
if [ $? -ne 0 ]; then
  echo "📦 Installing missing Python dependencies..."
  $PYTHON -m pip install --break-system-packages -q flask flask-cors pydantic click rich httpx aiohttp
fi

echo "  Starting server on port $PORT..."
echo ""

cd "$DIR"
exec $PYTHON web/app.py
