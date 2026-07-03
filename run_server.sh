#!/bin/bash
# Watson — FastAPI server launcher (Phase 1)
# Replaces the old Flask dev server with uvicorn + FastAPI.
# Auto-reload on code changes. Browser scraping disabled for memory stability.
cd /Users/lorenzobaron/Desktop/watson-osint

while true; do
    echo "[watson] Starting FastAPI server $(date)"
    WATSON_NO_BROWSER=1 PYTHONPATH=.:src .venv/bin/uvicorn watson.web.app:app \
        --host 0.0.0.0 --port 8777 --reload --log-level warning 2>&1
    EXIT_CODE=$?
    echo "[watson] Server exited with code $EXIT_CODE at $(date)"
    sleep 2
    lsof -ti:8777 | xargs kill -9 2>/dev/null
    sleep 1
done
