#!/bin/bash
# ─────────────────────────────────────────────────────────────────
# SecureCloud IDE — Start Script
# Run this from the secure-cloud-ide/ folder:
#   bash start.sh
# ─────────────────────────────────────────────────────────────────

set -e

# Get the directory this script lives in
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "  🔒 SecureCloud IDE"
echo "  ─────────────────────────────────────────"

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo "  ✅ Virtual environment activated"
else
    echo "  ⚠️  venv not found — creating it now..."
    python3 -m venv venv
    source venv/bin/activate
    pip install fastapi uvicorn pydantic pydantic-settings httpx pytest aiofiles python-dotenv python-multipart
    echo "  ✅ Dependencies installed"
fi

echo "  🌐 Starting server..."
echo "  ─────────────────────────────────────────"
echo "  Open your browser → http://localhost:8000"
echo "  API docs          → http://localhost:8000/docs"
echo "  Press Ctrl+C to stop"
echo "  ─────────────────────────────────────────"
echo ""

# Start FastAPI with auto-reload
python3 -m uvicorn backend.main:app --reload --port 8000 --host 0.0.0.0
