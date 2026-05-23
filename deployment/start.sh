#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# IMMUNEX Layer 5 — Linux/macOS Startup Script
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "╔══════════════════════════════════════════════════════╗"
echo "║   IMMUNEX Autonomous SOC — Layer 5 Startup           ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Check Python version ──────────────────────────────────────────────────────
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
REQUIRED_MAJOR=3
REQUIRED_MINOR=11

PY_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -lt "$REQUIRED_MAJOR" ] || \
   ([ "$PY_MAJOR" -eq "$REQUIRED_MAJOR" ] && [ "$PY_MINOR" -lt "$REQUIRED_MINOR" ]); then
    echo "ERROR: Python $REQUIRED_MAJOR.$REQUIRED_MINOR+ required. Found: $PYTHON_VERSION"
    exit 1
fi
echo "[OK] Python $PYTHON_VERSION"

# ── Create data directories ───────────────────────────────────────────────────
mkdir -p data/logs data/models data/baseline_vectors data/memory data/drift \
         data/retrain_archive data/mutations data/reports
echo "[OK] Data directories ready"

# ── Check/install dependencies ────────────────────────────────────────────────
DEPS_OK=1
python3 -c "import fastapi" 2>/dev/null || DEPS_OK=0
python3 -c "import jwt" 2>/dev/null || DEPS_OK=0
python3 -c "import reportlab" 2>/dev/null || DEPS_OK=0

if [ "$DEPS_OK" -eq 0 ]; then
    echo "[INFO] Installing dependencies..."
    pip install --no-cache-dir \
        torch --index-url https://download.pytorch.org/whl/cpu --quiet
    pip install --no-cache-dir -r requirements.txt --quiet
    echo "[OK] Dependencies installed"
else
    echo "[OK] Dependencies already installed"
fi

# ── Parse arguments ───────────────────────────────────────────────────────────
MODE="pipeline"
if [[ "${1:-}" == "--api" ]]; then
    MODE="pipeline+api"
elif [[ "${1:-}" == "--api-only" ]]; then
    MODE="api-only"
fi

echo "[OK] Mode: $MODE"
echo ""

# ── Start IMMUNEX ─────────────────────────────────────────────────────────────
case "$MODE" in
    "pipeline+api")
        echo "[START] IMMUNEX pipeline + REST API on :8080"
        exec python3 main.py --api
        ;;
    "api-only")
        echo "[START] IMMUNEX REST API only on :8080"
        exec python3 main.py --api-only
        ;;
    *)
        echo "[START] IMMUNEX pipeline (dashboard mode)"
        exec python3 main.py
        ;;
esac
