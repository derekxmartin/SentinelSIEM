#!/usr/bin/env bash
# AkesoSIEM Development Mode
# Starts Docker services, runs ingest + query servers in background,
# and starts the React dev server with live reload.
#
# Usage: ./scripts/dev.sh
#        make dev

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

BINDIR="bin"
EXT=""
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    EXT=".exe"
fi

# ─── Start Docker services ───────────────────────────────────────────────────
echo "[dev] Starting Docker services..."
if docker compose version &>/dev/null 2>&1; then
    docker compose up -d
elif command -v docker-compose &>/dev/null; then
    docker-compose up -d
else
    echo "[dev] Docker not found, skipping. Ensure Elasticsearch is running."
fi

# ─── Wait for Elasticsearch ──────────────────────────────────────────────────
echo "[dev] Waiting for Elasticsearch..."
"$SCRIPT_DIR/wait-for-es.sh" http://localhost:9200 20 || echo "[dev] ES not ready, continuing..."

# ─── Start Go services in background ─────────────────────────────────────────
echo "[dev] Starting akeso-ingest..."
"$BINDIR/akeso-ingest${EXT}" --config akeso.toml &
INGEST_PID=$!

echo "[dev] Starting akeso-query..."
"$BINDIR/akeso-query${EXT}" --config akeso.toml &
QUERY_PID=$!

# Trap to kill background processes on exit.
trap "echo '[dev] Stopping services...'; kill $INGEST_PID $QUERY_PID 2>/dev/null; wait" EXIT

echo "[dev] Services running: ingest=$INGEST_PID query=$QUERY_PID"
echo "[dev] Starting React dev server (Ctrl+C to stop all)..."

# ─── Start React dev server (foreground) ──────────────────────────────────────
cd web && npm run dev
