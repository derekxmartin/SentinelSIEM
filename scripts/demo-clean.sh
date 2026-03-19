#!/usr/bin/env bash
# AkesoSIEM Demo Cleanup
# Removes demo accounts, demo data indices, and stops services.
#
# Usage: ./scripts/demo-clean.sh
#        make demo-clean

set -euo pipefail

PROJECT_DIR="$(pwd)"
if [[ ! -f "$PROJECT_DIR/go.mod" ]]; then
    if [[ -f "$PROJECT_DIR/../go.mod" ]]; then
        PROJECT_DIR="$(cd "$PROJECT_DIR/.." && pwd)"
    fi
fi
cd "$PROJECT_DIR"

ES_HOST="${ES_HOST:-http://localhost:9200}"
QUERY_PORT="${QUERY_PORT:-8081}"
QUERY_URL="http://localhost:${QUERY_PORT}"

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[clean ]${NC} $*"; }
ok()    { echo -e "${GREEN}[  ok  ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[ warn ]${NC} $*"; }

EXT=""
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]] || [[ "$(uname -s)" == MINGW* ]] || [[ -n "${WINDIR:-}" ]]; then
    EXT=".exe"
fi

CLI="bin/akeso-cli${EXT}"

# ─── Step 1: Disable demo accounts ──────────────────────────────────────────
DEMO_USERS=("sarah.chen" "james.wilson" "maria.garcia" "alex.kumar" "viewer")

info "Disabling demo accounts..."
for user in "${DEMO_USERS[@]}"; do
    if [ -f "$CLI" ]; then
        "$CLI" --server "$QUERY_URL" users disable --username "$user" 2>/dev/null \
            && ok "Disabled user: $user" \
            || warn "Could not disable $user (may not exist or service not running)"
    fi
done

# ─── Step 2: Delete demo data from Elasticsearch ────────────────────────────
info "Deleting demo data and user indices..."
# Allow wildcard index deletion (disabled by default in ES 8.x).
curl -s -X PUT "${ES_HOST}/_cluster/settings" \
    -H "Content-Type: application/json" \
    -d '{"transient":{"action.destructive_requires_name":false}}' >/dev/null 2>&1
for pattern in "akeso-events-*" "akeso-alerts-*" "akeso-dlq-*" "akeso-users" "sentinel-sessions" "sentinel-api-keys"; do
    result=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${ES_HOST}/${pattern}" 2>/dev/null)
    if [[ "$result" == "200" ]]; then
        ok "Deleted indices: $pattern"
    elif [[ "$result" == "404" ]]; then
        ok "No indices matching: $pattern"
    else
        warn "Could not delete $pattern (HTTP $result)"
    fi
done

# ─── Step 3: Stop services ─────────────────────────────────────────────────
info "Stopping AkesoSIEM services..."
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]] || [[ "$(uname -s)" == MINGW* ]] || [[ -n "${WINDIR:-}" ]]; then
    taskkill //IM akeso-ingest.exe //F 2>/dev/null && ok "Stopped akeso-ingest" || warn "akeso-ingest not running"
    taskkill //IM akeso-query.exe //F 2>/dev/null && ok "Stopped akeso-query" || warn "akeso-query not running"
else
    pkill -f akeso-ingest 2>/dev/null && ok "Stopped akeso-ingest" || warn "akeso-ingest not running"
    pkill -f akeso-query 2>/dev/null && ok "Stopped akeso-query" || warn "akeso-query not running"
fi

echo ""
echo -e "${BOLD}Demo cleanup complete.${NC}"
echo -e "  To also remove Docker volumes: docker compose down -v"
