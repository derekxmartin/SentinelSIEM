#!/usr/bin/env bash
# AkesoSIEM Demo Script
# Runs install, creates demo analyst accounts, replays fixture data through
# all source types, triggers correlation rules, and populates the dashboard.
#
# Usage: ./scripts/demo.sh
#        make demo

set -euo pipefail

# Resolve project root by looking for go.mod.
PROJECT_DIR="$(pwd)"
if [[ ! -f "$PROJECT_DIR/go.mod" ]]; then
    # Possibly invoked from scripts/ — try parent.
    if [[ -f "$PROJECT_DIR/../go.mod" ]]; then
        PROJECT_DIR="$(cd "$PROJECT_DIR/.." && pwd)"
    fi
fi
cd "$PROJECT_DIR"
SCRIPT_DIR="$PROJECT_DIR/scripts"

BINDIR="bin"
ES_HOST="${ES_HOST:-http://localhost:9200}"
INGEST_PORT="${INGEST_PORT:-8080}"
QUERY_PORT="${QUERY_PORT:-8081}"

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[ demo ]${NC} $*"; }
ok()    { echo -e "${GREEN}[  ok  ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[ warn ]${NC} $*"; }

# ─── Pre-check ────────────────────────────────────────────────────────────────
EXT=""
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]] || [[ "$(uname -s)" == MINGW* ]] || [[ -n "${WINDIR:-}" ]]; then
    EXT=".exe"
fi

CLI="$BINDIR/akeso-cli${EXT}"
if [ ! -f "$CLI" ]; then
    info "Binaries not found. Running install first..."
    "$SCRIPT_DIR/install.sh"
fi

# Extract ingest key from config.
INGEST_KEY=$(grep -oP 'api_keys\s*=\s*\["\K[^"]+' akeso.toml 2>/dev/null || echo "changeme")
INGEST_URL="http://localhost:${INGEST_PORT}"
QUERY_URL="http://localhost:${QUERY_PORT}"

# ─── Step 1: Verify services are running ──────────────────────────────────────
info "Checking services..."
STARTED_SERVICES=false
if ! curl -s "http://localhost:${INGEST_PORT}/metrics" 2>/dev/null | grep -q "akeso"; then
    info "Ingest not running, starting services..."
    "$BINDIR/akeso-ingest${EXT}" --config akeso.toml &
    INGEST_PID=$!
    disown "$INGEST_PID"
    "$BINDIR/akeso-query${EXT}" --config akeso.toml &
    QUERY_PID=$!
    disown "$QUERY_PID"
    STARTED_SERVICES=true
    sleep 3
    ok "Services started (ingest=$INGEST_PID query=$QUERY_PID)"
else
    ok "Services already running"
fi

# ─── Step 2: Create demo analyst accounts ─────────────────────────────────────
info "Creating demo analyst accounts..."

# Create admin via first-run setup (no auth required, only works when no users exist).
SETUP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${QUERY_URL}/api/v1/auth/setup" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"Admin@Demo1","display_name":"Demo Admin"}' 2>/dev/null)
if [[ "$SETUP_STATUS" == "201" ]]; then
    ok "Created admin user via first-run setup"
elif [[ "$SETUP_STATUS" == "409" ]]; then
    ok "Admin user already exists"
else
    warn "First-run setup returned HTTP $SETUP_STATUS"
fi

# Log in as admin to get a JWT for creating remaining users.
LOGIN_RESP=$(curl -s -X POST "${QUERY_URL}/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"Admin@Demo1"}' 2>/dev/null)
ADMIN_TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

if [[ -z "$ADMIN_TOKEN" ]]; then
    warn "Could not obtain admin JWT — skipping user creation"
else
    create_user() {
        local user="$1" pass="$2" display="$3" role="$4"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${QUERY_URL}/api/v1/admin/users" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer ${ADMIN_TOKEN}" \
            -d "{\"username\":\"${user}\",\"password\":\"${pass}\",\"display_name\":\"${display}\",\"role\":\"${role}\"}" 2>/dev/null)
        if [[ "$status" == "201" ]]; then
            ok "Created user: $user ($role)"
        elif [[ "$status" == "409" ]]; then
            ok "User $user already exists"
        else
            warn "Could not create $user (HTTP $status)"
        fi
    }

    create_user "sarah.chen"   "Analyst@Demo1"   "Sarah Chen"      "soc_lead"
    create_user "james.wilson" "Analyst@Demo2"    "James Wilson"    "analyst"
    create_user "maria.garcia" "Analyst@Demo3"    "Maria Garcia"    "analyst"
    create_user "alex.kumar"   "Engineer@Demo1"   "Alex Kumar"      "detection_engineer"
    create_user "viewer"       "Viewer@Demo1"     "Read Only User"  "read_only"
fi

# ─── Step 3: Replay all fixture datasets ──────────────────────────────────────
info "Replaying fixture datasets..."

replay() {
    local file="$1" label="$2"
    if [ -f "$file" ]; then
        "$CLI" --ingest-server "$INGEST_URL" --ingest-key "$INGEST_KEY" \
            ingest replay "$file" --batch-size 500 2>/dev/null
        local count
        count=$(wc -l < "$file" | tr -d ' ')
        ok "Replayed ${count} events from ${label}"
    else
        warn "Fixture not found: $file"
    fi
}

replay "tests/fixtures/akeso_edr/akeso_edr_events.ndjson"     "Akeso EDR"
replay "tests/fixtures/akeso_ndr/akeso_ndr_events.ndjson"     "Akeso NDR"
replay "tests/fixtures/winevt_json/winevt_json_events.ndjson"       "Windows Events (JSON)"
replay "tests/fixtures/winevt_xml/winevt_xml_events.ndjson"         "Windows Events (XML)"
replay "tests/fixtures/akeso_av/akeso_av_events.ndjson"       "Akeso AV"
replay "tests/fixtures/akeso_dlp/akeso_dlp_events.ndjson"     "Akeso DLP"
replay "tests/fixtures/syslog/syslog_events.ndjson"                 "Syslog"

# Also replay edge case data.
for f in tests/fixtures/edge_cases/*.ndjson; do
    if [ -f "$f" ]; then
        "$CLI" --ingest-server "$INGEST_URL" --ingest-key "$INGEST_KEY" \
            ingest replay "$f" --batch-size 100 2>/dev/null || true
    fi
done
ok "Edge case datasets replayed"

# ─── Step 4: Wait for indexing and rule evaluation ────────────────────────────
info "Waiting for indexing and rule evaluation to complete..."
sleep 5

# ─── Step 5: Verify data in Elasticsearch ────────────────────────────────────
info "Verifying data in Elasticsearch..."

# Count total events.
TOTAL_EVENTS=$(curl -s "${ES_HOST}/akeso-events-*/_count" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "?")
ok "Total events indexed: ${TOTAL_EVENTS}"

# Count alerts.
TOTAL_ALERTS=$(curl -s "${ES_HOST}/akeso-alerts-*/_count" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "?")
ok "Total alerts generated: ${TOTAL_ALERTS}"

# Count DLQ entries.
DLQ_COUNT=$(curl -s "${ES_HOST}/akeso-dlq-*/_count" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "0")
if [ "$DLQ_COUNT" != "0" ] && [ "$DLQ_COUNT" != "?" ]; then
    info "DLQ entries: ${DLQ_COUNT} (expected for edge case data)"
fi

# ─── Step 6: Create demo cases ────────────────────────────────────────────────
info "Demo data loading complete."

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  AkesoSIEM Demo Ready${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Data Summary:${NC}"
echo -e "    Events indexed:  ${TOTAL_EVENTS}"
echo -e "    Alerts fired:    ${TOTAL_ALERTS}"
echo -e "    DLQ entries:     ${DLQ_COUNT}"
echo ""
echo -e "  ${BOLD}Demo Accounts:${NC}"
echo -e "    admin / Admin@Demo1          (role: admin)"
echo -e "    sarah.chen / Analyst@Demo1   (role: soc_lead)"
echo -e "    james.wilson / Analyst@Demo2 (role: analyst)"
echo -e "    maria.garcia / Analyst@Demo3 (role: analyst)"
echo -e "    alex.kumar / Engineer@Demo1  (role: detection_engineer)"
echo -e "    viewer / Viewer@Demo1        (role: read_only)"
echo ""
echo -e "  ${BOLD}Access:${NC}"
echo -e "    Dashboard:      http://localhost:3000  (run: cd web && npm run dev)"
echo -e "    Query API:      http://localhost:${QUERY_PORT}"
echo -e "    Ingest API:     http://localhost:${INGEST_PORT}"
echo -e "    Kibana:         http://localhost:5601"
echo -e "    Prometheus:     http://localhost:${INGEST_PORT}/metrics"
echo ""
echo -e "  ${BOLD}Try:${NC}"
echo -e "    akeso-cli --server http://localhost:${QUERY_PORT} alerts"
echo -e "    akeso-cli --server http://localhost:${QUERY_PORT} query 'event.action:process_start'"
echo ""
echo -e "  ${BOLD}Teardown:${NC}"
echo -e "    make demo-clean    (disables demo users, deletes indices, stops services)"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
