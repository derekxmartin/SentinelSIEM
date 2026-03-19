#!/usr/bin/env bash
# AkesoSIEM Installation Script
# Builds all binaries, starts Docker Compose services, applies ES templates,
# creates an initial admin user, and prints credentials + dashboard URL.
#
# Usage: ./scripts/install.sh
#        make install

set -euo pipefail

PROJECT_DIR="$(pwd)"
if [[ ! -f "$PROJECT_DIR/go.mod" ]]; then
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
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-}"

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[install]${NC} $*"; }
ok()    { echo -e "${GREEN}[  ok  ]${NC} $*"; }
warn()  { echo -e "${YELLOW}[ warn ]${NC} $*"; }
fail()  { echo -e "${RED}[ fail ]${NC} $*"; exit 1; }

# ─── Step 1: Generate config if missing ───────────────────────────────────────
info "Checking configuration..."
if [ ! -f akeso.toml ]; then
    info "Generating akeso.toml from template..."
    INGEST_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || openssl rand -base64 32 | tr -d '=+/' | head -c 32)
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))" 2>/dev/null || openssl rand -base64 48 | tr -d '=+/' | head -c 48)
    MFA_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)

    sed -e "s|{{INGEST_API_KEY}}|${INGEST_KEY}|g" \
        -e "s|{{JWT_SECRET}}|${JWT_SECRET}|g" \
        -e "s|{{MFA_KEY}}|${MFA_KEY}|g" \
        akeso.toml.template > akeso.toml

    ok "Generated akeso.toml with random secrets"
    echo -e "    ${BOLD}Ingest API Key:${NC} ${INGEST_KEY}"
else
    ok "akeso.toml already exists"
    # Extract the ingest key for display later.
    INGEST_KEY=$(grep -oP 'api_keys\s*=\s*\["\K[^"]+' akeso.toml 2>/dev/null || echo "see akeso.toml")
fi

# ─── Step 1b: Create log directory ─────────────────────────────────────────────
LOG_DIR=$(grep -oP 'log_dir\s*=\s*"\K[^"]+' akeso.toml 2>/dev/null || echo "logs")
mkdir -p "$LOG_DIR"
ok "Log directory ready: ${LOG_DIR}/"

# ─── Step 2: Build all binaries ───────────────────────────────────────────────
info "Building Go binaries..."
mkdir -p "$BINDIR"

# Detect OS for binary extension.
EXT=""
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]] || [[ "$(uname -s)" == MINGW* ]] || [[ -n "${WINDIR:-}" ]]; then
    EXT=".exe"
fi

go build -o "${BINDIR}/akeso-ingest${EXT}"    ./cmd/akeso-ingest
go build -o "${BINDIR}/akeso-correlate${EXT}"  ./cmd/akeso-correlate
go build -o "${BINDIR}/akeso-query${EXT}"      ./cmd/akeso-query
go build -o "${BINDIR}/akeso-cli${EXT}"        ./cmd/akeso-cli
ok "Built 4 binaries in ${BINDIR}/"

# ─── Step 3: Build React dashboard ───────────────────────────────────────────
if [ -f web/package.json ]; then
    info "Building React dashboard..."
    if command -v npm &>/dev/null; then
        (cd web && npm install --silent 2>/dev/null && npm run build 2>/dev/null)
        ok "Dashboard built to web/dist/"
    else
        warn "npm not found, skipping dashboard build"
    fi
fi

# ─── Step 4: Start Docker Compose services ────────────────────────────────────
info "Starting Docker Compose services (Elasticsearch + Kibana)..."
if command -v docker &>/dev/null && command -v docker-compose &>/dev/null || docker compose version &>/dev/null 2>&1; then
    # Use 'docker compose' (V2) if available, fall back to 'docker-compose' (V1).
    if docker compose version &>/dev/null 2>&1; then
        COMPOSE="docker compose"
    else
        COMPOSE="docker-compose"
    fi
    $COMPOSE up -d
    ok "Docker services started"
else
    warn "Docker not found. Please start Elasticsearch manually."
fi

# ─── Step 5: Wait for Elasticsearch ──────────────────────────────────────────
info "Waiting for Elasticsearch..."
"$SCRIPT_DIR/wait-for-es.sh" "$ES_HOST" 30

# ─── Step 6: Apply ES index templates / ILM ──────────────────────────────────
info "Applying Elasticsearch index templates..."
"$BINDIR/akeso-ingest${EXT}" --config akeso.toml &
INGEST_PID=$!
sleep 3
kill "$INGEST_PID" 2>/dev/null || true
wait "$INGEST_PID" 2>/dev/null || true
ok "Index templates applied"

# ─── Step 7: Start services ──────────────────────────────────────────────────
info "Starting AkesoSIEM services..."
"$BINDIR/akeso-ingest${EXT}" --config akeso.toml &
INGEST_PID=$!
disown "$INGEST_PID"
"$BINDIR/akeso-query${EXT}" --config akeso.toml &
QUERY_PID=$!
disown "$QUERY_PID"
sleep 2

# Verify services are running.
if kill -0 "$INGEST_PID" 2>/dev/null; then
    ok "akeso-ingest running (PID ${INGEST_PID})"
else
    fail "akeso-ingest failed to start"
fi
if kill -0 "$QUERY_PID" 2>/dev/null; then
    ok "akeso-query running (PID ${QUERY_PID})"
else
    fail "akeso-query failed to start"
fi

# ─── Step 8: Create admin user ───────────────────────────────────────────────
info "Creating admin user..."
if [ -z "$ADMIN_PASS" ]; then
    ADMIN_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))" 2>/dev/null || openssl rand -base64 16 | tr -d '=+/' | head -c 16)
fi

"$BINDIR/akeso-cli${EXT}" --server "http://localhost:${QUERY_PORT}" \
    users create \
    --username "$ADMIN_USER" \
    --password "$ADMIN_PASS" \
    --display-name "Administrator" \
    --role admin 2>/dev/null && ok "Admin user created" || warn "Admin user may already exist"

# ─── Step 9: Create ingest API key via CLI ────────────────────────────────────
info "Creating CLI API key..."
CLI_KEY=$("$BINDIR/akeso-cli${EXT}" --server "http://localhost:${QUERY_PORT}" \
    keys create --name "install-cli" --scopes "ingest,query,admin" 2>/dev/null | grep -oP 'Key:\s*\K.*' || echo "")
if [ -n "$CLI_KEY" ]; then
    ok "CLI API key created"
else
    CLI_KEY="(see akeso-cli keys create)"
    warn "Could not create CLI API key (may already exist)"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  AkesoSIEM Installation Complete${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Services:${NC}"
echo -e "    Ingest API:     http://localhost:${INGEST_PORT}"
echo -e "    Query API:      http://localhost:${QUERY_PORT}"
echo -e "    Dashboard:      http://localhost:3000  (run: cd web && npm run dev)"
echo -e "    Elasticsearch:  ${ES_HOST}"
echo -e "    Kibana:         http://localhost:5601"
echo -e "    Prometheus:     http://localhost:${INGEST_PORT}/metrics"
echo ""
echo -e "  ${BOLD}Credentials:${NC}"
echo -e "    Admin user:     ${ADMIN_USER}"
echo -e "    Admin password: ${ADMIN_PASS}"
echo -e "    Ingest API key: ${INGEST_KEY}"
echo -e "    CLI API key:    ${CLI_KEY}"
echo ""
echo -e "  ${BOLD}Quick start:${NC}"
echo -e "    akeso-cli --server http://localhost:${QUERY_PORT} health"
echo -e "    akeso-cli --ingest-server http://localhost:${INGEST_PORT} --ingest-key ${INGEST_KEY} ingest test"
echo ""
echo -e "  PIDs: ingest=${INGEST_PID} query=${QUERY_PID}"
echo -e "  Stop: kill ${INGEST_PID} ${QUERY_PID}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
