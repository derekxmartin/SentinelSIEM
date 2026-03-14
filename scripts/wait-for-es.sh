#!/usr/bin/env bash
# Wait for Elasticsearch to become healthy before proceeding.
# Usage: ./scripts/wait-for-es.sh [host] [max_retries]

set -euo pipefail

ES_HOST="${1:-http://localhost:9200}"
MAX_RETRIES="${2:-30}"
RETRY_INTERVAL=5

echo "Waiting for Elasticsearch at ${ES_HOST}..."

for i in $(seq 1 "$MAX_RETRIES"); do
    if curl -s "${ES_HOST}/_cluster/health" | grep -qE '"status":"(green|yellow)"'; then
        echo "Elasticsearch is healthy."
        curl -s "${ES_HOST}/_cluster/health" | python3 -m json.tool 2>/dev/null || curl -s "${ES_HOST}/_cluster/health"
        exit 0
    fi
    echo "  Attempt ${i}/${MAX_RETRIES} — not ready yet, retrying in ${RETRY_INTERVAL}s..."
    sleep "$RETRY_INTERVAL"
done

echo "ERROR: Elasticsearch did not become healthy after ${MAX_RETRIES} attempts."
exit 1
