#!/bin/bash
set -euo pipefail

# =============================================================================
# Cortex API Key Provisioner
# =============================================================================
# Ensures the APTL Cortex organisation and TheHive service account exist, then
# prints the deterministic fixture API key to stdout:
#
#   CORTEX_API_KEY=$(./scripts/cortex-apikey.sh)
#
# Idempotent on a fresh lab and after the fixture account exists. If a Cortex
# volume already contains different users and the fixture key does not
# authenticate, reset the lab volume or provision the key manually.
# =============================================================================

CORTEX_URL="${CORTEX_URL:-http://localhost:9001}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORTEX_CONTAINER="${CORTEX_CONTAINER:-aptl-cortex}"
CORTEX_ES_URL_IN_CONTAINER="${CORTEX_ES_URL_IN_CONTAINER:-http://thehive-es:9200}"
CORTEX_INDEX="${CORTEX_INDEX:-cortex_6}"
ORG_NAME="${CORTEX_ORG_NAME:-APTL}"
ORG_DESCRIPTION="${CORTEX_ORG_DESCRIPTION:-APTL Purple Team Lab}"
ORG_USER="${CORTEX_ORG_USER:-aptl-svc@cortex.local}"
ORG_USER_NAME="${CORTEX_ORG_USER_NAME:-APTL Cortex Service Account}"
ORG_USER_PASS="${CORTEX_ORG_USER_PASS:-AptlCortexService2026!}"
CORTEX_API_KEY="${CORTEX_API_KEY:-aptlcortexlabapikey2026purple}"
export ORG_NAME ORG_DESCRIPTION ORG_USER ORG_USER_NAME ORG_USER_PASS CORTEX_API_KEY

_curl_json() {
    curl -sf -H "Content-Type: application/json" "$@" 2>/dev/null
}

_curl_key() {
    curl -sf -H "Authorization: Bearer ${CORTEX_API_KEY}" "$@" 2>/dev/null
}

_ensure_cortex_index_mapping() {
    if ! command -v docker >/dev/null 2>&1; then
        return 0
    fi
    if ! docker inspect "$CORTEX_CONTAINER" >/dev/null 2>&1; then
        return 0
    fi

    docker exec -i \
        -e CORTEX_ES_URL="$CORTEX_ES_URL_IN_CONTAINER" \
        -e CORTEX_INDEX="$CORTEX_INDEX" \
        "$CORTEX_CONTAINER" sh -s < "$SCRIPT_DIR/cortex-index-init.sh"
}

# 1. Wait for the API surface that does not require Elasticsearch/auth.
max_wait=300
elapsed=0
while [ "$elapsed" -lt "$max_wait" ]; do
    if _curl_json "${CORTEX_URL}/api/status" >/dev/null; then
        break
    fi
    sleep 5
    elapsed=$((elapsed + 5))
done

if [ "$elapsed" -ge "$max_wait" ]; then
    echo "ERROR: Cortex did not become reachable at ${CORTEX_URL}" >&2
    exit 1
fi

# 2. Ensure key-auth fields are exact-match keyword mappings before the first
# org/user document creates the Cortex index.
_ensure_cortex_index_mapping

# 3. Fast path: the fixture key already works.
if _curl_key "${CORTEX_URL}/api/user/current" >/dev/null; then
    echo "$CORTEX_API_KEY"
    exit 0
fi

# 4. First-run bootstrap path. Cortex allows unauthenticated init actions only
# while the user index is empty. Creating any user closes that window.
ORG_PAYLOAD=$(python3 - <<'PY'
import json
import os

print(json.dumps({
    "name": os.environ["ORG_NAME"],
    "description": os.environ["ORG_DESCRIPTION"],
}))
PY
)

_curl_json -X POST "${CORTEX_URL}/api/organization" -d "$ORG_PAYLOAD" >/dev/null || true

USER_PAYLOAD=$(python3 - <<'PY'
import json
import os

print(json.dumps({
    "login": os.environ["ORG_USER"],
    "name": os.environ["ORG_USER_NAME"],
    "organization": os.environ["ORG_NAME"],
    "roles": ["read", "analyze", "orgadmin"],
    "password": os.environ["ORG_USER_PASS"],
    "key": os.environ["CORTEX_API_KEY"],
}))
PY
)

_curl_json -X POST "${CORTEX_URL}/api/user" -d "$USER_PAYLOAD" >/dev/null || {
    echo "ERROR: Failed to create Cortex service account. If this is an existing lab volume, reset or manually provision the fixture key." >&2
    exit 1
}

if ! _curl_key "${CORTEX_URL}/api/user/current" >/dev/null; then
    echo "ERROR: Cortex fixture key was created but did not authenticate" >&2
    exit 1
fi

echo "$CORTEX_API_KEY"
