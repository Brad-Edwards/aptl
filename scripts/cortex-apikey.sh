#!/bin/bash
set -euo pipefail

# =============================================================================
# Cortex API Key Provisioner
# =============================================================================
# Ensures the TechVault Cortex initializer, least-privilege TheHive connector,
# and declared analyzer exist, then prints the realized connector key to stdout:
#
#   CORTEX_API_KEY=$(./scripts/cortex-apikey.sh)
#
# Idempotent on a fresh lab and after the realized accounts exist. If a Cortex
# volume already contains incompatible users, reset the lab volume rather than
# changing an existing identity in place.
# =============================================================================

# Drive initialization inside the Cortex container rather than depending on a
# particular backend publication. APTL currently selects a loopback publication
# under the pack's open scope for native evidence, but the seed operation itself
# remains valid for another admitted backend that exposes no host port.
CORTEX_CONTAINER="${CORTEX_CONTAINER:-aptl-cortex}"
CORTEX_URL="${CORTEX_URL:-http://localhost:9001}"
ORG_NAME="${CORTEX_ORG_NAME:-APTL}"
ORG_DESCRIPTION="${CORTEX_ORG_DESCRIPTION:-APTL Purple Team Lab}"
CORTEX_ADMIN_USER="techvault-admin@cortex.local"
CORTEX_CONNECTOR_USER="thehive@cortex.local"
CORTEX_INITIALIZER_KEY_FILE="${CORTEX_INITIALIZER_KEY_FILE:-.aptl/realization/cortex-service-credentials/cortex/initializer-api-key}"
CORTEX_CONNECTOR_KEY_FILE="${CORTEX_CONNECTOR_KEY_FILE:-.aptl/realization/cortex-service-credentials/cortex/connector-api-key}"
if [ -r "$CORTEX_INITIALIZER_KEY_FILE" ]; then
    IFS= read -r CORTEX_ADMIN_KEY < "$CORTEX_INITIALIZER_KEY_FILE"
else
    CORTEX_ADMIN_KEY="${CORTEX_ADMIN_KEY:-aptlcortexinitializerapikey2026}"
fi
if [ -r "$CORTEX_CONNECTOR_KEY_FILE" ]; then
    IFS= read -r CORTEX_API_KEY < "$CORTEX_CONNECTOR_KEY_FILE"
else
    CORTEX_API_KEY="${CORTEX_API_KEY:-aptlcortexlabapikey2026purple}"
fi
ANALYZER_DEFINITION_ID="TechVaultScenarioContext_1_0"
ANALYZER_NAME="TechVaultScenarioContext"
export ORG_NAME ORG_DESCRIPTION CORTEX_ADMIN_USER CORTEX_CONNECTOR_USER
export CORTEX_ADMIN_KEY CORTEX_API_KEY

# Reach the Cortex API from inside its container. This mirrors the SOC seed's
# Wazuh path, which also drives its client through `docker exec` rather than a
# host binding.
_cortex_curl() {
    docker exec "$CORTEX_CONTAINER" curl "$@" 2>/dev/null
}

_curl_json() {
    _cortex_curl -sf -H "Content-Type: application/json" "$@"
}

_curl_key() {
    _cortex_curl -sf -H "Authorization: Bearer ${CORTEX_API_KEY}" "$@"
}

_curl_admin() {
    _cortex_curl -sf -H "Authorization: Bearer ${CORTEX_ADMIN_KEY}" "$@"
}

_ensure_database_migrated() {
    # Cortex owns its native Elasticsearch schema. Its supported first-run
    # migration endpoint must initialize that schema before any organization or
    # user is written; otherwise Elasticsearch auto-creates an incompatible
    # dynamic mapping and API-key authentication can never match status="Ok".
    if ! _curl_json -X POST "${CORTEX_URL}/api/maintenance/migrate" \
        -d '{}' >/dev/null; then
        echo "ERROR: Cortex database migration could not be started" >&2
        return 1
    fi
    for _ in $(seq 1 60); do
        if _cortex_curl -sf "${CORTEX_URL}/api/user" >/dev/null; then
            return 0
        fi
        sleep 2
    done
    echo "ERROR: Cortex database migration did not become ready" >&2
    return 1
}

_analyzer_is_enabled() {
    local catalog
    if ! catalog=$(_curl_key "${CORTEX_URL}/api/analyzer"); then
        echo "ERROR: Cortex analyzer catalog could not be queried" >&2
        return 1
    fi
    if ! printf '%s' "$catalog" \
        | grep -Eq '"analyzerDefinitionId"[[:space:]]*:[[:space:]]*"'"${ANALYZER_DEFINITION_ID}"'"'; then
        return 1
    fi
}

_ensure_analyzer_enabled() {
    local definitions="" payload
    if _analyzer_is_enabled; then
        return 0
    fi
    if ! _curl_admin -X POST \
        "${CORTEX_URL}/api/analyzerdefinition/scan" >/dev/null; then
        echo "ERROR: Cortex analyzer catalog scan failed" >&2
        return 1
    fi
    for _ in $(seq 1 30); do
        if definitions=$(_curl_admin "${CORTEX_URL}/api/analyzerdefinition") \
            && printf '%s' "$definitions" \
                | grep -Eq '"id"[[:space:]]*:[[:space:]]*"'"${ANALYZER_DEFINITION_ID}"'"'; then
            break
        fi
        definitions=""
        sleep 1
    done
    if [ -z "$definitions" ]; then
        echo "ERROR: Cortex ${ANALYZER_NAME} definition is not available" >&2
        return 1
    fi
    payload='{"name":"TechVaultScenarioContext","configuration":{}}'
    if ! _curl_admin -H "Content-Type: application/json" -X POST \
        "${CORTEX_URL}/api/organization/analyzer/${ANALYZER_DEFINITION_ID}" \
        -d "$payload" >/dev/null; then
        echo "ERROR: Cortex ${ANALYZER_NAME} could not be enabled" >&2
        return 1
    fi
    if ! _analyzer_is_enabled; then
        echo "ERROR: Cortex ${ANALYZER_NAME} was enabled but is not queryable" >&2
        return 1
    fi
}

_connector_is_exact() {
    local current
    if ! current=$(_curl_key "${CORTEX_URL}/api/user/current"); then
        return 1
    fi
    python3 -c '
import json
import sys

user = json.load(sys.stdin)
valid = (
    user.get("_id") == "thehive@cortex.local"
    and sorted(user.get("roles", [])) == ["analyze", "read"]
)
raise SystemExit(0 if valid else 1)
' <<<"$current"
}

_ensure_connector() {
    local payload
    if _connector_is_exact; then
        return 0
    fi
    if _curl_key "${CORTEX_URL}/api/user/current" >/dev/null; then
        echo "ERROR: Cortex connector identity has unexpected ownership or roles" >&2
        return 1
    fi
    if _curl_admin "${CORTEX_URL}/api/user/thehive%40cortex.local" >/dev/null; then
        echo "ERROR: Cortex connector identity exists with another key" >&2
        return 1
    fi
    payload=$(python3 - <<'PY'
import json
import os

print(json.dumps({
    "login": os.environ["CORTEX_CONNECTOR_USER"],
    "name": "TechVault TheHive Connector",
    "organization": os.environ["ORG_NAME"],
    "roles": ["read", "analyze"],
    "key": os.environ["CORTEX_API_KEY"],
}))
PY
)
    if ! _curl_admin -H "Content-Type: application/json" -X POST \
        "${CORTEX_URL}/api/user" -d "$payload" >/dev/null; then
        echo "ERROR: Failed to create Cortex connector identity" >&2
        return 1
    fi
    if ! _connector_is_exact; then
        echo "ERROR: Cortex connector identity was created but is not exact" >&2
        return 1
    fi
}

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is required to reach Cortex on the container network" >&2
    exit 1
fi
if [ -z "$CORTEX_ADMIN_KEY" ] || [ -z "$CORTEX_API_KEY" ] \
    || [ "$CORTEX_ADMIN_KEY" = "$CORTEX_API_KEY" ]; then
    echo "ERROR: Cortex initializer and connector keys must be present and distinct" >&2
    exit 1
fi

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

# 2. Fast path: both realized identities already work.
if _curl_admin "${CORTEX_URL}/api/user/current" >/dev/null; then
    _ensure_connector || exit 1
    _ensure_analyzer_enabled || exit 1
    echo "$CORTEX_API_KEY"
    exit 0
fi
if _curl_key "${CORTEX_URL}/api/user/current" >/dev/null; then
    echo "ERROR: Cortex has the connector identity but not its initializer" >&2
    exit 1
fi

# 3. First-run bootstrap path. Cortex owns its native index mapping, and allows
# unauthenticated migration/init actions only while the user index is empty.
# Migration must precede the first write so Elasticsearch cannot auto-create a
# dynamically mapped index. Creating any user closes the init window.
_ensure_database_migrated || exit 1

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

ADMIN_PAYLOAD=$(python3 - <<'PY'
import json
import os

print(json.dumps({
    "login": os.environ["CORTEX_ADMIN_USER"],
    "name": "TechVault Cortex Initializer",
    "organization": os.environ["ORG_NAME"],
    "roles": ["read", "analyze", "orgadmin"],
    "key": os.environ["CORTEX_ADMIN_KEY"],
}))
PY
)

_curl_json -X POST "${CORTEX_URL}/api/user" -d "$ADMIN_PAYLOAD" >/dev/null || {
    echo "ERROR: Failed to create Cortex initializer identity" >&2
    exit 1
}

if ! _curl_admin "${CORTEX_URL}/api/user/current" >/dev/null; then
    echo "ERROR: Cortex initializer identity was created but did not authenticate" >&2
    exit 1
fi

_ensure_connector || exit 1
_ensure_analyzer_enabled || exit 1

echo "$CORTEX_API_KEY"
