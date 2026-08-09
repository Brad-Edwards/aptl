#!/bin/bash
set -euo pipefail

# =============================================================================
# TheHive API Key Provisioner
# =============================================================================
# Ensures the APTL organisation exists in TheHive, creates an org-admin user,
# and outputs its API key. Prints the key to stdout:
#
#   THEHIVE_API_KEY=$(./scripts/thehive-apikey.sh)
#
# Idempotent -- safe to re-run. Creates org/user only if missing and REUSES
# the existing API key (does not rotate it) so keys handed out earlier -- such
# as the one baked into the seeded Shuffle workflow -- keep working.
# =============================================================================

# The env-pack exposes TheHive only on the container network, where its Play
# server listens on plain HTTP :9000 (TLS termination, if any, is an edge
# concern of the env-pack, not this in-network seed path). Reach it from inside
# the container -- the same container-network transport the Cortex and Wazuh
# seed paths use, rather than a host localhost binding the env-pack no longer
# publishes. Override THEHIVE_URL for local debugging.
THEHIVE_CONTAINER="${THEHIVE_CONTAINER:-aptl-thehive}"
THEHIVE_URL="${THEHIVE_URL:-http://localhost:9000}"
ADMIN_USER="${THEHIVE_ADMIN_USER:-admin@thehive.local}"
ADMIN_PASS="${THEHIVE_ADMIN_PASS:-secret}"
ORG_NAME="APTL"
ORG_USER="aptl-svc@thehive.local"
ORG_USER_NAME="APTL Service Account"
ORG_USER_PASS="AptlService2024!"
# The session cookie jar lives inside the container so it persists across the
# separate `docker exec` invocations below (each exec is a fresh process; a host
# temp path would not be visible to curl running in the container).
COOKIE="/tmp/aptl-thehive-apikey.cookie"
trap 'docker exec "$THEHIVE_CONTAINER" rm -f "$COOKIE" 2>/dev/null || true' EXIT

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is required to reach TheHive on the container network" >&2
    exit 1
fi

_thehive_curl() {
    docker exec "$THEHIVE_CONTAINER" curl "$@" 2>/dev/null
}

_curl() {
    _thehive_curl -sf -b "$COOKIE" -H "Content-Type: application/json" "$@"
}

# 1. Login as platform admin
_thehive_curl -sf -c "$COOKIE" -X POST "${THEHIVE_URL}/api/v1/login" \
    -H "Content-Type: application/json" \
    -d "{\"user\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
    >/dev/null 2>&1 || {
    echo "ERROR: TheHive login failed at ${THEHIVE_URL}" >&2
    exit 1
}

# 2. Create APTL org if it doesn't exist
ORG_EXISTS=$(_curl "${THEHIVE_URL}/api/v1/query" \
    -d "{\"query\":[{\"_name\":\"listOrganisation\"},{\"_name\":\"filter\",\"_field\":\"name\",\"_value\":\"${ORG_NAME}\"}]}" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['_id'] if d else '')" 2>/dev/null) || ORG_EXISTS=""

if [ -z "$ORG_EXISTS" ]; then
    ORG_ID=$(_curl -X POST "${THEHIVE_URL}/api/v1/organisation" \
        -d "{\"name\":\"${ORG_NAME}\",\"description\":\"APTL Purple Team Lab\"}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['_id'])" 2>/dev/null) || {
        echo "ERROR: Failed to create org ${ORG_NAME}" >&2
        exit 1
    }
    echo "Created org ${ORG_NAME} (${ORG_ID})" >&2
else
    ORG_ID="$ORG_EXISTS"
fi

# 3. Create org-admin user if it doesn't exist
USER_EXISTS=$(_curl "${THEHIVE_URL}/api/v1/query" \
    -d "{\"query\":[{\"_name\":\"listUser\"},{\"_name\":\"filter\",\"_field\":\"login\",\"_value\":\"${ORG_USER}\"}]}" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['_id'] if d else '')" 2>/dev/null) || USER_EXISTS=""

if [ -z "$USER_EXISTS" ]; then
    USER_ID=$(_curl -X POST "${THEHIVE_URL}/api/v1/user" \
        -d "{\"login\":\"${ORG_USER}\",\"name\":\"${ORG_USER_NAME}\",\"profile\":\"org-admin\",\"organisation\":\"${ORG_NAME}\",\"password\":\"${ORG_USER_PASS}\"}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['_id'])" 2>/dev/null) || {
        echo "ERROR: Failed to create user ${ORG_USER}" >&2
        exit 1
    }
    echo "Created user ${ORG_USER} (${USER_ID})" >&2
else
    USER_ID="$USER_EXISTS"
fi

# 4. Return the org user's existing API key; renew only if none exists.
# ``key/renew`` ROTATES the key and invalidates every previously issued
# copy -- including the key baked into the seeded Shuffle workflow at boot.
# This script is re-run by the live tests and by re-seeds, so an
# unconditional renew silently breaks the Shuffle -> TheHive action with a
# 401 ("no TheHive case created"). GET returns the current key, so prefer
# it and keep the key stable across calls; renew only to bootstrap.
API_KEY=$(_curl "${THEHIVE_URL}/api/v1/user/${USER_ID}/key") || API_KEY=""
if [ -z "$API_KEY" ]; then
    API_KEY=$(_curl -X POST "${THEHIVE_URL}/api/v1/user/${USER_ID}/key/renew") || {
        echo "ERROR: Failed to provision API key for user ${USER_ID}" >&2
        exit 1
    }
fi

# 5. Output the key
echo "$API_KEY"
