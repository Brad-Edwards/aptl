#!/bin/bash
set -euo pipefail

# =============================================================================
# TheHive API Key Provisioner
# =============================================================================
# Ensures the APTL organisation + org-admin user exist in TheHive, then
# returns a STABLE API key by caching the issued key under
# `.aptl/thehive-apikey`. Subsequent calls return the cached key if it
# still authenticates; only on cache miss or auth failure does the
# script call `/key/renew` (which rotates and invalidates the prior
# key). Without caching, every caller invalidated the previous
# caller's key — helpers.py would get key A, the seed script would
# get key B and stamp B into the Shuffle workflow, then the integration
# test would call back with A and TheHive would reject it.
#
# Usage:
#   THEHIVE_API_KEY=$(./scripts/thehive-apikey.sh)
#
# Override the cache location with THEHIVE_APIKEY_CACHE (defaults to
# `.aptl/thehive-apikey` under the project root). Delete the cache file
# to force a rotation.
# =============================================================================

# SEC-006 / ADR-034: TheHive now serves HTTPS on 9000 using the
# lab-managed CA. Seed paths verify against the CA bundle that
# `aptl lab start` materializes under `config/soc_certs/lab-ca.pem`.
# Override via THEHIVE_URL / THEHIVE_CACERT for local debugging.
THEHIVE_URL="${THEHIVE_URL:-https://localhost:9000}"
THEHIVE_CACERT="${THEHIVE_CACERT:-${APTL_PROJECT_DIR:-.}/config/soc_certs/lab-ca.pem}"
ADMIN_USER="${THEHIVE_ADMIN_USER:-admin@thehive.local}"
ADMIN_PASS="${THEHIVE_ADMIN_PASS:-secret}"
ORG_NAME="APTL"
ORG_USER="aptl-svc@thehive.local"
ORG_USER_NAME="APTL Service Account"
ORG_USER_PASS="AptlService2024!"
PROJECT_DIR="${APTL_PROJECT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
THEHIVE_APIKEY_CACHE="${THEHIVE_APIKEY_CACHE:-${PROJECT_DIR}/.aptl/thehive-apikey}"
COOKIE=$(mktemp)
trap 'rm -f "$COOKIE"' EXIT

# Build the CA-verification flag once; if the bundle file is missing
# we fall back to system trust (still verify), never to ``-k``.
TLS_FLAGS=()
if [ -f "$THEHIVE_CACERT" ]; then
    TLS_FLAGS+=(--cacert "$THEHIVE_CACERT")
fi

_curl() {
    curl -sf "${TLS_FLAGS[@]}" -b "$COOKIE" -H "Content-Type: application/json" "$@" 2>/dev/null
}

# Verify a candidate key against the current-user endpoint. Returns 0 (true)
# on 200, non-zero otherwise.
_key_works() {
    local key="$1"
    curl -sf "${TLS_FLAGS[@]}" \
        -H "Authorization: Bearer ${key}" \
        "${THEHIVE_URL}/api/v1/user/current" \
        >/dev/null 2>&1
}

# Try the cached key first — if it still authenticates, just print it
# and exit without touching TheHive's renewal endpoint. The cache file
# lives under .aptl/ which is gitignored.
if [ -f "$THEHIVE_APIKEY_CACHE" ]; then
    CACHED_KEY=$(<"$THEHIVE_APIKEY_CACHE")
    if [ -n "$CACHED_KEY" ] && _key_works "$CACHED_KEY"; then
        echo "$CACHED_KEY"
        exit 0
    fi
fi

# 1. Login as platform admin
curl -sf "${TLS_FLAGS[@]}" -c "$COOKIE" -X POST "${THEHIVE_URL}/api/v1/login" \
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

# 4. Renew API key for the org user (only reached when the cached key
#    was missing or no longer authenticates — see the cache check above).
API_KEY=$(_curl -X POST "${THEHIVE_URL}/api/v1/user/${USER_ID}/key/renew") || {
    echo "ERROR: Failed to renew API key for user ${USER_ID}" >&2
    exit 1
}

# 5. Cache and emit the key.
mkdir -p "$(dirname "$THEHIVE_APIKEY_CACHE")"
umask 077
printf '%s' "$API_KEY" > "$THEHIVE_APIKEY_CACHE"
echo "$API_KEY"
