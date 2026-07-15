#!/bin/bash
set -euo pipefail

# =============================================================================
# TheHive API Key Provisioner
# =============================================================================
# Ensures the APTL organisation exists in TheHive, creates an org-admin user,
# and outputs a working API key. An existing generated key is reused while it
# remains valid so downstream integrations are not invalidated by a rerun.
# Prints the key to stdout:
#
#   THEHIVE_API_KEY=$(./scripts/thehive-apikey.sh)
#
# Idempotent -- safe to re-run. Creates org/user only if missing.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/aptl-env.sh"
aptl_load_env_key "$PROJECT_DIR/.env" THEHIVE_API_KEY

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
COOKIE=$(mktemp)
trap 'rm -f "$COOKIE"' EXIT

# Build the CA-verification flag once; if the bundle file is missing
# we fall back to system trust (still verify), never to ``-k``.
TLS_FLAGS=()
if [ -f "$THEHIVE_CACERT" ]; then
    TLS_FLAGS+=(--cacert "$THEHIVE_CACERT")
fi

# Renewing a TheHive key immediately revokes the previous one. Reuse the
# project key when TheHive accepts it so an idempotent seed rerun cannot leave
# an already-created Shuffle workflow holding a revoked credential. A stale
# key left by `lab stop -v` fails this probe and falls through to renewal.
if [[ -n "${THEHIVE_API_KEY:-}" && ! "${THEHIVE_API_KEY}" =~ [[:space:]] ]] && \
    curl -sf "${TLS_FLAGS[@]}" -X POST "${THEHIVE_URL}/api/v1/query" \
        -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
        -H "Content-Type: application/json" \
        -d '{"query":[{"_name":"listCase"},{"_name":"page","from":0,"to":1}]}' \
        >/dev/null 2>&1; then
    echo "$THEHIVE_API_KEY"
    exit 0
fi

_curl() {
    curl -sf "${TLS_FLAGS[@]}" -b "$COOKIE" -H "Content-Type: application/json" "$@" 2>/dev/null
}

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

# 4. Renew API key for the org user
API_KEY=$(_curl -X POST "${THEHIVE_URL}/api/v1/user/${USER_ID}/key/renew") || {
    echo "ERROR: Failed to renew API key for user ${USER_ID}" >&2
    exit 1
}

# 5. Output the key
echo "$API_KEY"
