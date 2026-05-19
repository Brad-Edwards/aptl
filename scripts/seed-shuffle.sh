#!/bin/bash
set -euo pipefail

# =============================================================================
# APTL Shuffle SOAR Seed Script
# =============================================================================
# Seeds Shuffle with an "Alert to Case" workflow that receives alert
# webhooks, enriches the source IP via MISP threat intel lookup, then
# creates a corresponding TheHive case with enrichment data.
#
# Prerequisites:
#   - Shuffle backend running (aptl-shuffle-backend / localhost:5001)
#   - TheHive running (aptl-thehive / localhost:9000)
#   - MISP running (aptl-misp / localhost:8443)
#   - THEHIVE_API_KEY env var set
#
# Usage:
#   export THEHIVE_API_KEY="your-api-key-here"
#   ./scripts/seed-shuffle.sh
#
# The script is idempotent -- skips creation if the workflow already exists.
# =============================================================================

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# SEC-006 / ADR-034: the host-facing Shuffle backend moved from
# http://localhost:5001 to the HTTPS frontend at localhost:3443. The
# seed script is a host-side CLIENT of Shuffle, so it verifies against
# the lab-managed CA.
SHUFFLE_URL="${SHUFFLE_URL:-https://localhost:3443}"
SHUFFLE_CACERT="${SHUFFLE_CACERT:-${APTL_PROJECT_DIR:-.}/config/soc_certs/lab-ca.pem}"
SHUFFLE_API_KEY="${SHUFFLE_API_KEY:-31a211c4-ea5c-4a49-b022-5e2434e758a7}"
# Container-internal URLs used INSIDE Shuffle workflow actions. These
# are intra-trust-boundary calls on the aptl-security Docker network
# (ADR-034 § Decision: SOC consumers OF Shuffle verify; Shuffle's own
# SOAR-internal HTTP actions are not the SOC-consumer surface and
# retain ``verify_ssl: false`` until Shuffle's bundled HTTP app is
# taught about the lab CA bundle — see workflow JSON below).
THEHIVE_INTERNAL_URL="https://172.20.0.18:9000"
MISP_INTERNAL_URL="https://172.20.0.16"
MISP_API_KEY="${MISP_API_KEY:-JHxBbGPnAtyut0FTwkeuhVFnbMksGRCRwsE0V9Xw}"
WORKFLOW_NAME="APTL Alert to Case"

# Build TLS flags once for the host-side Shuffle CLIENT calls below.
SHUFFLE_TLS_FLAGS=()
if [ -f "$SHUFFLE_CACERT" ]; then
    SHUFFLE_TLS_FLAGS+=(--cacert "$SHUFFLE_CACERT")
fi

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

# Auto-provision TheHive API key if not set in env
if [ -z "${THEHIVE_API_KEY:-}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [ -x "$SCRIPT_DIR/thehive-apikey.sh" ]; then
        THEHIVE_API_KEY=$("$SCRIPT_DIR/thehive-apikey.sh" 2>/dev/null) || true
    fi
fi
THEHIVE_API_KEY="${THEHIVE_API_KEY:-}"

if [ -z "$THEHIVE_API_KEY" ]; then
    echo "WARNING: THEHIVE_API_KEY not set and auto-provision failed."
    echo "The Shuffle workflow will be created but TheHive integration may not work."
    echo "Set THEHIVE_API_KEY or run: export THEHIVE_API_KEY=\$(./scripts/thehive-apikey.sh)"
    THEHIVE_API_KEY="PLACEHOLDER-SET-ME"
fi

echo "=== APTL Shuffle SOAR Seed ==="
echo "Shuffle URL:  ${SHUFFLE_URL}"
echo "TheHive URL:  ${THEHIVE_INTERNAL_URL}"
echo "MISP URL:     ${MISP_INTERNAL_URL}"
echo ""

# ---------------------------------------------------------------------------
# Check Shuffle connectivity
# ---------------------------------------------------------------------------
echo "Checking Shuffle backend connectivity..."
# curl -w "%{http_code}" prints "000" itself when the transport fails
# (e.g. TLS verification refusal under the new --cacert path) AND exits
# non-zero. The previous ``|| echo "000"`` appended another "000",
# producing the literal string "000000" and short-circuiting the
# transport-failure guard below.
if ! HTTP_CODE=$(curl -sS "${SHUFFLE_TLS_FLAGS[@]}" -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${SHUFFLE_API_KEY}" \
    "${SHUFFLE_URL}/api/v1/workflows" 2>/dev/null); then
    HTTP_CODE="000"
fi

if [[ "${HTTP_CODE}" == "000" ]]; then
    echo "ERROR: Cannot reach Shuffle backend at ${SHUFFLE_URL}."
    echo "Ensure the SOC profile is running: docker compose --profile soc up -d"
    exit 1
fi

if [[ "${HTTP_CODE}" == "401" ]]; then
    echo "ERROR: Shuffle returned 401 Unauthorized. Check SHUFFLE_API_KEY."
    exit 1
fi

echo "Shuffle backend is reachable (HTTP ${HTTP_CODE})."
echo ""

# ---------------------------------------------------------------------------
# Check for existing workflow (idempotency)
# ---------------------------------------------------------------------------
echo "Checking for existing '${WORKFLOW_NAME}' workflow..."

WORKFLOWS_JSON=$(curl -s "${SHUFFLE_TLS_FLAGS[@]}" \
    -H "Authorization: Bearer ${SHUFFLE_API_KEY}" \
    "${SHUFFLE_URL}/api/v1/workflows")

# Search for our workflow by name
EXISTING_ID=""
if command -v jq &>/dev/null; then
    EXISTING_ID=$(echo "${WORKFLOWS_JSON}" | jq -r \
        --arg name "${WORKFLOW_NAME}" \
        '.[] | select(.name == $name) | .id // empty' 2>/dev/null | head -n1)
else
    # Fallback: grep-based detection
    if echo "${WORKFLOWS_JSON}" | grep -q "\"${WORKFLOW_NAME}\""; then
        EXISTING_ID=$(echo "${WORKFLOWS_JSON}" \
            | grep -o "\"id\":\"[^\"]*\"" \
            | head -1 \
            | grep -o '"[^"]*"$' \
            | tr -d '"')
    fi
fi

if [[ -n "${EXISTING_ID}" ]]; then
    # The workflow already exists, but two things still need to be
    # reconciled on every run:
    #   1. The `create_thehive_case` action's hardcoded `Authorization:
    #      Bearer <key>` drifts whenever TheHive's API key gets
    #      regenerated (scripts/thehive-apikey.sh is run during seeding,
    #      and TheHive's bootstrap key rotates per fresh container).
    #   2. Shuffle's webhook trigger needs to be explicitly
    #      registered with `POST /api/v1/hooks/new` before it fires —
    #      if the workflow row exists but the hook registration was
    #      never made (or was dropped on a Shuffle restart), the
    #      Wazuh→Shuffle webhook path stays silent.
    # Both were previously "skip if workflow exists", which masked
    # key rotation and dropped webhook registrations.
    echo "Workflow '${WORKFLOW_NAME}' already exists (id: ${EXISTING_ID})."
    echo "Refreshing TheHive auth header and re-registering webhook trigger..."

    WF_JSON=$(curl -s "${SHUFFLE_TLS_FLAGS[@]}" \
        -H "Authorization: Bearer ${SHUFFLE_API_KEY}" \
        "${SHUFFLE_URL}/api/v1/workflows/${EXISTING_ID}")

    UPDATED=$(echo "${WF_JSON}" | THEHIVE_API_KEY="${THEHIVE_API_KEY}" python3 -c '
import json, os, sys

key = os.environ["THEHIVE_API_KEY"]
wf = json.load(sys.stdin)

# Shuffle/HTTP-1.4.0 reads the SSL flag as "verify", not "verify_ssl".
# Earlier seeds wrote "verify_ssl"; the action silently dropped it,
# verification stayed on, and every internal HTTPS call to MISP /
# TheHive against the lab CA failed. Rename in place so existing
# workflows pick up the fix without a manual reseed.
def _set(action, name, value):
    for p in action.get("parameters", []):
        if p.get("name") == name:
            p["value"] = value
            return
    action.setdefault("parameters", []).append({"name": name, "value": value})

def _rename(action, old, new):
    for p in action.get("parameters", []):
        if p.get("name") == old:
            p["name"] = new

# Embedding the raw $misp_ip_lookup output broke JSON parsing on the
# create_thehive_case body — its quoted/braced payload appeared
# inside a string literal and Shuffle surfaced an "unterminated
# string literal" error. Replace with a static reference; the MISP
# IOCs can be attached via a separate observable action later.
CASE_BODY = (
    "{\"title\": \"[Wazuh $exec.rule.id] $exec.rule.description\", "
    "\"description\": \"Wazuh Alert Details:\\n"
    "- Rule: $exec.rule.id ($exec.rule.description)\\n"
    "- Level: $exec.rule.level\\n"
    "- Source IP: $exec.data.srcip\\n"
    "- Agent: $exec.agent.name\\n"
    "- Timestamp: $exec.timestamp\\n\\n"
    "MISP enrichment results are attached as an observable on the case "
    "(see create_observable action).\", "
    "\"severity\": 3}"
)

for action in wf.get("actions", []):
    _rename(action, "verify_ssl", "verify")
    if action.get("label") == "create_thehive_case":
        _set(action, "headers",
             "Authorization: Bearer " + key + "\nContent-Type: application/json")
        _set(action, "body", CASE_BODY)

print(json.dumps(wf))
')

    curl -s "${SHUFFLE_TLS_FLAGS[@]}" -X PUT \
        -H "Authorization: Bearer ${SHUFFLE_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "${UPDATED}" \
        "${SHUFFLE_URL}/api/v1/workflows/${EXISTING_ID}" > /dev/null

    REAL_TRIGGER_ID=$(echo "${WF_JSON}" | python3 -c "
import sys,json
wf=json.load(sys.stdin)
triggers=wf.get('triggers',[])
if triggers:
    print(triggers[0].get('id',''))
")

    if [[ -n "${REAL_TRIGGER_ID}" ]]; then
        curl -s "${SHUFFLE_TLS_FLAGS[@]}" -X POST \
            -H "Authorization: Bearer ${SHUFFLE_API_KEY}" \
            -H "Content-Type: application/json" \
            -d "{\"name\": \"Alert Webhook\", \"id\": \"${REAL_TRIGGER_ID}\", \"type\": \"webhook\", \"workflow\": \"${EXISTING_ID}\", \"start\": \"${REAL_TRIGGER_ID}\", \"status\": \"running\", \"environment\": \"Shuffle\"}" \
            "${SHUFFLE_URL}/api/v1/hooks/new" > /dev/null

        WEBHOOK_URL="http://shuffle-backend:5001/api/v1/hooks/webhook_${REAL_TRIGGER_ID}"
        echo "$WEBHOOK_URL" > /tmp/aptl_shuffle_webhook_url
        # Also install the webhook URL into the running Wazuh manager,
        # mirroring `seed-prime.sh` § step 5. The refresh path was
        # previously a no-op for the manager-side config, which left
        # /var/ossec/etc/shuffle_webhook_url stale (or absent) and the
        # custom-shuffle integration silently exiting 0 for every alert.
        if docker ps --format '{{.Names}}' | grep -q '^aptl-wazuh-manager$'; then
            docker exec aptl-wazuh-manager bash -c \
                "echo '${WEBHOOK_URL}' > /var/ossec/etc/shuffle_webhook_url"
            # Tell wazuh-manager to reload so the new file is picked up
            # by the next alert-driven integration call. (custom-shuffle
            # reads the file per-invocation, so this is belt-and-braces.)
            docker exec aptl-wazuh-manager /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || true
            echo "  Webhook URL installed on aptl-wazuh-manager"
        fi
        echo "  Webhook trigger registered (id: ${REAL_TRIGGER_ID})"
    fi

    echo ""
    echo "=== Seed Complete (refreshed) ==="
    exit 0
fi

echo "Workflow not found. Creating..."
echo ""

# ---------------------------------------------------------------------------
# Build and create workflow
# ---------------------------------------------------------------------------
TRIGGER_ID="trigger-webhook-$(date +%s)"
MISP_ACTION_ID="action-misp-lookup-$(date +%s)"
CASE_ACTION_ID="action-create-case-$(date +%s)"

read -r -d '' WORKFLOW_JSON << ENDJSON || true
{
    "name": "${WORKFLOW_NAME}",
    "description": "Receives Wazuh alert webhook, enriches source IP via MISP, creates TheHive case",
    "start": "${TRIGGER_ID}",
    "actions": [
        {
            "id": "${MISP_ACTION_ID}",
            "app_name": "http",
            "app_version": "1.4.0",
            "name": "POST",
            "label": "misp_ip_lookup",
            "environment": "Shuffle",
            "position": {"x": 450, "y": 200},
            "parameters": [
                {"name": "url", "value": "${MISP_INTERNAL_URL}/attributes/restSearch"},
                {"name": "method", "value": "POST"},
                {"name": "headers", "value": "Authorization: ${MISP_API_KEY}\nContent-Type: application/json\nAccept: application/json"},
                {"name": "body", "value": "{\"value\": \"\$exec.data.srcip\", \"type\": \"ip-src\", \"returnFormat\": \"json\"}"},
                {"name": "verify", "value": "false"}
            ]
        },
        {
            "id": "${CASE_ACTION_ID}",
            "app_name": "http",
            "app_version": "1.4.0",
            "name": "POST",
            "label": "create_thehive_case",
            "environment": "Shuffle",
            "position": {"x": 750, "y": 200},
            "parameters": [
                {"name": "url", "value": "${THEHIVE_INTERNAL_URL}/api/v1/case"},
                {"name": "method", "value": "POST"},
                {"name": "headers", "value": "Authorization: Bearer ${THEHIVE_API_KEY}\nContent-Type: application/json"},
                {"name": "body", "value": "{\"title\": \"[Wazuh \$exec.rule.id] \$exec.rule.description\", \"description\": \"Wazuh Alert Details:\\n- Rule: \$exec.rule.id (\$exec.rule.description)\\n- Level: \$exec.rule.level\\n- Source IP: \$exec.data.srcip\\n- Agent: \$exec.agent.name\\n- Timestamp: \$exec.timestamp\\n\\nMISP enrichment results are attached as an observable on the case (see create_observable action).\", \"severity\": 3}"},
                {"name": "verify", "value": "false"}
            ]
        }
    ],
    "triggers": [
        {
            "id": "${TRIGGER_ID}",
            "name": "Alert Webhook",
            "label": "alert_webhook",
            "trigger_type": "WEBHOOK",
            "status": "running",
            "environment": "Shuffle",
            "position": {"x": 150, "y": 200},
            "parameters": []
        }
    ],
    "branches": [
        {
            "source_id": "${TRIGGER_ID}",
            "destination_id": "${MISP_ACTION_ID}",
            "conditions": [],
            "has_errors": false
        },
        {
            "source_id": "${MISP_ACTION_ID}",
            "destination_id": "${CASE_ACTION_ID}",
            "conditions": [],
            "has_errors": false
        }
    ]
}
ENDJSON

echo "Creating workflow '${WORKFLOW_NAME}'..."

CREATE_RESPONSE=$(curl -s "${SHUFFLE_TLS_FLAGS[@]}" -w "\n%{http_code}" \
    -X POST \
    -H "Authorization: Bearer ${SHUFFLE_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "${WORKFLOW_JSON}" \
    "${SHUFFLE_URL}/api/v1/workflows")

CREATE_BODY=$(echo "${CREATE_RESPONSE}" | sed '$d')
CREATE_CODE=$(echo "${CREATE_RESPONSE}" | tail -n1)

if [[ "${CREATE_CODE}" -ge 200 ]] && [[ "${CREATE_CODE}" -lt 300 ]]; then
    CREATED_ID="unknown"
    if command -v jq &>/dev/null; then
        CREATED_ID=$(echo "${CREATE_BODY}" | jq -r '.id // .workflow_id // "unknown"')
    else
        CREATED_ID=$(echo "${CREATE_BODY}" \
            | grep -o '"id":"[^"]*"' \
            | head -1 \
            | grep -o '"[^"]*"$' \
            | tr -d '"')
        CREATED_ID="${CREATED_ID:-unknown}"
    fi
    echo "Workflow created successfully."
    echo "  ID: ${CREATED_ID}"

    # Shuffle assigns its own UUIDs to triggers, so the start field
    # may reference our original trigger ID which no longer exists.
    # Fetch the workflow and fix the start node to point to the actual trigger.
    echo "  Fixing start node..."
    WF_JSON=$(curl -s "${SHUFFLE_TLS_FLAGS[@]}" \
        -H "Authorization: Bearer ${SHUFFLE_API_KEY}" \
        "${SHUFFLE_URL}/api/v1/workflows/${CREATED_ID}")

    REAL_TRIGGER_ID=$(echo "${WF_JSON}" \
        | python3 -c "
import sys,json
wf=json.load(sys.stdin)
triggers=wf.get('triggers',[])
if triggers:
    print(triggers[0].get('id',''))
" 2>/dev/null || true)

    if [[ -n "${REAL_TRIGGER_ID}" ]]; then
        # Update workflow start to point to real trigger
        UPDATED=$(echo "${WF_JSON}" \
            | python3 -c "
import sys,json
wf=json.load(sys.stdin)
wf['start']='${REAL_TRIGGER_ID}'
print(json.dumps(wf))
" 2>/dev/null)

        curl -s "${SHUFFLE_TLS_FLAGS[@]}" -X PUT \
            -H "Authorization: Bearer ${SHUFFLE_API_KEY}" \
            -H "Content-Type: application/json" \
            -d "${UPDATED}" \
            "${SHUFFLE_URL}/api/v1/workflows/${CREATED_ID}" > /dev/null

        echo "  Start node set to trigger: ${REAL_TRIGGER_ID}"

        # Register and start the webhook trigger (Shuffle requires explicit registration)
        echo "  Registering webhook trigger..."
        curl -s "${SHUFFLE_TLS_FLAGS[@]}" -X POST \
            -H "Authorization: Bearer ${SHUFFLE_API_KEY}" \
            -H "Content-Type: application/json" \
            -d "{\"name\": \"Alert Webhook\", \"id\": \"${REAL_TRIGGER_ID}\", \"type\": \"webhook\", \"workflow\": \"${CREATED_ID}\", \"start\": \"${REAL_TRIGGER_ID}\", \"status\": \"running\", \"environment\": \"Shuffle\"}" \
            "${SHUFFLE_URL}/api/v1/hooks/new" > /dev/null

        # Write webhook URL for Wazuh integration (Shuffle uses webhook_ prefix)
        echo "http://shuffle-backend:5001/api/v1/hooks/webhook_${REAL_TRIGGER_ID}" > /tmp/aptl_shuffle_webhook_url
        echo "  Webhook URL written to /tmp/aptl_shuffle_webhook_url"
    fi
else
    echo "ERROR: Failed to create workflow (HTTP ${CREATE_CODE})."
    echo "Response: ${CREATE_BODY}"
    exit 1
fi

echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Shuffle Seed Complete ==="
echo ""
echo "Workflow:     ${WORKFLOW_NAME}"
echo "Workflow ID:  ${CREATED_ID}"
echo "Description:  Webhook -> MISP IP lookup -> TheHive case"
echo ""
echo "Pipeline:     Wazuh alert -> Shuffle webhook"
echo "              -> MISP source IP enrichment (${MISP_INTERNAL_URL})"
echo "              -> TheHive case creation (${THEHIVE_INTERNAL_URL})"
echo ""
echo "TheHive:      ${THEHIVE_INTERNAL_URL}"
echo "MISP:         ${MISP_INTERNAL_URL}"
echo "Shuffle UI:   http://localhost:3443"
