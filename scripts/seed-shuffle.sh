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
SHUFFLE_URL="${SHUFFLE_URL:-http://localhost:5001}"
SHUFFLE_API_KEY="${SHUFFLE_API_KEY:-31a211c4-ea5c-4a49-b022-5e2434e758a7}"
THEHIVE_INTERNAL_URL="http://172.20.0.18:9000"
MISP_INTERNAL_URL="https://172.20.0.16"
MISP_API_KEY="${MISP_API_KEY:-JHxBbGPnAtyut0FTwkeuhVFnbMksGRCRwsE0V9Xw}"
WORKFLOW_NAME="APTL Alert to Case"

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
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${SHUFFLE_API_KEY}" \
    "${SHUFFLE_URL}/api/v1/workflows" 2>/dev/null || echo "000")

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

WORKFLOWS_JSON=$(curl -s \
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
    echo "Workflow '${WORKFLOW_NAME}' already exists (id: ${EXISTING_ID})."
    echo "Skipping creation."
    echo ""
    echo "=== Seed Complete (no changes) ==="
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
                {"name": "verify_ssl", "value": "false"}
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
                {"name": "body", "value": "{\"title\": \"[Wazuh \$exec.rule.id] \$exec.rule.description\", \"description\": \"Wazuh Alert Details:\\n- Rule: \$exec.rule.id (\$exec.rule.description)\\n- Level: \$exec.rule.level\\n- Source IP: \$exec.data.srcip\\n- Agent: \$exec.agent.name\\n- Timestamp: \$exec.timestamp\\n\\nMISP Enrichment:\\n\$misp_ip_lookup\", \"severity\": 3}"},
                {"name": "verify_ssl", "value": "false"}
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

CREATE_RESPONSE=$(curl -s -w "\n%{http_code}" \
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
    WF_JSON=$(curl -s \
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

        curl -s -X PUT \
            -H "Authorization: Bearer ${SHUFFLE_API_KEY}" \
            -H "Content-Type: application/json" \
            -d "${UPDATED}" \
            "${SHUFFLE_URL}/api/v1/workflows/${CREATED_ID}" > /dev/null

        echo "  Start node set to trigger: ${REAL_TRIGGER_ID}"

        # Write webhook URL for Wazuh integration
        echo "http://shuffle-backend:5001/api/v1/hooks/${REAL_TRIGGER_ID}" > /tmp/aptl_shuffle_webhook_url
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
