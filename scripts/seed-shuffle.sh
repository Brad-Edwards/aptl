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
# Reruns reuse workflow identity and converge credentials, actions, and webhook.
# =============================================================================

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$PROJECT_DIR/.env"
source "$SCRIPT_DIR/aptl-env.sh"
for key in SHUFFLE_API_KEY MISP_API_KEY THEHIVE_API_KEY; do
    aptl_load_env_key "$ENV_FILE" "$key"
done

# The env-pack exposes the Shuffle frontend only on the container network (it
# serves HTTPS on :443 there; the pre-#875 host 3443 binding is gone). Reach it
# from inside the frontend container over loopback, mirroring the other SOC seed
# paths. The connection is container-internal so TLS verification is moot (-k).
SHUFFLE_CONTAINER="${SHUFFLE_CONTAINER:-aptl-shuffle-frontend}"
SHUFFLE_URL="${SHUFFLE_URL:-https://localhost:443}"
SHUFFLE_API_KEY="${SHUFFLE_API_KEY:-31a211c4-ea5c-4a49-b022-5e2434e758a7}"
# Container-internal URLs used INSIDE Shuffle workflow actions. These
# are intra-trust-boundary calls on the aptl-security Docker network
# (ADR-034 § Decision: SOC consumers OF Shuffle verify; Shuffle's own
# SOAR-internal HTTP actions are not the SOC-consumer surface and skip
# verification until Shuffle's bundled HTTP app is taught about the lab
# CA bundle. NOTE: the HTTP app parameter is ``verify`` (not
# ``verify_ssl``); the wrong name is silently ignored and the app then
# defaults to verifying, which fails against the lab CA — see below).
# Reached at runtime by Shuffle worker actions on the aptl-security network.
# Use service DNS names, not the pre-#875 static IPs the env-pack no longer
# pins. Both services use HTTPS; the generic HTTP action's explicit `verify`
# setting remains false because its worker does not receive the private lab CA.
THEHIVE_INTERNAL_URL="https://thehive:9000"
MISP_INTERNAL_URL="https://misp"
MISP_API_KEY="${MISP_API_KEY:-JHxBbGPnAtyut0FTwkeuhVFnbMksGRCRwsE0V9Xw}"
WORKFLOW_NAME="APTL Alert to Case"

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is required to reach Shuffle on the container network" >&2
    exit 1
fi


# Required integrations fail closed; a placeholder key cannot yield a usable lab.
if [ -z "${THEHIVE_API_KEY:-}" ] && [ -x "$SCRIPT_DIR/thehive-apikey.sh" ]; then
    THEHIVE_API_KEY=$("$SCRIPT_DIR/thehive-apikey.sh") || exit 1
fi
if [ -z "${THEHIVE_API_KEY:-}" ]; then
    echo "ERROR: TheHive API key could not be provisioned." >&2
    exit 1
fi
export SHUFFLE_API_KEY MISP_API_KEY THEHIVE_API_KEY
export SHUFFLE_URL

# Curl reads credentials and request bodies from stdin, never process argv.
# JSON quoting is also valid for these curl-config string values.
shuffle_api() {
    local method="$1" endpoint="$2" payload="${3:-}"
    printf '%s' "$payload" | python3 -c '
import json, os, sys
method, endpoint = sys.argv[1:]
fields = [
    ("request", method),
    ("url", os.environ["SHUFFLE_URL"] + "/api/v1/" + endpoint),
    ("header", "Authorization: Bearer " + os.environ["SHUFFLE_API_KEY"]),
    ("header", "Content-Type: application/json"),
]
body = sys.stdin.read()
if body:
    fields.append(("data", body))
for key, value in fields:
    print(key + " = " + json.dumps(value))
' "$method" "$endpoint" | docker exec -i "$SHUFFLE_CONTAINER" \
        curl -fksS --max-time 30 --config - | python3 -c '
import json, sys
try:
    response = json.load(sys.stdin)
except (ValueError, UnicodeError):
    raise SystemExit("ERROR: Invalid Shuffle API response.") from None
if isinstance(response, dict) and "success" in response and response["success"] is not True:
    raise SystemExit("ERROR: Shuffle rejected the seed operation.")
print(json.dumps(response))
'
}

require_id() {
    [[ "$1" =~ ^[a-zA-Z0-9_-]+$ ]] || {
        echo "ERROR: Shuffle returned an invalid resource identity." >&2
        return 1
    }
}

echo "=== APTL Shuffle SOAR Seed ==="
WORKFLOWS_JSON=$(shuffle_api GET workflows)
EXISTING_ID=$(printf '%s' "$WORKFLOWS_JSON" | python3 -c '
import json, sys
workflows = json.load(sys.stdin)
if not isinstance(workflows, list):
    raise SystemExit("ERROR: Invalid Shuffle workflow inventory.")
matches = [w["id"] for w in workflows if w.get("name") == "APTL Alert to Case"]
if len(matches) > 1:
    raise SystemExit("ERROR: Multiple seeded Shuffle workflows found.")
print(matches[0] if matches else "")
')
MISP_HEADERS_JSON=$(python3 -c 'import json, os; print(json.dumps("Authorization: " + os.environ["MISP_API_KEY"] + "\nContent-Type: application/json\nAccept: application/json"))')
THEHIVE_HEADERS_JSON=$(python3 -c 'import json, os; print(json.dumps("Authorization: Bearer " + os.environ["THEHIVE_API_KEY"] + "\nContent-Type: application/json"))')

TRIGGER_ID="trigger-webhook-$(date +%s)"
MISP_ACTION_ID="action-misp-lookup-$(date +%s)"
CASE_ACTION_ID="action-create-case-$(date +%s)"

# NOTE: a node's JSON `body` must be a single-line JSON object built ONLY
# from scalar interpolations (e.g. $exec.data.srcip). Two traps that both
# yield "SyntaxError - unterminated string literal" so no TheHive case is
# created even though the workflow reports FINISHED:
#   1. Embedding a whole node output (e.g. $misp_ip_lookup) -- Shuffle
#      splices the raw JSON, with its own quotes, into the surrounding
#      string and breaks it.
#   2. Any "\n" in a string value -- Shuffle unescapes it to a real newline,
#      which is illegal inside a JSON/Python string literal. Keep bodies on
#      one line and separate fields with "; ".
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
                {"name": "headers", "value": ${MISP_HEADERS_JSON}},
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
                {"name": "headers", "value": ${THEHIVE_HEADERS_JSON}},
                {"name": "body", "value": "{\"title\": \"[Wazuh \$exec.rule.id] \$exec.rule.description\", \"description\": \"Wazuh alert id \$exec.id; rule \$exec.rule.id (\$exec.rule.description); level \$exec.rule.level; source IP \$exec.data.srcip; agent \$exec.agent.name; time \$exec.timestamp; MISP: source IP \$exec.data.srcip checked against threat intelligence.\", \"severity\": 3}"},
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

if [ -n "$EXISTING_ID" ]; then
    CREATED_ID="$EXISTING_ID"
else
    CREATED=$(shuffle_api POST workflows "$WORKFLOW_JSON")
    CREATED_ID=$(printf '%s' "$CREATED" | python3 -c \
        'import json, sys; d=json.load(sys.stdin); print(d.get("id") or d.get("workflow_id") or "")')
fi
require_id "$CREATED_ID"
WF_JSON=$(shuffle_api GET "workflows/$CREATED_ID")
UPDATED=$(printf '%s' "$WF_JSON" | APTL_SEED_TEMPLATE="$WORKFLOW_JSON" python3 -c '
import json, os, sys
workflow = json.load(sys.stdin)
template = json.loads(os.environ["APTL_SEED_TEMPLATE"])
triggers = [t for t in workflow.get("triggers", []) if t.get("trigger_type") == "WEBHOOK"]
if len(triggers) != 1 or not triggers[0].get("id"):
    raise SystemExit("ERROR: Seeded workflow must have one webhook trigger.")
workflow["start"] = triggers[0]["id"]
desired = {a["label"]: a["parameters"] for a in template["actions"]}
seen = set()
for action in workflow.get("actions", []):
    label = action.get("label")
    if label not in desired:
        continue
    if label in seen:
        raise SystemExit("ERROR: Duplicate seeded workflow action.")
    seen.add(label)
    current = {p["name"]: p for p in action.get("parameters", [])}
    for parameter in desired[label]:
        current[parameter["name"]] = parameter
    current.pop("verify_ssl", None)
    action["parameters"] = list(current.values())
if seen != set(desired):
    raise SystemExit("ERROR: Required seeded workflow action is missing.")
print(json.dumps(workflow))
')
REAL_TRIGGER_ID=$(printf '%s' "$UPDATED" | python3 -c \
    'import json, sys; print(json.load(sys.stdin)["start"])')
require_id "$REAL_TRIGGER_ID"
shuffle_api PUT "workflows/$CREATED_ID" "$UPDATED" >/dev/null
HOOK_JSON=$(python3 -c '
import json, sys
workflow, trigger = sys.argv[1:]
print(json.dumps({"name": "Alert Webhook", "id": trigger, "type": "webhook",
                  "workflow": workflow, "start": trigger, "status": "running",
                  "environment": "Shuffle"}))
' "$CREATED_ID" "$REAL_TRIGGER_ID")
shuffle_api POST hooks/new "$HOOK_JSON" >/dev/null

# Publish metadata only after both the workflow and trigger are usable.
WEBHOOK_FILE="${APTL_SHUFFLE_WEBHOOK_FILE:-/tmp/aptl_shuffle_webhook_url}"
umask 077
WEBHOOK_TEMP=$(mktemp "${WEBHOOK_FILE}.XXXXXX")
trap 'rm -f "$WEBHOOK_TEMP"' EXIT
printf 'http://shuffle-backend:5001/api/v1/hooks/webhook_%s\n' "$REAL_TRIGGER_ID" > "$WEBHOOK_TEMP"
mv -f -- "$WEBHOOK_TEMP" "$WEBHOOK_FILE"
echo "=== Shuffle Seed Complete ==="
echo "Workflow ID: $CREATED_ID"
