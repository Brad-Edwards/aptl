#!/bin/bash
set -euo pipefail

# =============================================================================
# APTL MISP Seed Script
# =============================================================================
# Seeds MISP with lab-specific threat intelligence data for integration tests
# and attack scenarios. Creates an "APTL Lab - Known Threat Actors" event
# populated with IOCs matching the lab network: Kali red-team IPs, common
# injection patterns, and lab-specific indicators.
#
# Prerequisites:
#   - MISP container running (aptl-misp on 172.20.0.16 / localhost:8443)
#
# Usage:
#   ./scripts/seed-misp.sh
#
# Uses ADMIN_KEY from docker-compose.yml by default. Override with:
#   MISP_API_KEY="custom-key" ./scripts/seed-misp.sh
#
# The script is idempotent -- re-running it will skip event creation if the
# "APTL Lab" event already exists.
# =============================================================================

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MISP_URL="${MISP_URL:-https://localhost:8443}"
EVENT_INFO="APTL Lab - Known Threat Actors"

CURL_OPTS=(-ks --max-time 30)

# ---------------------------------------------------------------------------
# Preflight checks — default to ADMIN_KEY from docker-compose.yml
# ---------------------------------------------------------------------------
MISP_API_KEY="${MISP_API_KEY:-JHxBbGPnAtyut0FTwkeuhVFnbMksGRCRwsE0V9Xw}"

echo "=== APTL MISP Seed Script ==="
echo "MISP URL: ${MISP_URL}"
echo ""

# ---------------------------------------------------------------------------
# Helper: make an authenticated MISP API call
# ---------------------------------------------------------------------------
misp_api() {
    local method="$1"
    local endpoint="$2"
    local data="${3:-}"

    local args=("${CURL_OPTS[@]}" -X "${method}"
        -H "Authorization: ${MISP_API_KEY}"
        -H "Accept: application/json"
        -H "Content-Type: application/json"
    )

    if [[ -n "${data}" ]]; then
        args+=(-d "${data}")
    fi

    curl "${args[@]}" "${MISP_URL}${endpoint}"
}

# ---------------------------------------------------------------------------
# Step 1: Check if the event already exists
# ---------------------------------------------------------------------------
echo "Checking if '${EVENT_INFO}' event already exists..."

SEARCH_RESULT=$(misp_api POST /events/restSearch \
    "{\"returnFormat\":\"json\",\"eventinfo\":\"${EVENT_INFO}\",\"limit\":1}")

EVENT_ID=""
EVENT_UUID=""
if echo "${SEARCH_RESULT}" | grep -q '"id"'; then
    EVENT_ID=$(echo "${SEARCH_RESULT}" \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['Event']['id'] if d else '')" 2>/dev/null || true)
    EVENT_UUID=$(echo "${SEARCH_RESULT}" \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['Event']['uuid'] if d else '')" 2>/dev/null || true)
fi

if [[ -n "${EVENT_ID}" ]]; then
    echo "Event already exists (id: ${EVENT_ID}, uuid: ${EVENT_UUID}). Skipping creation."
else
    echo "Event not found. Creating new event..."

    CREATE_RESULT=$(misp_api POST /events \
        "{
            \"Event\": {
                \"info\": \"${EVENT_INFO}\",
                \"distribution\": 0,
                \"threat_level_id\": 1,
                \"analysis\": 2,
                \"date\": \"$(date +%Y-%m-%d)\"
            }
        }")

    EVENT_ID=$(echo "${CREATE_RESULT}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['Event']['id'])" 2>/dev/null || true)
    EVENT_UUID=$(echo "${CREATE_RESULT}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['Event']['uuid'])" 2>/dev/null || true)

    if [[ -z "${EVENT_ID}" ]]; then
        echo "ERROR: Failed to create event. MISP response:"
        echo "${CREATE_RESULT}"
        exit 1
    fi

    echo "Created event (id: ${EVENT_ID})."
fi

echo ""

# ---------------------------------------------------------------------------
# Step 2: Add IOC attributes
# ---------------------------------------------------------------------------
add_attribute() {
    local attr_type="$1"
    local value="$2"
    local category="$3"
    local comment="$4"
    local to_ids="${5:-1}"

    echo "  Adding ${attr_type}: ${value} ..."

    ATTR_RESULT=$(misp_api POST "/attributes/add/${EVENT_ID}" \
        "{
            \"type\": \"${attr_type}\",
            \"value\": \"${value}\",
            \"category\": \"${category}\",
            \"to_ids\": ${to_ids},
            \"comment\": \"${comment}\"
        }")

    if echo "${ATTR_RESULT}" | grep -qi "already exists"; then
        echo "    (already exists, skipped)"
    elif echo "${ATTR_RESULT}" | grep -q '"Attribute"'; then
        echo "    OK"
    else
        echo "    WARNING: unexpected response: ${ATTR_RESULT}"
    fi
}

echo "Adding IOC attributes to event ${EVENT_ID}..."

# -- Network indicators: Kali red-team IPs --
add_attribute "ip-src" "172.20.4.30" \
    "Network activity" \
    "APTL Kali red-team container (external IP)"

add_attribute "ip-src" "172.20.2.35" \
    "Network activity" \
    "APTL Kali internal pivot IP"

add_attribute "ip-src" "172.20.1.30" \
    "Network activity" \
    "APTL Kali DMZ network IP"

# -- Web attack patterns --
add_attribute "pattern-in-traffic" "UNION SELECT" \
    "Network activity" \
    "SQL injection pattern (UNION-based)" 0

add_attribute "pattern-in-traffic" "<script>" \
    "Network activity" \
    "Cross-site scripting (XSS) pattern" 0

add_attribute "pattern-in-traffic" ";ls" \
    "Network activity" \
    "OS command injection pattern" 0

echo ""

# ---------------------------------------------------------------------------
# Step 3: Tag the event
# ---------------------------------------------------------------------------
tag_event() {
    local tag_name="$1"

    echo "  Tagging event with '${tag_name}' ..."

    TAG_RESULT=$(misp_api POST /tags/attachTagToObject \
        "{
            \"uuid\": \"${EVENT_UUID}\",
            \"tag\": \"${tag_name}\"
        }")

    if echo "${TAG_RESULT}" | grep -qi "successfully"; then
        echo "    OK"
    elif echo "${TAG_RESULT}" | grep -qi "already"; then
        echo "    (already tagged, skipped)"
    else
        echo "    Done (response: $(echo "${TAG_RESULT}" | head -c 120))"
    fi
}

echo "Tagging event..."
tag_event "aptl:red-team"
tag_event "tlp:red"

echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== MISP Seed Complete ==="
echo "Event ID:    ${EVENT_ID}"
echo "Event Info:  ${EVENT_INFO}"
echo "MISP URL:    ${MISP_URL}/events/view/${EVENT_ID}"
echo ""
echo "Attributes added:"
echo "  ip-src           172.20.4.30       Kali external IP"
echo "  ip-src           172.20.2.35       Kali internal IP"
echo "  pattern-in-traffic   UNION SELECT      SQLi pattern"
echo "  pattern-in-traffic   <script>          XSS pattern"
echo "  pattern-in-traffic   ;ls               Command injection pattern"
echo ""
echo "Tags: aptl:red-team, tlp:red"
