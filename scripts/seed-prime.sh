#!/bin/bash
set -euo pipefail

# =============================================================================
# APTL Prime Scenario Seed Script
# =============================================================================
# Master seed script for the TechVault Enterprise prime research scenario.
# Calls existing seed scripts and ensures the environment is ready for a run.
#
# Prerequisites:
#   - All containers running (wazuh, enterprise, victim, kali, fileshare, soc)
#
# Usage:
#   ./scripts/seed-prime.sh
#
# Idempotent -- safe to re-run.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$PROJECT_DIR/.env"
SEED_FAILURES=()

record_seed_failure() {
    local component="$1"
    local message="$2"
    echo "  ERROR: $message"
    SEED_FAILURES+=("$component")
}

ensure_env_file() {
    if [ ! -f "$ENV_FILE" ]; then
        touch "$ENV_FILE"
        chmod 600 "$ENV_FILE"
    fi
}

update_env_var() {
    local key="$1"
    local value="$2"
    ensure_env_file
    local tmp
    tmp=$(mktemp "${ENV_FILE}.tmp.XXXXXX")
    awk -v key="$key" -v value="$value" '
        BEGIN { updated = 0 }
        index($0, key "=") == 1 {
            print key "=" value
            updated = 1
            next
        }
        { print }
        END {
            if (!updated) {
                print key "=" value
            }
        }
    ' "$ENV_FILE" > "$tmp"
    cat "$tmp" > "$ENV_FILE"
    rm -f "$tmp"
    chmod 600 "$ENV_FILE"
}

# Manual reruns start in a fresh shell, unlike `aptl lab start`, which passes
# the hydrated lab environment explicitly. Reuse the running lab's credentials
# so recovery cannot replace a randomized service key with a baked-in default.
source "$SCRIPT_DIR/aptl-env.sh"
for key in \
    INDEXER_USERNAME INDEXER_PASSWORD MISP_API_KEY SHUFFLE_API_KEY CORTEX_API_KEY
do
    aptl_load_env_key "$ENV_FILE" "$key"
done

echo "============================================="
echo "  APTL Prime Scenario Seed"
echo "============================================="
echo ""

# ---------------------------------------------------------------------------
# 0. Wait for SOC tools to be healthy
# ---------------------------------------------------------------------------
echo "[0/7] Waiting for SOC tools to be healthy..."

# SEC-006 / ADR-034: seed-shuffle.sh now talks to the HTTPS frontend
# at https://localhost:3443. The readiness gate waits for
# `aptl-shuffle-frontend` (which has a healthcheck post-SEC-006)
# rather than the headless `aptl-shuffle-backend` container that
# Docker reports without a `.State.Health.Status`.
for svc in aptl-cortex aptl-thehive aptl-misp aptl-shuffle-frontend; do
    max_wait=600
    elapsed=0
    while [ $elapsed -lt $max_wait ]; do
        status=$(docker inspect "$svc" --format '{{.State.Health.Status}}' 2>/dev/null) || status="not found"
        if [ "$status" = "healthy" ] || [ "$status" = "not found" ]; then
            break
        fi
        if [ $((elapsed % 30)) -eq 0 ]; then
            echo "  Waiting for $svc ($status)... ${elapsed}s / ${max_wait}s"
        fi
        sleep 10
        elapsed=$((elapsed + 10))
    done
    if [ "$status" = "healthy" ]; then
        echo "  $svc is healthy"
    elif [ "$status" = "not found" ]; then
        echo "  $svc not running (skipping)"
    else
        echo "  WARNING: $svc still not healthy after ${max_wait}s, will attempt anyway"
    fi
done

echo ""

# ---------------------------------------------------------------------------
# 1. Provision TheHive API key
# ---------------------------------------------------------------------------
echo "[1/7] Provisioning TheHive API key..."

if [ -x "$SCRIPT_DIR/thehive-apikey.sh" ]; then
    if THEHIVE_API_KEY=$("$SCRIPT_DIR/thehive-apikey.sh" 2>/dev/null) && \
        [ -n "$THEHIVE_API_KEY" ]; then
        export THEHIVE_API_KEY
        echo "  TheHive API key provisioned: ${THEHIVE_API_KEY:0:8}..."

        # Persist provisioned + default seed keys back to .env so MCP servers
        # (which spawn fresh per tool call and load .env at startup) can
        # authenticate to TheHive, MISP, and Shuffle without manual rewiring.
        # The shared aptl-mcp-common library walks up the directory tree from
        # each MCP server's docker-lab-config.json and merges .env defaults
        # under process.env, so the values land in every MCP child process.
        update_env_var THEHIVE_API_KEY "$THEHIVE_API_KEY"
        # MISP and Shuffle use stable defaults baked into the lab; persist them
        # too so future MCP startups read a single canonical source.
        update_env_var MISP_API_KEY "${MISP_API_KEY:-JHxBbGPnAtyut0FTwkeuhVFnbMksGRCRwsE0V9Xw}"
        update_env_var SHUFFLE_API_KEY "${SHUFFLE_API_KEY:-31a211c4-ea5c-4a49-b022-5e2434e758a7}"
        echo "  TheHive/MISP/Shuffle API keys written to .env (mode 600)"
    else
        record_seed_failure "TheHive API key" "Could not provision TheHive API key"
    fi
else
    record_seed_failure "TheHive API key" "thehive-apikey.sh not found"
fi

# ---------------------------------------------------------------------------
# 2. Provision Cortex API key for TheHive connector
# ---------------------------------------------------------------------------
echo ""
echo "[2/7] Provisioning Cortex API key..."

if [ -x "$SCRIPT_DIR/cortex-apikey.sh" ]; then
    if CORTEX_API_KEY=$("$SCRIPT_DIR/cortex-apikey.sh") && \
        [ -n "$CORTEX_API_KEY" ]; then
        export CORTEX_API_KEY
        update_env_var CORTEX_API_KEY "$CORTEX_API_KEY"
        echo "  Cortex API key provisioned and written to .env (mode 600)"
    else
        record_seed_failure "Cortex API key" "Could not provision Cortex API key"
    fi
else
    record_seed_failure "Cortex API key" "cortex-apikey.sh not found"
fi

# ---------------------------------------------------------------------------
# 3. Wait for Wazuh Indexer to be healthy
# ---------------------------------------------------------------------------
echo ""
echo "[3/7] Waiting for Wazuh Indexer to be healthy..."

INDEXER_PORT="${APTL_HP_WAZUH_INDEXER_9200:-9200}"
INDEXER_URL="${INDEXER_URL:-https://localhost:${INDEXER_PORT}}"
INDEXER_USER="${INDEXER_USERNAME:-admin}"
INDEXER_PASS="${INDEXER_PASSWORD:-SecretPassword}"

max_wait=600
elapsed=0
while [ $elapsed -lt $max_wait ]; do
    status=$(curl -ks -u "$INDEXER_USER:$INDEXER_PASS" \
        "$INDEXER_URL/_cluster/health" 2>/dev/null \
        | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4) || true

    if [ "$status" = "green" ] || [ "$status" = "yellow" ]; then
        echo "  Wazuh Indexer is healthy (status: $status)"
        break
    fi

    if [ $((elapsed % 30)) -eq 0 ]; then
        echo "  Waiting for indexer... (${elapsed}s / ${max_wait}s)"
    fi
    sleep 5
    elapsed=$((elapsed + 5))
done

if [ $elapsed -ge $max_wait ]; then
    record_seed_failure \
        "Wazuh Indexer" \
        "Indexer was not ready after ${max_wait}s"
fi

# ---------------------------------------------------------------------------
# 4. Seed MISP with threat intelligence
# ---------------------------------------------------------------------------
echo ""
echo "[4/7] Seeding MISP with lab threat intelligence..."

if [ -x "$SCRIPT_DIR/seed-misp.sh" ]; then
    if ! "$SCRIPT_DIR/seed-misp.sh"; then
        record_seed_failure "MISP" "MISP seeding failed"
    fi
else
    record_seed_failure "MISP" "seed-misp.sh not found or not executable"
fi

# ---------------------------------------------------------------------------
# 5. Seed Shuffle with SOAR workflows
# ---------------------------------------------------------------------------
echo ""
echo "[5/7] Seeding Shuffle with SOAR workflows..."

if [ -x "$SCRIPT_DIR/seed-shuffle.sh" ]; then
    if ! "$SCRIPT_DIR/seed-shuffle.sh"; then
        record_seed_failure "Shuffle" "Shuffle seeding failed"
    fi
else
    record_seed_failure "Shuffle" "seed-shuffle.sh not found or not executable"
fi

# ---------------------------------------------------------------------------
# 6. Configure Wazuh -> Shuffle integration
# ---------------------------------------------------------------------------
echo ""
echo "[6/7] Configuring Wazuh -> Shuffle integration..."

WEBHOOK_FILE="${APTL_SHUFFLE_WEBHOOK_FILE:-/tmp/aptl_shuffle_webhook_url}"
if [ -f "$WEBHOOK_FILE" ]; then
    WEBHOOK_URL=$(cat "$WEBHOOK_FILE")
    if docker exec aptl-wazuh-manager bash -c \
        "echo '${WEBHOOK_URL}' > /var/ossec/etc/shuffle_webhook_url"; then
        echo "  Webhook URL written to Wazuh manager: ${WEBHOOK_URL}"
    else
        record_seed_failure \
            "Wazuh to Shuffle" \
            "Could not write the Shuffle webhook URL to Wazuh"
    fi
else
    record_seed_failure \
        "Wazuh to Shuffle" \
        "Shuffle seed did not produce a webhook URL"
fi

# ---------------------------------------------------------------------------
# 7. Plant workstation SSH key into victim authorized_keys (if needed)
# ---------------------------------------------------------------------------
echo ""
echo "[7/7] Ensuring workstation SSH key is authorized on victim..."

# Extract the workstation's dev-user public key and add to victim's labadmin
ws_pubkey=$(docker exec aptl-workstation cat /home/dev-user/.ssh/id_rsa.pub 2>/dev/null) || true

if [ -n "$ws_pubkey" ]; then
    # Check if already present
    existing=$(docker exec aptl-victim grep -c "$(echo "$ws_pubkey" | awk '{print $2}')" \
        /home/labadmin/.ssh/authorized_keys 2>/dev/null) || existing=0

    if [ "$existing" -eq 0 ]; then
        docker exec aptl-victim bash -c "echo '$ws_pubkey' >> /home/labadmin/.ssh/authorized_keys"
        echo "  Added workstation dev-user key to victim labadmin authorized_keys"
    else
        echo "  Workstation key already present in victim authorized_keys"
    fi
else
    record_seed_failure \
        "Workstation to victim" \
        "Could not read workstation SSH public key"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
if [ ${#SEED_FAILURES[@]} -gt 0 ]; then
    echo "============================================="
    echo "  Prime Scenario Seed Incomplete"
    echo "============================================="
    echo ""
    echo "Required seed steps failed:"
    printf '  - %s\n' "${SEED_FAILURES[@]}"
    echo ""
    echo "Resolve the errors above and re-run scripts/seed-prime.sh."
    exit 1
fi

echo "============================================="
echo "  Prime Scenario Seed Complete"
echo "============================================="
echo ""
echo "Seeded state:"
echo "  - TheHive API key: provisioned and stored in .env"
echo "  - Cortex API key: provisioned for TheHive connector"
echo "  - Wazuh Indexer: healthy"
echo "  - MISP: Kali IOCs and attack patterns"
echo "  - Shuffle: Alert-to-Case workflow (webhook -> MISP enrichment -> TheHive case)"
echo "  - Wazuh -> Shuffle: integration configured (level 10+ alerts)"
echo "  - Workstation -> Victim: SSH key trust"
echo ""
echo "Ready for: aptl scenario start prime-enterprise"
echo ""
