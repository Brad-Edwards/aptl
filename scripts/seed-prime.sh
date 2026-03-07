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

echo "============================================="
echo "  APTL Prime Scenario Seed"
echo "============================================="
echo ""

# ---------------------------------------------------------------------------
# 0. Wait for SOC tools to be healthy
# ---------------------------------------------------------------------------
echo "[0/6] Waiting for SOC tools to be healthy..."

for svc in aptl-thehive aptl-misp aptl-shuffle-backend; do
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
echo "[1/6] Provisioning TheHive API key..."

if [ -x "$SCRIPT_DIR/thehive-apikey.sh" ]; then
    THEHIVE_API_KEY=$("$SCRIPT_DIR/thehive-apikey.sh" 2>/dev/null) || true
    if [ -n "$THEHIVE_API_KEY" ]; then
        export THEHIVE_API_KEY
        echo "  TheHive API key provisioned: ${THEHIVE_API_KEY:0:8}..."
    else
        echo "  WARNING: Could not provision TheHive API key (non-fatal)"
    fi
else
    echo "  SKIP: thehive-apikey.sh not found"
fi

# ---------------------------------------------------------------------------
# 2. Wait for Wazuh Indexer to be healthy
# ---------------------------------------------------------------------------
echo ""
echo "[2/6] Waiting for Wazuh Indexer to be healthy..."

INDEXER_URL="${INDEXER_URL:-https://localhost:9200}"
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
    echo "  WARNING: Indexer may not be ready after ${max_wait}s, continuing anyway..."
fi

# ---------------------------------------------------------------------------
# 3. Seed MISP with threat intelligence
# ---------------------------------------------------------------------------
echo ""
echo "[3/6] Seeding MISP with lab threat intelligence..."

if [ -x "$SCRIPT_DIR/seed-misp.sh" ]; then
    "$SCRIPT_DIR/seed-misp.sh" || echo "  WARNING: MISP seeding failed (non-fatal)"
else
    echo "  SKIP: seed-misp.sh not found or not executable"
fi

# ---------------------------------------------------------------------------
# 4. Seed Shuffle with SOAR workflows
# ---------------------------------------------------------------------------
echo ""
echo "[4/6] Seeding Shuffle with SOAR workflows..."

if [ -x "$SCRIPT_DIR/seed-shuffle.sh" ]; then
    "$SCRIPT_DIR/seed-shuffle.sh" || echo "  WARNING: Shuffle seeding failed (non-fatal)"
else
    echo "  SKIP: seed-shuffle.sh not found or not executable"
fi

# ---------------------------------------------------------------------------
# 5. Configure Wazuh -> Shuffle integration
# ---------------------------------------------------------------------------
echo ""
echo "[5/6] Configuring Wazuh -> Shuffle integration..."

WEBHOOK_FILE="/tmp/aptl_shuffle_webhook_url"
if [ -f "$WEBHOOK_FILE" ]; then
    WEBHOOK_URL=$(cat "$WEBHOOK_FILE")
    docker exec aptl-wazuh-manager bash -c \
        "echo '${WEBHOOK_URL}' > /var/ossec/etc/shuffle_webhook_url"
    echo "  Webhook URL written to Wazuh manager: ${WEBHOOK_URL}"
else
    echo "  WARNING: No webhook URL from Shuffle seed (non-fatal)"
fi

# ---------------------------------------------------------------------------
# 6. Plant workstation SSH key into victim authorized_keys (if needed)
# ---------------------------------------------------------------------------
echo ""
echo "[6/6] Ensuring workstation SSH key is authorized on victim..."

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
    echo "  WARNING: Could not read workstation SSH public key"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================="
echo "  Prime Scenario Seed Complete"
echo "============================================="
echo ""
echo "Seeded state:"
echo "  - TheHive API key: provisioned (export THEHIVE_API_KEY=${THEHIVE_API_KEY:-not set})"
echo "  - Wazuh Indexer: healthy"
echo "  - MISP: Kali IOCs and attack patterns"
echo "  - Shuffle: Alert-to-Case workflow (webhook -> MISP enrichment -> TheHive case)"
echo "  - Wazuh -> Shuffle: integration configured (level 10+ alerts)"
echo "  - Workstation -> Victim: SSH key trust"
echo ""
echo "Ready for: aptl scenario start prime-enterprise"
echo ""
