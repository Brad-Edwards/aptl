#!/bin/bash
# =============================================================================
# provision-range.sh -- bring a freshly-launched AMI clone up as a fully working
# APTL Arsenal range.
# =============================================================================
# Runs on an instance launched from the Arsenal AMI. The AMI carries: the aptl
# checkout with all fixes on disk, the .venv, the baked Docker images, and the
# agent layer (Node 22 + Claude Code + built MCPs + .mcp.json + Bedrock env in
# ~/.bashrc). This script rebuilds a clean lab from those baked images so every
# clone is deterministic and free of any lab state captured into the AMI.
#
# It is idempotent and safe to re-run. `aptl lab start` internally runs the
# realization (with the certs.py root-owned-cert-dir self-heal) and then
# scripts/seed-prime.sh, which applies the temporary env-pack fixups
# (SOAR + Suricata + Kali capture-wrapper). Kali readiness may report
# "degraded" DURING lab start because the kali wrapper is relaxed by seed-prime
# which runs just after the readiness probe; kali is fully reachable once this
# script finishes. That degraded line is cosmetic -- verification below is the
# source of truth.
# =============================================================================
set -uo pipefail

PROJECT_DIR="${APTL_PROJECT_DIR:-/home/ubuntu/aptl3}"
LOG=/tmp/provision-range.log
exec > >(tee -a "$LOG") 2>&1
echo "=== provision-range starting $(date -u) ==="

cd "$PROJECT_DIR"

# Elasticsearch/OpenSearch mmap requirement (persisted for reboots).
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-aptl.conf >/dev/null
sudo sysctl -w vm.max_map_count=262144 >/dev/null

# shellcheck disable=SC1091
source .venv/bin/activate 2>/dev/null || true

# -1. Re-assert the RDP login password. cloud-init locks the default user's
#     password on a fresh clone's first boot, overriding what the AMI baked, so
#     RDP auth fails ("login failed for user ubuntu"). This runs after cloud-init.
echo "--- set RDP password ---"
echo "${APTL_RDP_USER:-ubuntu}:${APTL_RDP_PASS:-AptlArsenal!2026}" | sudo chpasswd || true
sudo passwd -u "${APTL_RDP_USER:-ubuntu}" >/dev/null 2>&1 || true

# 0. Free UDP :5353 for the aptl `dns` node. The RDP desktop pulls in
#    avahi-daemon (mDNS on 5353); on a fresh boot it wins the port before the
#    lab starts, so the dns container cannot bind and the whole realization
#    fails (BaseSubstrateOp on node dns). avahi is not needed here -- mask it.
echo "--- free :5353 (mask avahi) ---"
sudo systemctl disable --now avahi-daemon.service avahi-daemon.socket 2>/dev/null || true
sudo systemctl mask avahi-daemon.service avahi-daemon.socket 2>/dev/null || true

# 1. Clean any lab state captured into the AMI so we build fresh from images.
echo "--- clean-slate baked lab state ---"
pkill -f 'aptl lab start' 2>/dev/null || true
sleep 2
docker rm -f $(docker ps -aq --filter name=aptl-) 2>/dev/null || true
docker network ls --format '{{.Name}}' | grep -E '^aptl' | xargs -r docker network rm 2>/dev/null || true
docker volume ls --format '{{.Name}}' \
    | grep -Ei 'aptl|misp|shuffle|thehive|wazuh|cortex|tempo|grafana|kali|suricata|opensearch' \
    | xargs -r docker volume rm 2>/dev/null || true
# wazuh_indexer_ssl_certs is regenerated each boot; certs.py also self-heals a
# root-owned one, but removing it here keeps the slate clean. soc_certs is
# (re)generated below and must exist before the bind-mount pre-flight.
sudo rm -rf config/wazuh_indexer_ssl_certs .aptl 2>/dev/null || true

# 2. Ensure the SOC CA + service certs exist at the project dir. The bind-mount
#    pre-flight in `aptl lab start` requires config/soc_certs/ to pre-exist;
#    generate it deterministically here (proven code path) rather than rely on
#    lab-start's own generation resolving the project root on a fresh clone.
echo "--- ensure SOC certs ---"
python -c "from pathlib import Path; from aptl.core.soc_ca import ensure_soc_certs; r=ensure_soc_certs(Path('$PROJECT_DIR')); print('soc_certs:', 'generated' if r.generated else 'present', r.certs_dir)"

# 3. Build the lab. This realizes the stack (certs self-heal included) and runs
#    seed-prime.sh (SOAR + Suricata + Kali fixups).
echo "--- aptl lab start ---"
aptl lab start || echo "WARN: aptl lab start returned non-zero (kali readiness 'degraded' is expected pre-seed; verifying below)"

# 4. Ensure the fixups actually applied (seed-prime runs inside lab start, but
#    re-run idempotently in case lab start aborted before reaching it).
echo "--- re-assert env-pack fixups (idempotent) ---"
bash scripts/seed-prime.sh || echo "WARN: seed-prime reported issues"

# 4b. Per-range identity + agent desktop. The range passphrase is passed via EC2
#     user-data at launch (`APTL_RANGE_PASS=...`); fall back to a default for a
#     manual boot. Guacamole (browser entry) and the ubuntu OS account (used by
#     guacd -> xrdp on localhost) share it, and the guac RDP connection is kept
#     in sync so guacd can still log in.
echo "--- per-range secure init ---"
UD="$(curl -s -m5 http://169.254.169.254/latest/user-data 2>/dev/null || true)"
RANGE_PASS="$(printf '%s\n' "$UD" | sed -n 's/^APTL_RANGE_PASS=//p' | head -1)"
RANGE_PASS="${RANGE_PASS:-AptlArsenal!2026}"
echo "ubuntu:${RANGE_PASS}" | sudo chpasswd || true
sudo passwd -u ubuntu >/dev/null 2>&1 || true

if [ -f /home/ubuntu/guac/docker-compose.yml ]; then
    echo "--- guac stack ---"
    docker compose -p guac -f /home/ubuntu/guac/docker-compose.yml up -d >/dev/null 2>&1 || true
    for _ in $(seq 1 25); do
        [ "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8090/guacamole/ 2>/dev/null)" = "200" ] && break
        sleep 3
    done
    # keep the guac RDP connection password in sync with the ubuntu account
    docker exec guac-postgres psql -U guacamole -d guacamole_db -c \
      "UPDATE guacamole_connection_parameter SET parameter_value='${RANGE_PASS}' WHERE parameter_name='password' AND connection_id IN (SELECT connection_id FROM guacamole_connection WHERE connection_name='Kali Range Desktop');" >/dev/null 2>&1 || true
    # Set the guacadmin web password to the range passphrase via SQL (robust: no
    # dependency on the previous password). Guacamole hashes as
    # SHA-256(password + UPPERCASE_HEX(salt)).
    python3 - "$RANGE_PASS" <<'PY' | docker exec -i guac-postgres psql -U guacamole -d guacamole_db >/dev/null 2>&1 && echo "guac web password set (SQL)" || echo "WARN: guac password set failed"
import sys, os, hashlib
pw = sys.argv[1]
salt = os.urandom(32)
h = hashlib.sha256(pw.encode() + salt.hex().upper().encode()).hexdigest()
print("UPDATE guacamole_user SET password_hash=decode('%s','hex'), password_salt=decode('%s','hex'), password_date=now() "
      "WHERE entity_id=(SELECT entity_id FROM guacamole_entity WHERE name='guacadmin' AND type='USER');" % (h, salt.hex()))
PY
fi

# Recreate the red/blue Claude tmux sessions. The baked ~/.claude.json carries
# the completed onboarding + folder-trust + bypass acceptance, so the agents
# launch straight to a prompt with no interactive dialogs.
if [ -x scripts/setup-purple-demo.sh ]; then
    echo "--- purple team sessions ---"
    bash scripts/setup-purple-demo.sh >/tmp/purple-setup.log 2>&1 || echo "WARN: purple setup issues (see /tmp/purple-setup.log)"
fi

# 5. Verify the range is actually usable.
echo "--- verify ---"
UP=$(docker ps -q --filter name=aptl- | wc -l)
echo "containers up: $UP"
KALI=$(docker exec -u root aptl-kali bash -c 'unset APTL_CAPTURE_CAPABILITY; export SSH_ORIGINAL_COMMAND="echo KALI_OK"; bash /usr/local/bin/aptl-wrap-shell.sh' 2>/dev/null | tail -1)
echo "kali shell: ${KALI:-UNREACHABLE}"
SURI=$(docker logs aptl-suricata 2>&1 | grep -a 'rules successfully loaded' | tail -1)
echo "suricata: ${SURI:-no-rule-load-line}"
BADCTRS=$(docker ps -a --filter name=aptl- --format '{{.Names}} {{.Status}}' | grep -iE 'unhealthy|Exited|Restarting' || true)
[ -n "$BADCTRS" ] && echo "UNHEALTHY/EXITED:" && echo "$BADCTRS"

if [ "$UP" -ge 30 ] && [ "$KALI" = "KALI_OK" ] && [ -z "$BADCTRS" ]; then
    echo "RANGE_PROVISION_OK $(date -u)"
else
    echo "RANGE_PROVISION_DEGRADED $(date -u) -- inspect $LOG"
fi
