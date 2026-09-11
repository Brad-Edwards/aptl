#!/bin/bash
# =============================================================================
# TEMPORARY env-pack SOAR fixups
# =============================================================================
# The frozen TechVault env-pack realizes MISP and misp-redis WITHOUT the runtime
# environment they need, so they boot broken:
#
#   - misp-redis runs with no password, but MISP connects with
#     auth=redispassword -> Redis unreachable -> API-key auth fails.
#   - MISP has no MYSQL_*/ADMIN_*/BASE_URL env and its lab cert is mounted at
#     the wrong path -> no DB, no admin key, self-signed cert.
# This recreates those two containers with the configuration recovered from
# the pre-ACES docker-compose.yml (which ran these services for months). It is
# idempotent: a container already carrying the fix is left untouched, so this is
# safe to run on every boot. It buys us out of the env-pack release cycle; it
# does not change the scenario.
#
# Root fixes tracked upstream (remove this script when they ship):
#   MISP  -> OpenRAE/env-packs#280 ; retire per Brad-Edwards/aptl#912
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="${APTL_PROJECT_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
CERT_BASE="$PROJECT_DIR/config/soc_certs"
# Same canonical key MISP's server (ADMIN_KEY) and the seed client share.
MISP_API_KEY="${MISP_API_KEY:-JHxBbGPnAtyut0FTwkeuhVFnbMksGRCRwsE0V9Xw}"

command -v docker >/dev/null 2>&1 || exit 0

_present()  { docker inspect "$1" >/dev/null 2>&1; }
_net()      { docker inspect "$1" -f '{{range $n,$c := .NetworkSettings.Networks}}{{$n}}{{end}}' 2>/dev/null; }
_image()    { docker inspect "$1" -f '{{.Config.Image}}' 2>/dev/null; }
_has_env()  { docker inspect "$1" -f '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -q "^$2="; }

# The RAES/Compose realization owns the MISP publication.  fix_misp replaces
# that realized container after compose up, so it must carry the exact binding
# across the replacement instead of reconstructing a second source of truth.
MISP_PUBLISH_ARGS=()
MISP_EXPECTED_PUBLICATION=""
_misp_publications() {
    docker inspect "$1" --format \
        '{{with (index .HostConfig.PortBindings "443/tcp")}}{{range .}}{{println .HostIp .HostPort}}{{end}}{{end}}' \
        2>/dev/null
}

_capture_misp_publication() {
    MISP_PUBLISH_ARGS=()
    MISP_EXPECTED_PUBLICATION=""
    local host_ip host_port count=0
    while read -r host_ip host_port; do
        [ -n "$host_ip" ] && [ -n "$host_port" ] || continue
        count=$((count + 1))
        if [ "$host_ip" != "127.0.0.1" ] \
            || ! [[ "$host_port" =~ ^[0-9]+$ ]] \
            || [ "$host_port" -lt 1 ] \
            || [ "$host_port" -gt 65535 ]; then
            log "ERROR: realized MISP publication is not a valid loopback TCP binding"
            return 1
        fi
        MISP_EXPECTED_PUBLICATION="$host_ip $host_port"
        MISP_PUBLISH_ARGS+=(--publish "$host_ip:$host_port:443/tcp")
    done < <(_misp_publications aptl-misp)
    if [ "$count" -ne 1 ]; then
        log "ERROR: realized MISP container must have exactly one 443/tcp publication"
        return 1
    fi
}

_verify_misp_publication() {
    local host_ip host_port count=0 actual=""
    while read -r host_ip host_port; do
        [ -n "$host_ip" ] && [ -n "$host_port" ] || continue
        count=$((count + 1))
        actual="$host_ip $host_port"
    done < <(_misp_publications aptl-misp)
    if [ "$count" -ne 1 ] || [ "$actual" != "$MISP_EXPECTED_PUBLICATION" ]; then
        log "ERROR: replacement MISP container did not preserve its realized publication"
        return 1
    fi
}

# Capture a container's labels into LBL_ARGS as `--label k=v` pairs BEFORE it is
# removed, so the recreated container keeps its compose-project membership.
# Without this the replacement is invisible to `docker compose down` and its live
# endpoint blocks the NEXT boot's clean-state teardown ("network has active
# endpoints").
LBL_ARGS=()
_capture_labels() {
    LBL_ARGS=()
    local l
    while IFS= read -r l; do
        [ -n "$l" ] && LBL_ARGS+=(--label "$l")
    done < <(docker inspect "$1" \
        --format '{{range $k,$v := .Config.Labels}}{{$k}}={{$v}}{{"\n"}}{{end}}' 2>/dev/null)
}

log() { echo "[envpack-soar-fixups] $*"; }

# --- misp-redis: restore the password MISP expects --------------------------
fix_misp_redis() {
    _present aptl-misp-redis || return 0
    # If AUTH is already required, redis-cli ping without a password says NOAUTH.
    if docker exec aptl-misp-redis redis-cli ping 2>&1 | grep -qi 'NOAUTH'; then
        return 0
    fi
    log "misp-redis has no password; recreating with --requirepass"
    local img net
    img="$(_image aptl-misp-redis)"; net="$(_net aptl-misp-redis)"
    _capture_labels aptl-misp-redis
    docker rm -f aptl-misp-redis >/dev/null 2>&1 || true
    docker run -d --name aptl-misp-redis --restart unless-stopped "${LBL_ARGS[@]}" \
        --network "$net" --network-alias aptl-misp-redis --network-alias misp-redis \
        "$img" redis-server --requirepass redispassword >/dev/null
}

# --- MISP: full working env + correct cert path + fresh init ----------------
fix_misp() {
    _present aptl-misp || return 0
    _has_env aptl-misp MYSQL_HOST && return 0
    log "MISP missing DB/admin env; recreating with working configuration"
    local img net
    img="$(_image aptl-misp)"; net="$(_net aptl-misp)"
    _capture_labels aptl-misp
    _capture_misp_publication || return 1
    docker rm -f aptl-misp >/dev/null 2>&1 || true
    # Fresh schema so the admin key (ADMIN_KEY) is applied at init.
    docker exec aptl-misp-db mysql -uroot -pmisp_root_password \
        -e 'DROP DATABASE IF EXISTS misp; CREATE DATABASE misp;' >/dev/null 2>&1 || true
    docker volume rm aptl_misp_config aptl_misp_data >/dev/null 2>&1 || true
    if ! docker run -d --name aptl-misp --restart unless-stopped "${LBL_ARGS[@]}" \
        "${MISP_PUBLISH_ARGS[@]}" \
        --network "$net" --network-alias aptl-misp --network-alias misp \
        -e MYSQL_HOST=misp-db -e MYSQL_DATABASE=misp -e MYSQL_USER=misp -e MYSQL_PASSWORD=misp_db_password \
        -e ADMIN_EMAIL=admin@admin.test -e ADMIN_PASSWORD=admin -e ADMIN_KEY="$MISP_API_KEY" \
        -e BASE_URL=https://localhost:8443 -e REDIS_HOST=misp-redis \
        -v aptl_misp_config:/var/www/MISP/app/Config -v aptl_misp_data:/var/www/MISP/app/files \
        -v "$CERT_BASE/misp/server.pem":/etc/nginx/certs/cert.pem:ro \
        -v "$CERT_BASE/misp/server.key":/etc/nginx/certs/key.pem:ro \
        "$img" >/dev/null; then
        log "ERROR: replacement MISP container could not be started"
        return 1
    fi
    _verify_misp_publication
}

# --- readiness waits so the seed steps find the services up -----------------
wait_misp() {
    _present aptl-misp || return 0
    local i
    # Wait for AUTHENTICATED readiness, not just the login page: MISP's admin key
    # + Redis-backed auth come up several minutes after the HTTP listener, and
    # the MISP seed step needs the key to authenticate. Polling /users/view/me
    # with the canonical key is exactly the readiness the seed depends on.
    for i in $(seq 1 90); do
        if docker exec aptl-misp curl -ks -o /dev/null -w '%{http_code}' --max-time 8 \
            -H "Authorization: ${MISP_API_KEY}" -H 'Accept: application/json' \
            https://localhost:443/users/view/me 2>/dev/null | grep -q '^200$'; then
            log "MISP API is authenticating"; return 0
        fi
        sleep 10
    done
    log "WARNING: MISP API not authenticating after 900s"
}

wait_shuffle() {
    _present aptl-shuffle-backend || return 0
    local i
    for i in $(seq 1 30); do
        if docker exec aptl-shuffle-backend wget -qO- --timeout=6 \
            --header="Authorization: Bearer 31a211c4-ea5c-4a49-b022-5e2434e758a7" \
            http://localhost:5001/api/v1/getenvironments 2>/dev/null | grep -q 'Shuffle'; then
            log "Shuffle backend is serving"; return 0
        fi
        sleep 10
    done
    log "ERROR: shuffle-backend not serving after 300s"
    return 1
}

log "applying temporary env-pack SOAR fixups (see header for tracking issues)"
fix_misp_redis
if ! fix_misp; then
    exit 1
fi
wait_misp
if ! wait_shuffle; then
    exit 1
fi
log "done"
