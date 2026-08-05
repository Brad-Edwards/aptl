#!/bin/bash
# =============================================================================
# TEMPORARY env-pack SOAR fixups
# =============================================================================
# The frozen TechVault env-pack realizes MISP, misp-redis, and shuffle-backend
# WITHOUT the runtime environment they need, so they boot broken:
#
#   - misp-redis runs with no password, but MISP connects with
#     auth=redispassword -> Redis unreachable -> API-key auth fails.
#   - MISP has no MYSQL_*/ADMIN_*/BASE_URL env and its lab cert is mounted at
#     the wrong path -> no DB, no admin key, self-signed cert.
#   - shuffle-backend has no SHUFFLE_OPENSEARCH_* env -> it verifies TLS against
#     the opensearch demo cert and never connects to its datastore.
#
# This recreates those three containers with the configuration recovered from
# the pre-ACES docker-compose.yml (which ran these services for months). It is
# idempotent: a container already carrying the fix is left untouched, so this is
# safe to run on every boot. It buys us out of the env-pack release cycle; it
# does not change the scenario.
#
# Root fixes tracked upstream (remove this script when they ship):
#   MISP  -> OpenRAE/env-packs#280 ; retire per Brad-Edwards/aptl#912
#   Shuffle -> OpenRAE/env-packs#281 ; retire per Brad-Edwards/aptl#913
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
    docker rm -f aptl-misp >/dev/null 2>&1 || true
    # Fresh schema so the admin key (ADMIN_KEY) is applied at init.
    docker exec aptl-misp-db mysql -uroot -pmisp_root_password \
        -e 'DROP DATABASE IF EXISTS misp; CREATE DATABASE misp;' >/dev/null 2>&1 || true
    docker volume rm aptl_misp_config aptl_misp_data >/dev/null 2>&1 || true
    docker run -d --name aptl-misp --restart unless-stopped "${LBL_ARGS[@]}" \
        --network "$net" --network-alias aptl-misp --network-alias misp \
        -e MYSQL_HOST=misp-db -e MYSQL_DATABASE=misp -e MYSQL_USER=misp -e MYSQL_PASSWORD=misp_db_password \
        -e ADMIN_EMAIL=admin@admin.test -e ADMIN_PASSWORD=admin -e ADMIN_KEY="$MISP_API_KEY" \
        -e BASE_URL=https://localhost -e REDIS_HOST=misp-redis \
        -v aptl_misp_config:/var/www/MISP/app/Config -v aptl_misp_data:/var/www/MISP/app/files \
        -v "$CERT_BASE/misp/server.pem":/etc/nginx/certs/cert.pem:ro \
        -v "$CERT_BASE/misp/server.key":/etc/nginx/certs/key.pem:ro \
        "$img" >/dev/null
}

# --- shuffle-backend: restore opensearch env (incl. intra-cluster skip-ssl) --
fix_shuffle_backend() {
    _present aptl-shuffle-backend || return 0
    _has_env aptl-shuffle-backend SHUFFLE_OPENSEARCH_URL && return 0
    log "shuffle-backend missing opensearch env; recreating with working configuration"
    local img net
    img="$(_image aptl-shuffle-backend)"; net="$(_net aptl-shuffle-backend)"
    _capture_labels aptl-shuffle-backend
    docker rm -f aptl-shuffle-backend >/dev/null 2>&1 || true
    docker run -d --name aptl-shuffle-backend --restart unless-stopped "${LBL_ARGS[@]}" \
        --network "$net" --network-alias aptl-shuffle-backend --network-alias shuffle-backend \
        -e SHUFFLE_APP_SDK_TIMEOUT=120 \
        -e SHUFFLE_DEFAULT_USERNAME=admin -e SHUFFLE_DEFAULT_PASSWORD=ShuffleAdmin2024! \
        -e SHUFFLE_DEFAULT_APIKEY=31a211c4-ea5c-4a49-b022-5e2434e758a7 \
        -e SHUFFLE_OPENSEARCH_URL=https://shuffle-opensearch:9200 \
        -e SHUFFLE_OPENSEARCH_USERNAME=admin -e SHUFFLE_OPENSEARCH_PASSWORD=StrongPassword123! \
        -e SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY=true \
        -v aptl_shuffle_data:/shuffle-database -v /var/run/docker.sock:/var/run/docker.sock \
        "$img" >/dev/null
    # The frontend proxies to the backend; bounce it so it re-resolves the new one.
    docker restart aptl-shuffle-frontend >/dev/null 2>&1 || true
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
    log "WARNING: shuffle-backend not serving after 300s"
}

# --- MCP participant endpoints ----------------------------------------------
# The participant MCP servers connect to https://localhost:{8443 MISP, 9000
# TheHive, 3443 Shuffle} and verify strictly (verify_ssl + ca_cert_path
# lab-ca.pem). The env-pack publishes only wazuh 9200/55000 + dashboard 443, so
# those three MCP smoke checks (threatintel/cases/soar) have nothing to reach.
# The pre-#875 compose published all three on 127.0.0.1. Republish them with a
# small TLS-terminating socat proxy that serves a lab-CA localhost certificate
# (so verification passes) and forwards to each backend: MISP already serves a
# localhost-SAN lab cert (TCP passthrough); TheHive serves plain HTTP (terminate
# TLS, forward plaintext); Shuffle serves its own cert (terminate + re-originate,
# ignoring the backend cert). This restores documented plumbing without changing
# the access model or recreating the heavy TheHive/Shuffle-frontend containers.
fix_mcp_endpoints() {
    _present aptl-thehive || return 0
    local net cert key
    net="$(_net aptl-thehive)"
    cert="$CERT_BASE/misp/server.pem"   # lab-CA-signed, SAN includes localhost
    key="$CERT_BASE/misp/server.key"
    if [ ! -f "$cert" ] || [ ! -f "$key" ]; then
        log "localhost cert missing; skipping MCP endpoint proxy"; return 0
    fi
    log "publishing MCP HTTPS endpoints (MISP:8443, TheHive:9000, Shuffle:3443) via TLS proxy"
    docker rm -f aptl-mcp-endpoints >/dev/null 2>&1 || true
    local socat_script
    socat_script='socat TCP-LISTEN:8443,fork,reuseaddr TCP:misp:443 & socat OPENSSL-LISTEN:9000,fork,reuseaddr,cert=/certs/localhost.pem,key=/certs/localhost.key,verify=0 TCP:thehive:9000 & socat OPENSSL-LISTEN:3443,fork,reuseaddr,cert=/certs/localhost.pem,key=/certs/localhost.key,verify=0 OPENSSL-CONNECT:shuffle-frontend:443,verify=0 & wait'
    docker run -d --name aptl-mcp-endpoints --restart unless-stopped \
        --label com.docker.compose.project=aptl \
        --label com.docker.compose.service=mcp-endpoints \
        --network "$net" \
        -p 127.0.0.1:8443:8443 -p 127.0.0.1:9000:9000 -p 127.0.0.1:3443:3443 \
        -v "$cert":/certs/localhost.pem:ro -v "$key":/certs/localhost.key:ro \
        --entrypoint /bin/sh alpine/socat -c "$socat_script" >/dev/null
}

log "applying temporary env-pack SOAR fixups (see header for tracking issues)"
fix_misp_redis
fix_misp
fix_shuffle_backend
wait_misp
wait_shuffle
fix_mcp_endpoints
log "done"
