#!/bin/bash
# =============================================================================
# TEMPORARY env-pack SOAR fixups
# =============================================================================
# The frozen TechVault env-pack realizes parts of the SOC stack without the
# image-specific runtime contract they need, so they boot broken:
#
#   - misp-redis runs with no password, but MISP connects with
#     auth=redispassword -> Redis unreachable -> API-key auth fails.
#   - MISP has no MYSQL_*/ADMIN_*/BASE_URL env and its lab cert is mounted at
#     the wrong path -> no DB, no admin key, self-signed cert.
#   - Shuffle and TheHive receive the generated SOC certificate bundle under
#     neutral /opt/aptl paths, but their pinned images only activate TLS from
#     /etc/nginx and /etc/thehive respectively.
# This recreates those containers with the configuration recovered from the
# pre-ACES docker-compose.yml (which ran these services for months). It
# preserves each realized image, network, labels, volumes, and host publication.
# A container already carrying the fix is left untouched, so this is safe to run
# on every boot. It buys us out of the env-pack release cycle; it does not change
# the scenario.
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
_has_mount_target() {
    docker inspect "$1" -f '{{range .Mounts}}{{println .Destination}}{{end}}' \
        2>/dev/null | grep -Fxq "$2"
}

_publications() {
    local container="$1" container_port="$2"
    docker inspect "$container" --format \
        "{{with (index .HostConfig.PortBindings \"$container_port\")}}{{range .}}{{println .HostIp .HostPort}}{{end}}{{end}}" \
        2>/dev/null
}

CAPTURED_PUBLISH_ARG=""
CAPTURED_PUBLICATION=""
_capture_loopback_publication() {
    local container="$1" container_port="$2"
    local host_ip host_port count=0
    CAPTURED_PUBLISH_ARG=""
    CAPTURED_PUBLICATION=""
    while read -r host_ip host_port; do
        [ -n "$host_ip" ] && [ -n "$host_port" ] || continue
        count=$((count + 1))
        if [ "$host_ip" != "127.0.0.1" ] \
            || ! [[ "$host_port" =~ ^[0-9]+$ ]] \
            || [ "$host_port" -lt 1 ] \
            || [ "$host_port" -gt 65535 ]; then
            log "ERROR: realized $container $container_port publication is not loopback TCP"
            return 1
        fi
        CAPTURED_PUBLISH_ARG="$host_ip:$host_port:${container_port%/tcp}/tcp"
        CAPTURED_PUBLICATION="$container_port|$host_ip|$host_port"
    done < <(_publications "$container" "$container_port")
    if [ "$count" -ne 1 ]; then
        log "ERROR: realized $container must publish $container_port exactly once"
        return 1
    fi
}

_verify_publications() {
    local container="$1" expected container_port host_ip host_port actual
    shift
    for expected in "$@"; do
        IFS='|' read -r container_port host_ip host_port <<< "$expected"
        actual="$(_publications "$container" "$container_port")"
        if [ "$actual" != "$host_ip $host_port" ]; then
            log "ERROR: replacement $container did not preserve $container_port publication"
            return 1
        fi
    done
}

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

verify_soc_tls() {
    local port="$1" path="$2"
    for _ in $(seq 1 120); do
        if curl --silent --show-error --fail \
            --cacert "$CERT_BASE/lab-ca.pem" \
            --connect-timeout 5 --max-time 10 \
            "https://localhost:$port$path" >/dev/null 2>&1; then
            return 0
        fi
        sleep 5
    done
    return 1
}

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
    docker run -d --name aptl-misp-redis --restart unless-stopped \
        "${LBL_ARGS[@]+"${LBL_ARGS[@]}"}" \
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
    if ! docker run -d --name aptl-misp --restart unless-stopped \
        "${LBL_ARGS[@]+"${LBL_ARGS[@]}"}" \
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

# --- Shuffle frontend: activate the generated certificate ------------------
fix_shuffle_frontend_tls() {
    _present aptl-shuffle-frontend || return 0
    _capture_loopback_publication aptl-shuffle-frontend 80/tcp || return 1
    local http_publish="$CAPTURED_PUBLISH_ARG" http_expected="$CAPTURED_PUBLICATION"
    _capture_loopback_publication aptl-shuffle-frontend 443/tcp || return 1
    local https_publish="$CAPTURED_PUBLISH_ARG" https_expected="$CAPTURED_PUBLICATION"
    local https_port="${https_expected##*|}"

    if _has_mount_target aptl-shuffle-frontend /etc/nginx/fullchain.cert.pem; then
        verify_soc_tls "$https_port" / || {
            log "ERROR: Shuffle frontend has authored TLS mounts but verification failed"
            return 1
        }
        return 0
    fi

    log "Shuffle frontend is not using the generated SOC certificate; recreating"
    local img net
    img="$(_image aptl-shuffle-frontend)"; net="$(_net aptl-shuffle-frontend)"
    _capture_labels aptl-shuffle-frontend
    docker rm -f aptl-shuffle-frontend >/dev/null 2>&1 || true
    if ! docker run -d --name aptl-shuffle-frontend --hostname shuffle-frontend \
        --restart unless-stopped "${LBL_ARGS[@]+"${LBL_ARGS[@]}"}" \
        --publish "$http_publish" --publish "$https_publish" \
        --network "$net" --network-alias aptl-shuffle-frontend --network-alias shuffle-frontend \
        -e BACKEND_HOSTNAME=shuffle-backend \
        -v "$CERT_BASE/shuffle-frontend/server.pem":/etc/nginx/fullchain.cert.pem:ro \
        -v "$CERT_BASE/shuffle-frontend/server.key":/etc/nginx/privkey.pem:ro \
        -v "$CERT_BASE/lab-ca.pem":/etc/lab-ca/lab-ca.pem:ro \
        --health-cmd 'curl -ksf https://localhost/ || exit 1' \
        --health-interval 30s --health-timeout 10s --health-retries 10 \
        --health-start-period 60s "$img" >/dev/null; then
        log "ERROR: replacement Shuffle frontend could not be started"
        return 1
    fi
    _verify_publications aptl-shuffle-frontend "$http_expected" "$https_expected" || return 1
    verify_soc_tls "$https_port" / || {
        log "ERROR: replacement Shuffle frontend failed SOC TLS verification"
        return 1
    }
    log "Shuffle frontend serves the generated SOC certificate"
}

# --- TheHive: activate the generated keystore and Play configuration --------
fix_thehive_tls() {
    _present aptl-thehive || return 0
    _capture_loopback_publication aptl-thehive 9000/tcp || return 1
    local publish="$CAPTURED_PUBLISH_ARG" expected="$CAPTURED_PUBLICATION"
    local host_port="${expected##*|}"

    if _has_mount_target aptl-thehive /etc/thehive/application.conf; then
        verify_soc_tls "$host_port" /api/status || {
            log "ERROR: TheHive has authored TLS mounts but verification failed"
            return 1
        }
        return 0
    fi

    log "TheHive is not using the generated SOC keystore; recreating"
    local img net source destination writable volume_count=0
    local -a volume_args=()
    img="$(_image aptl-thehive)"; net="$(_net aptl-thehive)"
    _capture_labels aptl-thehive
    while read -r source destination writable; do
        [ -n "$source" ] && [ -n "$destination" ] || continue
        volume_count=$((volume_count + 1))
        if [ "$writable" = "true" ]; then
            volume_args+=(-v "$source:$destination")
        else
            volume_args+=(-v "$source:$destination:ro")
        fi
    done < <(docker inspect aptl-thehive -f \
        '{{range .Mounts}}{{if eq .Type "volume"}}{{println .Name .Destination .RW}}{{end}}{{end}}' \
        2>/dev/null)
    if [ "$volume_count" -lt 1 ]; then
        log "ERROR: realized TheHive has no state volume to preserve"
        return 1
    fi

    docker rm -f aptl-thehive >/dev/null 2>&1 || true
    if ! docker run -d --name aptl-thehive --hostname thehive \
        --restart unless-stopped "${LBL_ARGS[@]+"${LBL_ARGS[@]}"}" \
        --publish "$publish" \
        --network "$net" --network-alias aptl-thehive --network-alias thehive \
        -e 'JVM_OPTS=-Xms512m -Xmx512m' \
        --env-file "$CERT_BASE/thehive/keystore.p12.password" \
        --env-file "$PROJECT_DIR/config/cortex/thehive-cortex.env" \
        "${volume_args[@]}" \
        -v "$CERT_BASE/thehive/keystore.p12":/etc/thehive/keystore.p12:ro \
        -v "$PROJECT_DIR/config/thehive/application.conf":/etc/thehive/application.conf:ro \
        -v "$CERT_BASE/lab-ca.pem":/etc/lab-ca/lab-ca.pem:ro \
        --health-cmd 'curl -ksf https://localhost:9000/api/status || exit 1' \
        --health-interval 30s --health-timeout 10s --health-retries 15 \
        --health-start-period 300s "$img" \
        --secret aptl-thehive-lab-secret-key-2024-purple \
        --cql-hostnames thehive-cassandra --index-backend lucene \
        --es-hostnames thehive-es --cortex-proto http \
        --cortex-hostnames cortex --cortex-port 9001 >/dev/null; then
        log "ERROR: replacement TheHive container could not be started"
        return 1
    fi
    _verify_publications aptl-thehive "$expected" || return 1
    verify_soc_tls "$host_port" /api/status || {
        log "ERROR: replacement TheHive failed SOC TLS verification"
        return 1
    }
    log "TheHive serves the generated SOC certificate"
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
if ! fix_shuffle_frontend_tls; then
    exit 1
fi
if ! fix_thehive_tls; then
    exit 1
fi
wait_misp
if ! wait_shuffle; then
    exit 1
fi
log "done"
