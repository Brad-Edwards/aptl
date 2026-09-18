#!/bin/bash
# =============================================================================
# TEMPORARY env-pack SOAR fixups
# =============================================================================
# The frozen TechVault env-pack realizes parts of the SOC stack without the
# image-specific runtime contract they need, so they boot broken:
#
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
# The MISP and Redis branch is gone (Brad-Edwards/aptl#912). raes-env-packs
# 6.1.0 closed OpenRAE/env-packs#280: the pack now authors the cache
# authorization, MISP's database and cache bindings, and its canonical URL, so
# the runtime environment, the generated cache credential, and the leaf
# certificate's image-native placement are all admitted before realization and
# read back afterwards. Nothing about MISP is repaired here any more -- no
# container is recreated, no database is dropped, and no volume is removed.
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="${APTL_PROJECT_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
CERT_BASE="$PROJECT_DIR/config/soc_certs"

command -v docker >/dev/null 2>&1 || exit 0

_present()  { docker inspect "$1" >/dev/null 2>&1; }
_net()      { docker inspect "$1" -f '{{range $n,$c := .NetworkSettings.Networks}}{{$n}}{{end}}' 2>/dev/null; }
_image()    { docker inspect "$1" -f '{{.Config.Image}}' 2>/dev/null; }
_has_env()  { docker inspect "$1" -f '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -q "^$2="; }
_env_equals() {
    docker inspect "$1" -f '{{range .Config.Env}}{{println .}}{{end}}' \
        2>/dev/null | grep -Fxq "$2=$3"
}
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

# Return the TheHive connector env file selected by the current realized Compose
# model without exposing its value. Historical generated-environment files may
# remain after an artifact address changes; scanning that directory would mix
# prior realization state into the current one.
_thehive_cortex_env_file() {
    local root="$PROJECT_DIR/.aptl/realization/generated-environment"
    local model="$PROJECT_DIR/.aptl/realization/compose.stateful.yml"
    if [ -r "$model" ] && [ -d "$root" ]; then
        python3 - "$model" "$root" <<'PY'
import sys
from pathlib import Path

import yaml

model = Path(sys.argv[1])
root = Path(sys.argv[2]).resolve()
try:
    document = yaml.safe_load(model.read_text(encoding="utf-8")) or {}
    paths = document["services"]["thehive"]["env_file"]
except (KeyError, OSError, TypeError, yaml.YAMLError):
    raise SystemExit(1)
if not isinstance(paths, list) or len(paths) != 1:
    raise SystemExit(1)
candidate = Path(paths[0]).resolve()
try:
    candidate.relative_to(root)
    lines = candidate.read_text(encoding="utf-8").splitlines()
except (OSError, ValueError):
    raise SystemExit(1)
bindings = [line for line in lines if line.startswith("TH_CORTEX_KEYS=")]
if len(bindings) != 1 or not bindings[0].removeprefix("TH_CORTEX_KEYS="):
    raise SystemExit(1)
print(candidate)
PY
        return $?
    fi
    if [ -r "$PROJECT_DIR/config/cortex/thehive-cortex.env" ]; then
        printf '%s\n' "$PROJECT_DIR/config/cortex/thehive-cortex.env"
        return 0
    fi
    return 1
}

_thehive_cortex_env_matches() {
    local env_file="$1" expected observed
    expected="$(sed -n 's/^TH_CORTEX_KEYS=//p' "$env_file")"
    observed="$(docker inspect aptl-thehive -f \
        '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
        | sed -n 's/^TH_CORTEX_KEYS=//p')"
    [ -n "$expected" ] && [ "$observed" = "$expected" ]
}

# --- TheHive: activate the generated keystore and Play configuration --------
fix_thehive_tls() {
    _present aptl-thehive || return 0
    _capture_loopback_publication aptl-thehive 9000/tcp || return 1
    local publish="$CAPTURED_PUBLISH_ARG" expected="$CAPTURED_PUBLICATION"
    local host_port="${expected##*|}"
    local cortex_env
    if ! cortex_env="$(_thehive_cortex_env_file)"; then
        log "ERROR: TheHive must have exactly one realized Cortex connector env"
        return 1
    fi

    if _has_mount_target aptl-thehive /etc/thehive/application.conf \
        && _thehive_cortex_env_matches "$cortex_env"; then
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
        --env-file "$cortex_env" \
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
if ! fix_shuffle_frontend_tls; then
    exit 1
fi
if ! fix_thehive_tls; then
    exit 1
fi
if ! wait_shuffle; then
    exit 1
fi
log "done"
