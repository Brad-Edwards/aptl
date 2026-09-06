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
# the pre-ACES docker-compose.yml (which ran these services for months). The
# released pack also mounts the APTL Shuffle certificate at its governed
# artifact destination without configuring nginx to serve it, and the Wazuh
# image aborts its initialization before installing the mounted ossec.conf when
# its integration directory is mounted read-only. The bounded repairs below
# activate those already-declared inputs; they do not invent credentials or
# additional runtime nodes.
#
# Every repair is idempotent, so this is safe to run on every boot. It buys us
# out of the env-pack release cycle; it does not change the scenario.
#
# Root fixes tracked upstream (remove this script when they ship):
#   MISP  -> OpenRAE/env-packs#280 ; retire per Brad-Edwards/aptl#912
#   Shuffle TLS + Wazuh integration activation -> OpenRAE/env-packs#294
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
_mount_src() { docker inspect "$1" --format '{{range .Mounts}}{{if eq .Destination "'"$2"'"}}{{.Source}}{{end}}{{end}}' 2>/dev/null; }

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
    if _has_env aptl-misp MYSQL_HOST \
        && docker port aptl-misp 443/tcp 2>/dev/null | grep -q '^127\.0\.0\.1:8443$'; then
        return 0
    fi
    log "MISP runtime env or published API endpoint is incomplete; recreating"
    local img net initialize
    initialize=0
    _has_env aptl-misp MYSQL_HOST || initialize=1
    img="$(_image aptl-misp)"; net="$(_net aptl-misp)"
    _capture_labels aptl-misp
    docker rm -f aptl-misp >/dev/null 2>&1 || true
    if [ "$initialize" -eq 1 ]; then
        # Fresh schema so the admin key (ADMIN_KEY) is applied at init.
        docker exec aptl-misp-db mysql -uroot -pmisp_root_password \
            -e 'DROP DATABASE IF EXISTS misp; CREATE DATABASE misp;' >/dev/null 2>&1 || true
        docker volume rm aptl_misp_config aptl_misp_data >/dev/null 2>&1 || true
    fi
    docker run -d --name aptl-misp --restart unless-stopped "${LBL_ARGS[@]}" \
        --network "$net" --network-alias aptl-misp --network-alias misp \
        -p 127.0.0.1:8443:443 \
        -e MYSQL_HOST=misp-db -e MYSQL_DATABASE=misp -e MYSQL_USER=misp -e MYSQL_PASSWORD=misp_db_password \
        -e ADMIN_EMAIL=admin@admin.test -e ADMIN_PASSWORD=admin -e ADMIN_KEY="$MISP_API_KEY" \
        -e BASE_URL=https://localhost:8443 -e REDIS_HOST=misp-redis \
        -v aptl_misp_config:/var/www/MISP/app/Config -v aptl_misp_data:/var/www/MISP/app/files \
        -v "$CERT_BASE/misp/server.pem":/etc/nginx/certs/cert.pem:ro \
        -v "$CERT_BASE/misp/server.key":/etc/nginx/certs/key.pem:ro \
        "$img" >/dev/null
}

# --- Shuffle: serve the already-declared APTL certificate ------------------
fix_shuffle_tls() {
    _present aptl-shuffle-frontend || return 0
    # The pack delivers these governed artifacts at /opt/aptl/soc-certs, while
    # this immutable Shuffle image configures nginx's native certificate paths.
    # Copy only inside the ephemeral container and reload nginx; private bytes
    # never cross the container boundary or enter diagnostics.
    if docker exec aptl-shuffle-frontend sh -c \
        'cmp -s /opt/aptl/soc-certs/shuffle-frontend/server.pem /etc/nginx/fullchain.cert.pem && cmp -s /opt/aptl/soc-certs/shuffle-frontend/server.key /etc/nginx/privkey.pem' \
        >/dev/null 2>&1; then
        return 0
    fi
    log "activating the declared APTL certificate in Shuffle nginx"
    docker exec aptl-shuffle-frontend sh -c \
        'test -s /opt/aptl/soc-certs/shuffle-frontend/server.pem && test -s /opt/aptl/soc-certs/shuffle-frontend/server.key && cp /opt/aptl/soc-certs/shuffle-frontend/server.pem /etc/nginx/fullchain.cert.pem && cp /opt/aptl/soc-certs/shuffle-frontend/server.key /etc/nginx/privkey.pem && chmod 600 /etc/nginx/privkey.pem && nginx -s reload' \
        >/dev/null
}

# --- Wazuh: activate the mounted manager configuration ---------------------
fix_wazuh_integration_metadata() {
    _present aptl-wazuh-manager || return 0
    local src img host_uid host_gid
    src="$(_mount_src aptl-wazuh-manager /var/ossec/integrations)"
    # The only writable input to the helper is the pack artifact staged under
    # this project's owned realization tree. Refuse an unexpected bind source.
    case "$src" in
        "$PROJECT_DIR"/.aptl/realization/content/*) ;;
        *) log "unexpected Wazuh integration source; refusing metadata repair"; return 1 ;;
    esac
    img="$(_image aptl-wazuh-manager)"
    host_uid="$(id -u)"; host_gid="$(id -g)"
    log "normalizing the declared Wazuh integration metadata"
    # Exact pack archives use epoch-zero mtimes. Wazuh 4.12 treats mtime==0 as
    # "file not found", then independently requires root:wazuh/0750. A
    # network-isolated, read-only-root helper changes only that staged file's
    # metadata. The directory stays owned by the invoking user so the next
    # realization can remove it normally.
    docker run --rm --network none --read-only --entrypoint sh \
        -e APTL_HOST_UID="$host_uid" -e APTL_HOST_GID="$host_gid" \
        --mount "type=bind,src=$src,dst=/work" "$img" -c \
        'test -s /work/custom-shuffle && chown "$APTL_HOST_UID:$APTL_HOST_GID" /work && chmod 0755 /work && chown 0:999 /work/custom-shuffle && chmod 0750 /work/custom-shuffle && touch -t 200001010000 /work/custom-shuffle' \
        >/dev/null
}

fix_wazuh_manager_config() {
    _present aptl-wazuh-manager || return 0
    fix_wazuh_integration_metadata || return 1
    if docker exec aptl-wazuh-manager cmp -s \
        /wazuh-config-mount/etc/ossec.conf /var/ossec/etc/ossec.conf \
        >/dev/null 2>&1; then
        return 0
    fi
    log "activating the declared Wazuh manager configuration"
    # The read-only /var/ossec/integrations artifact makes the upstream image's
    # exclusion-copy phase fail before its later mount_files phase. Install the
    # already-mounted configuration with the image's native owner/mode, then
    # restart Wazuh services without replacing the admitted container.
    docker exec aptl-wazuh-manager sh -c \
        'test -s /wazuh-config-mount/etc/ossec.conf && install -o 0 -g 999 -m 0660 /wazuh-config-mount/etc/ossec.conf /var/ossec/etc/ossec.conf && /var/ossec/bin/wazuh-control restart' \
        >/dev/null
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

# env-packs 5.1 publishes TheHive and Shuffle directly. Older APTL revisions
# created an undeclared all-in-one proxy for those ports; remove it so runtime
# inventory remains exactly the scenario's declared node set. MISP's still-open
# upstream compatibility gap is handled on the declared MISP container above.
remove_legacy_mcp_proxy() {
    if _present aptl-mcp-endpoints; then
        log "removing obsolete MCP endpoint proxy"
        docker rm -f aptl-mcp-endpoints >/dev/null 2>&1 || true
    fi
}

log "applying temporary env-pack SOAR fixups (see header for tracking issues)"
remove_legacy_mcp_proxy
if ! fix_misp_redis; then
    exit 1
fi
if ! fix_misp; then
    exit 1
fi
if ! fix_shuffle_tls; then
    exit 1
fi
if ! fix_wazuh_manager_config; then
    exit 1
fi
wait_misp
if ! wait_shuffle; then
    exit 1
fi
log "done"
