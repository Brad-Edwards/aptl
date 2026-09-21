#!/bin/bash
# =============================================================================
# TEMPORARY env-pack Suricata content fixups
# =============================================================================
# The frozen TechVault env-pack (post-#875 cutover) realizes the Suricata
# defensive content in a regressed form, so the sensor boots with no working
# detection:
#
#   - suricata-local-rules materializes as a HEADER-ONLY file (three comment
#     lines, zero rules) -> Suricata logs "0 signatures processed". The authored
#     46-rule local corpus (nmap, SQLi, XSS, command-injection, kerberoasting,
#     SMB brute force, lateral movement, LDAP enum, reverse-shell/C2, meterpreter)
#     never reaches the engine.
#   - suricata-config (suricata.yaml) declares only HOME_NET + EXTERNAL_NET in
#     its address-groups and no port-groups, but the authored rules reference
#     HTTP_SERVERS, HTTP_PORTS, INTERNAL_NET, and DMZ_NET -> ~10 rules fail to
#     load against undefined variables.
#
# This restores the authored local corpus and the full authored suricata.yaml
# (complete address-groups + port-groups and the rule-files list the env-pack
# stripped down; its eve-log outputs and command-socket path already match the
# realized config), then reloads Suricata. Source of truth is the in-tree
# authored config under config/suricata/ (the pre-ACES config this lab ran for
# months, and the same content the range seed carries). Idempotent:
# a file already carrying the full corpus / complete vars is left untouched, so
# it is safe on every boot. It buys us out of the env-pack release cycle; it
# does not change the scenario.
#
# Root fixes tracked upstream (remove this script when they ship):
#   env-pack ships full local.rules + complete suricata.yaml vars
#     -> OpenRAE/env-packs#<TBD> ; retire per Brad-Edwards/aptl#<TBD>
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="${APTL_PROJECT_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
SURICATA_CTR="${SURICATA_CONTAINER:-aptl-suricata}"
AUTHORED_RULES="$PROJECT_DIR/config/suricata/rules/local.rules"
AUTHORED_YAML="$PROJECT_DIR/config/suricata/suricata.yaml"

command -v docker >/dev/null 2>&1 || exit 0

log() { echo "[envpack-suricata-fixups] $*"; }

_present() { docker inspect "$1" >/dev/null 2>&1; }

# Host-side bind-mount source for a given in-container destination path.
_mount_src() {
    docker inspect "$1" \
        --format '{{range .Mounts}}{{if eq .Destination "'"$2"'"}}{{.Source}}{{end}}{{end}}' \
        2>/dev/null
}

# --- local.rules: restore the authored 46-rule corpus -----------------------
fix_local_rules() {
    local dest="/etc/suricata/rules/local.rules"
    local src
    src="$(_mount_src "$SURICATA_CTR" "$dest")"
    if [ -z "$src" ] || [ ! -e "$src" ]; then
        log "no bind-mount source for $dest; skipping local.rules restore"
        return 0
    fi
    if [ ! -r "$AUTHORED_RULES" ]; then
        log "authored rules missing at $AUTHORED_RULES; skipping"
        return 0
    fi
    # Idempotent: already restored if the active rule count matches authored.
    local want have
    want="$(grep -cE '^\s*(alert|drop|pass|reject)\b' "$AUTHORED_RULES")"
    have="$(grep -cE '^\s*(alert|drop|pass|reject)\b' "$src" 2>/dev/null || echo 0)"
    if [ "$have" = "$want" ]; then
        log "local.rules already carries $have rules; leaving untouched"
        return 0
    fi
    log "restoring authored local corpus ($want rules) into $src (was $have)"
    cat "$AUTHORED_RULES" > "$src"
}

# --- suricata.yaml: restore the full authored config ------------------------
fix_suricata_config() {
    local dest="/etc/suricata/suricata.yaml"
    local src
    src="$(_mount_src "$SURICATA_CTR" "$dest")"
    if [ -z "$src" ] || [ ! -e "$src" ]; then
        log "no bind-mount source for $dest; skipping config restore"
        return 0
    fi
    if [ ! -r "$AUTHORED_YAML" ]; then
        log "authored suricata.yaml missing at $AUTHORED_YAML; skipping"
        return 0
    fi
    # The env-pack materializes a stripped config: only HOME_NET/EXTERNAL_NET in
    # address-groups, no port-groups, and rule-files limited to local.rules. The
    # authored config is a superset -- complete address-groups + port-groups and
    # rule-files (suricata.rules ET corpus + local.rules + misp/misp-iocs.rules)
    # -- and its eve-log outputs + command-socket path match the realized ones,
    # so a full restore is safe (validated on-range) and loads the whole corpus.
    # Idempotent: a no-op once the bind already matches the authored config.
    if cmp -s "$AUTHORED_YAML" "$src"; then
        log "suricata.yaml already matches authored config; leaving untouched"
        return 0
    fi
    log "restoring full authored suricata.yaml (complete vars + rule-files) into $src"
    cat "$AUTHORED_YAML" > "$src"
}

# --- reload Suricata so the restored corpus + vars take effect --------------
reload_suricata() {
    # Prefer a live rule reload over the command socket (keeps flow state);
    # fall back to a container restart if the socket path is unavailable.
    if docker exec "$SURICATA_CTR" sh -c \
        'suricatasc -c reload-rules 2>/dev/null || suricatasc /var/run/suricata/suricata-command.socket -c reload-rules 2>/dev/null' \
        >/dev/null 2>&1; then
        log "reloaded rules over the command socket"
    else
        log "command-socket reload unavailable; restarting $SURICATA_CTR"
        docker restart "$SURICATA_CTR" >/dev/null 2>&1 || true
    fi
}

if ! _present "$SURICATA_CTR"; then
    log "no $SURICATA_CTR container present; nothing to fix up"
    exit 0
fi

log "applying temporary env-pack Suricata content fixups (see header for tracking issues)"
fix_local_rules
fix_suricata_config
reload_suricata
log "done"
