#!/usr/bin/env bash
set -euo pipefail

# SCN-010 / issue #344 — wazuh-sidecar-suricata steady-state asset inventory capture.
#
# The wazuh-sidecar-suricata asset is a *log-forwarding agent sidecar*: the same
# custom debian:12-slim image as wazuh-sidecar-db (aptl-wazuh-sidecar:local)
# running wazuh-agent 4.12.0, registered as aptl-suricata-agent. It has no
# inbound listener — it dials OUT to the Wazuh manager (1514/1515), reads the
# suricata container's EVE JSON log via a read-only bind of the shared
# aptl_suricata_logs volume at /logs, and ships /logs/eve.json with
# log_format json. Capture reflects that archetype (no listening-service probe
# surface; the manager connection and the read-only log source are recorded
# explicitly).
#
# The image is a local custom build, not a registry artifact, so build
# provenance is the repo Dockerfile + build-context inputs (source-checksums.txt),
# not a registry manifest digest. docker buildx imagetools inspect is attempted
# but expected to fail for the local-only tag; that is recorded as a limit.

ROOT="$(git rev-parse --show-toplevel)"
ASSET_DIR="$ROOT/docs/aces/inventory/wazuh-sidecar-suricata"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-wazuh-sidecar-suricata}"
MANAGER_CONTAINER="${MANAGER_CONTAINER:-aptl-wazuh-manager}"
IMAGE="${IMAGE:-aptl-wazuh-sidecar:local}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-aptl}"
COMPOSE_ENV_FILE="${COMPOSE_ENV_FILE:-$ROOT/.env}"

# Tool images are digest-pinned so reruns use the same scanner binaries even
# when floating tags move.
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6}"
OSQUERY_IMAGE="${OSQUERY_IMAGE:-osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd}"
SYFT_NORMALIZER="${SYFT_NORMALIZER:-$ASSET_DIR/normalize-syft-cyclonedx.jq}"

mkdir -p "$OUT"
: > "$OUT/capture-limits.txt"

record_limit() {
  printf -- '- %s\n' "$*" >> "$OUT/capture-limits.txt"
}

redact_stream() {
  sed -E \
    -e 's/(PASSWORD|PASS|SECRET|TOKEN|KEY|COOKIE|SESSION|PRIVATE_KEY|API_KEY|JWT|AUTHD_PASS)=([^[:space:]]+)/\1=<REDACTED>/Ig'
}

redact_env_jq='
  def redact_env:
    if contains("=") then
      capture("^(?<name>[^=]+)=(?<value>.*)$") as $m
      | if ($m.name | test("(PASSWORD|PASS|SECRET|TOKEN|KEY|COOKIE|SESSION|PRIVATE_KEY|API_KEY|JWT|AUTHD_PASS)$"; "i")) then
          "\($m.name)=<REDACTED-\($m.name | gsub("_"; "-"))>"
        else
          .
        end
    else
      .
    end;

  def redact_sensitive_keys:
    walk(
      if type == "object" then
        with_entries(
          if (.key | test("(password|pass|secret|token|key|cookie|session|private_key|api_key|jwt)$"; "i")) then
            .value = "<REDACTED>"
          else
            .
          end
        )
      else
        .
      end
    );
'

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

# The wazuh-sidecar-suricata compose block carries only plain env (WAZUH_MANAGER,
# AGENT_NAME, LOG_PATHS, LOG_FORMAT); it is extracted directly from
# docker-compose.yml with yq. A profile-filtered `docker compose config` cannot
# be used because the soc profile pulls in services that depend_on
# wazuh.manager and profile filtering invalidates the project.
yq -o=json '.services."wazuh-sidecar-suricata"' "$ROOT/docker-compose.yml" \
  | jq '
      if (has("environment") and (.environment | type == "array")) then
        .environment |= map(
          if test("^(?<name>[^=]+)=") then
            capture("^(?<name>[^=]+)=(?<value>.*)$") as $m
            | if ($m.name | test("(PASSWORD|PASS|SECRET|TOKEN|KEY|COOKIE|SESSION|PRIVATE_KEY|API_KEY|JWT|AUTHD_PASS)$"; "i"))
              then "\($m.name)=<REDACTED-\($m.name | gsub("_"; "-"))>"
              else .
              end
          else
            .
          end
        )
      else . end
    ' > "$OUT/compose-service.wazuh-sidecar-suricata.json"
record_limit "compose-service.wazuh-sidecar-suricata.json is the authored docker-compose.yml service block (yq-extracted); a profile-filtered docker compose config could not be used because soc-profile services depend_on wazuh.manager and profile filtering invalidates the project. The block carries only plain environment, so authored and resolved compose values coincide."

docker inspect "$CONTAINER" \
  | jq "$redact_env_jq .[].Config.Env |= ((. // []) | map(redact_env)) | redact_sensitive_keys" \
  > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" \
  | jq "$redact_env_jq redact_sensitive_keys" \
  > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" | redact_stream > "$OUT/docker-history.image.txt"
docker history --no-trunc --format '{{json .}}' "$IMAGE" | redact_stream > "$OUT/docker-history.image.jsonl"

if docker buildx imagetools inspect "$IMAGE" > "$OUT/docker-buildx-imagetools.image.txt" 2>"$OUT/docker-buildx-imagetools.image.err"; then
  docker buildx imagetools inspect "$IMAGE" --raw \
    | jq . > "$OUT/docker-buildx-imagetools.image.raw.json"
  rm -f "$OUT/docker-buildx-imagetools.image.err"
else
  record_limit "Docker Buildx imagetools inspection failed for $IMAGE because it is a locally built tag with no registry manifest; see docker-buildx-imagetools.image.err. Image identity is the local config ID in docker-inspect.image.json plus the build recipe in source-checksums.txt."
fi

docker network inspect aptl_aptl-security | jq . > "$OUT/docker-network.aptl-security.json"
docker volume inspect aptl_suricata_logs | jq . > "$OUT/docker-volume.suricata_logs.json"
docker top "$CONTAINER" | redact_stream > "$OUT/docker-top.txt"
docker logs "$CONTAINER" --tail 500 2>&1 | redact_stream > "$OUT/docker-logs.wazuh-sidecar-suricata.txt"

record_limit "Capture used the already-running aptl project (soc profile up) per operator direction and did not run aptl lab stop -v && aptl lab start; this bundle is a steady-state observation of that local lab, not a clean-reset rebuild proof."
record_limit "/logs is the shared aptl_suricata_logs volume (the suricata container's log directory) bind-mounted read-only. Only /logs/eve.json — the monitored log source — is recorded as path metadata here; the full log directory content (eve.json, suricata.log, stats.log, fast.log) is the suricata asset's content and is inventoried under docs/aces/inventory/suricata/, not duplicated or checksummed in this bundle."
record_limit "/var/ossec/etc/client.keys is the agent's manager-registration secret (shared key). It is recorded as path/metadata only; its content is excluded from checksums and never emitted (ADR-029)."
record_limit "/var/ossec/.ssh is the wazuh agentless SSH material directory; recorded as metadata only, content excluded from checksums."

# Build-recipe provenance: the Dockerfile and every build-context input it COPYs,
# plus the compose file. These are the source of the local image (no registry digest).
sha256sum \
  "$ROOT/docker-compose.yml" \
  "$ROOT/containers/wazuh-sidecar/Dockerfile" \
  "$ROOT/containers/_wazuh-agent/install.sh" \
  "$ROOT/containers/_wazuh-agent/wazuh-agent.sh" \
  "$ROOT/containers/_wazuh-agent/ossec.conf.template" \
  "$ROOT/containers/_wazuh-agent/aptl-firewall-drop.sh" \
  "$ROOT/config/wazuh_cluster/etc/lists/active-response-whitelist" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"

docker exec "$CONTAINER" dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' \
  | sort > "$OUT/os-packages.txt"

# No application language runtime is installed (wazuh-agent is C; the image trims
# curl/gnupg post-install). Record the relevant binary/tool versions and the
# absence of pip/npm/gem manifests for methodology completeness.
{
  printf "%s\n" "--no-application-language-runtime--"
  printf "%s\n" "wazuh-agent is a compiled C daemon set; the image ships no python/node/ruby/go application runtime. The helper tools below are the only interpreters/utilities present."
  printf "%s\n" "--wazuh-control-info--"
  docker exec "$CONTAINER" /var/ossec/bin/wazuh-control info 2>&1 || true
  printf "%s\n" "--tool-versions--"
  docker exec "$CONTAINER" sh -lc 'jq --version 2>&1; iptables --version 2>&1; nc -h 2>&1 | head -1; bash --version 2>&1 | head -1' || true
  printf "%s\n" "--pip/npm/gem--"
  docker exec "$CONTAINER" sh -lc 'command -v pip pip3 npm gem 2>&1 || echo "no pip/npm/gem on PATH"' || true
} > "$OUT/language-manifests.txt"

# Filesystem manifest: the agent install tree, the APTL bootstrap scripts, the
# wazuh apt source + signing key, and os-release. /logs (suricata log volume) is
# excluded (suricata asset content). client.keys and .ssh are classified secret
# and excluded from checksums below.
docker exec "$CONTAINER" sh -lc '
  set -eu
  roots="
    /var/ossec
    /opt/aptl/wazuh
    /etc/apt/sources.list.d/wazuh.list
    /usr/share/keyrings/wazuh.gpg
    /etc/os-release
  "
  for root in $roots; do
    [ -e "$root" ] || continue
    find "$root" -xdev \( -type f -o -type d -o -type l -o -type s -o -type p \) -print
  done \
    | sort -u \
    | while IFS= read -r path; do
        stability=stable
        sensitivity=plain
        case "$path" in
          /var/ossec/etc/client.keys)
            sensitivity=secret_fixture
            ;;
          /var/ossec/.ssh*)
            sensitivity=secret_fixture
            ;;
          /var/ossec/etc/ossec.conf)
            stability=runtime_created
            ;;
          /var/ossec/logs/*)
            stability=log
            ;;
          /var/ossec/queue/*|/var/ossec/var/*|/var/ossec/tmp/*)
            stability=runtime_created
            ;;
        esac
        stat -c "%F\t%A\t%a\t%u\t%U\t%g\t%G\t%s\t%Y\t${stability}\t${sensitivity}\t%n" "$path"
      done
' | gzip -n > "$OUT/filesystem-tree.txt.gz"

# Stable-content checksums over the config/install tree. Exclude the secret
# client.keys + .ssh, transient logs, runtime queue/var/tmp state, sockets, and
# pid files.
docker exec "$CONTAINER" sh -lc '
  set -eu
  roots="
    /var/ossec/etc
    /var/ossec/active-response
    /var/ossec/bin
    /var/ossec/ruleset
    /var/ossec/wodles
    /var/ossec/agentless
    /var/ossec/VERSION.json
    /opt/aptl/wazuh
    /etc/apt/sources.list.d/wazuh.list
    /usr/share/keyrings/wazuh.gpg
    /etc/os-release
  "
  for root in $roots; do
    [ -e "$root" ] || continue
    find "$root" -xdev -type f -print0
  done \
    | sort -zu \
    | grep -zEv "(/var/ossec/etc/client\.keys$|/var/ossec/\.ssh/|\.(sock|pid)$)" \
    | xargs -0 -r sha256sum
' | xz -9 -c > "$OUT/filesystem-checksums.txt.xz"

docker exec "$CONTAINER" sh -lc '
  set -eu
  printf "%s\n" --os-release--
  cat /etc/os-release 2>/dev/null || true
  printf "%s\n" --id--
  id
  printf "%s\n" --pwd--
  pwd
  printf "%s\n" --uname--
  uname -a
  printf "%s\n" --capabilities-pid1--
  grep "^Cap" /proc/1/status || true
  printf "%s\n" --environment--
  env | sort
  printf "%s\n" --listeners--
  (ss -lntup || netstat -lntup || true) 2>&1
  printf "%s\n" --outbound-connections--
  (ss -ntp || netstat -ntp || true) 2>&1
  printf "%s\n" --mounts--
  mount | sed -n "1,220p"
  printf "%s\n" --users--
  getent passwd | sed -n "1,260p" || true
  printf "%s\n" --groups--
  getent group | sed -n "1,260p" || true
  printf "%s\n" --sudoers--
  (cat /etc/sudoers 2>/dev/null; ls /etc/sudoers.d 2>/dev/null) || true
  printf "%s\n" --process-tree--
  ps -eo pid,ppid,user,args || true
  printf "%s\n" --wazuh-version--
  /var/ossec/bin/wazuh-control info 2>&1 || true
' | redact_stream > "$OUT/runtime-baseline.txt"

# Agent-specific state: rendered ossec.conf (manager addr / localfile / AR),
# control status, connection state to the manager, AR config, and the presence
# (not content) of client.keys.
docker exec "$CONTAINER" sh -lc '
  set -eu
  printf "%s\n" --wazuh-control-info--
  /var/ossec/bin/wazuh-control info 2>&1 || true
  printf "%s\n" --wazuh-control-status--
  /var/ossec/bin/wazuh-control status 2>&1 || true
  printf "%s\n" --ossec-conf--
  cat /var/ossec/etc/ossec.conf 2>&1 || true
  printf "%s\n" --agentd-state--
  cat /var/ossec/var/run/wazuh-agentd.state 2>&1 || true
  printf "%s\n" --client-keys-presence--
  if [ -s /var/ossec/etc/client.keys ]; then
    printf "client.keys present: %s line(s), %s bytes (content withheld)\n" "$(wc -l < /var/ossec/etc/client.keys)" "$(wc -c < /var/ossec/etc/client.keys)"
    awk "{print \$1, \$2, \$3}" /var/ossec/etc/client.keys 2>/dev/null || true
  else
    printf "client.keys absent or empty\n"
  fi
  printf "%s\n" --active-response-whitelist--
  cat /var/ossec/etc/lists/active-response-whitelist 2>&1 || true
  printf "%s\n" --active-response-bin--
  ls -la /var/ossec/active-response/bin 2>&1 || true
  printf "%s\n" --monitored-log-source--
  ls -la /logs/eve.json 2>&1 || true
  printf "%s\n" --internal-options--
  grep -vE "^#|^$" /var/ossec/etc/internal_options.conf 2>/dev/null | sed -n "1,60p" || true
  cat /var/ossec/etc/local_internal_options.conf 2>&1 || true
' | redact_stream > "$OUT/wazuh-agent-state.txt"

# Observer vantage: the Wazuh manager ingests from this agent. agent_control -l
# documents the registered agent (name, id, IP, status) — the realized form of
# the sidecar -> manager forwarding relationship.
if docker inspect "$MANAGER_CONTAINER" >/dev/null 2>&1; then
  docker exec "$MANAGER_CONTAINER" sh -lc '
    set +e
    printf "%s\n" --agent-list--
    /var/ossec/bin/agent_control -l 2>&1 | grep -iE "aptl-suricata-agent|Total|Wazuh"
    printf "%s\n" --agent-detail--
    id="$(/var/ossec/bin/agent_control -l 2>/dev/null | sed -n "s/^[[:space:]]*ID: \([0-9]*\),.*aptl-suricata-agent.*/\1/p" | head -1)"
    if [ -n "$id" ]; then /var/ossec/bin/agent_control -i "$id" 2>&1; else echo "aptl-suricata-agent id not resolved from agent_control -l"; fi
    true
  ' | redact_stream > "$OUT/observer-discovery.wazuh-manager.txt"
else
  record_limit "Wazuh manager observer-vantage discovery was skipped because $MANAGER_CONTAINER was not present."
  printf '%s container unavailable\n' "$MANAGER_CONTAINER" > "$OUT/observer-discovery.wazuh-manager.txt"
fi

# Attacker vantage: kali. The sidecar is on security-net only and publishes no
# host ports; record what an in-range attacker can resolve/reach.
if docker inspect aptl-kali >/dev/null 2>&1; then
  docker exec aptl-kali sh -lc '
    set +e
    printf "%s\n" --dns--
    getent hosts wazuh-sidecar-suricata aptl-wazuh-sidecar-suricata 172.20.0.36 2>&1
    printf "%s\n" --route-to-security-net--
    ip route get 172.20.0.36 2>&1
    printf "%s\n" --tcp-probe--
    timeout 8 sh -c "nc -vz -w 3 172.20.0.36 1514 2>&1; nc -vz -w 3 172.20.0.36 1515 2>&1" 2>&1
    printf "%s\n" --ping--
    ping -c 1 -W 2 172.20.0.36 2>&1 | sed -n "1,4p"
    true
  ' | redact_stream > "$OUT/participant-discovery.kali.txt"
else
  record_limit "Kali participant-vantage discovery was skipped because aptl-kali was not present."
  printf 'aptl-kali container unavailable\n' > "$OUT/participant-discovery.kali.txt"
fi

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" --version \
  > "$OUT/trivy-version.txt"

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" \
  image --format cyclonedx "$IMAGE" \
  | jq -c . \
  | gzip -n > "$OUT/trivy-sbom.cyclonedx.json.gz"

trivy_json="$(mktemp)"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" \
  image --format json --scanners vuln "$IMAGE" > "$trivy_json"
gzip -n -c "$trivy_json" > "$OUT/trivy-vulnerabilities.json.gz"
jq '
  [
    .Results[]?.Vulnerabilities[]?
    | {
        id: .VulnerabilityID,
        package_name: .PkgName,
        installed_version: .InstalledVersion,
        fixed_version: (.FixedVersion // ""),
        severity: .Severity,
        primary_url: (.PrimaryURL // ""),
        target: (.Target // null)
      }
  ]
' "$trivy_json" > "$OUT/trivy-vulnerability-list.json"
jq '
  group_by(.severity)
  | map({severity: .[0].severity, count: length})
' "$OUT/trivy-vulnerability-list.json" > "$OUT/trivy-vulnerability-counts.json"
rm -f "$trivy_json"

docker run --rm "$SYFT_IMAGE" version -o json | jq . > "$OUT/syft-version.json"

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$SYFT_IMAGE" \
  "docker:$IMAGE" \
  --output cyclonedx-json \
  --select-catalogers "-file-content-cataloger,-file-digest-cataloger,-file-executable-cataloger,-file-metadata-cataloger" \
  | jq -c -f "$SYFT_NORMALIZER" \
  | gzip -n > "$OUT/syft-sbom.cyclonedx.json.gz"
record_limit "Syft CycloneDX output was deterministically normalized by stripping syft:location:* properties; filesystem provenance is captured in filesystem-tree.txt.gz and filesystem-checksums.txt.xz."

docker run --rm "$OSQUERY_IMAGE" osqueryi --version > "$OUT/osquery-version.txt"
OSQUERY_TOOL="$(cat "$OUT/osquery-version.txt")"

write_osquery_json() {
  local output="$1"
  local table="$2"
  local query="$3"
  local vantage="$4"
  local mode="$5"
  local rows

  if [[ "$mode" == "container" ]]; then
    rows="$(docker run --rm --pid="container:$CONTAINER" --network="container:$CONTAINER" "$OSQUERY_IMAGE" osqueryi --json "$query")"
  else
    rows="$(docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$OSQUERY_IMAGE" osqueryi --json "$query")"
  fi

  jq -n \
    --arg table "$table" \
    --arg query "$query" \
    --arg tool "$OSQUERY_TOOL" \
    --arg vantage "$vantage" \
    --argjson rows "$rows" \
    '{table: $table, query: $query, tool: $tool, vantage: $vantage, status: "captured", rows: $rows}' \
    > "$output"
}

write_unavailable_osquery_json() {
  local output="$1"
  local table="$2"
  local query="$3"
  jq -n \
    --arg table "$table" \
    --arg query "$query" \
    --arg tool "$OSQUERY_TOOL" \
    --arg reason "osquery table $table is not present in the Linux osquery registry for the digest-pinned osquery 4.9.0 scanner image" \
    '{table: $table, query: $query, tool: $tool, vantage: "containerized osquery Linux image", status: "unavailable", reason: $reason, rows: []}' \
    > "$output"
}

write_osquery_json "$OUT/osquery-processes.json" processes \
  'select pid, name, path, cmdline, uid, gid, start_time from processes where name != "osqueryi" order by pid;' \
  "containerized osquery sharing aptl-wazuh-sidecar-suricata PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-wazuh-sidecar-suricata network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-wazuh-sidecar-suricata";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%aptl-wazuh-sidecar%";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-apt-sources.json" apt_sources \
  'select * from apt_sources order by name;' \
  "containerized osquery host-side view; target rootfs apt source parsing is not supported by this capture" docker

write_unavailable_osquery_json "$OUT/osquery-installed-applications.json" installed_applications \
  'select * from installed_applications;'

write_unavailable_osquery_json "$OUT/osquery-programs.json" programs \
  'select * from programs;'

{
  echo "- osquery installed_applications table unavailable in the digest-pinned Linux scanner image."
  echo "- osquery programs table unavailable in the digest-pinned Linux scanner image."
  echo "- osquery apt_sources reflects the host-side scanner vantage; the target rootfs wazuh apt source is captured directly in filesystem-tree.txt.gz and runtime-baseline.txt."
} >> "$OUT/capture-limits.txt"

sed -i 's/[[:space:]]\+$//' "$OUT"/*.txt

(
  cd "$ROOT"
  find docs/aces/inventory/wazuh-sidecar-suricata/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
