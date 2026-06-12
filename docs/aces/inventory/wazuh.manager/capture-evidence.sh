#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
ASSET_ID="wazuh.manager"
ASSET_DIR="$ROOT/docs/aces/inventory/$ASSET_ID"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-wazuh-manager}"
IMAGE="${IMAGE:-wazuh/wazuh-manager:4.12.0}"
COMPOSE_FILE="$ROOT/docker-compose.yml"
COMPOSE_SERVICE="wazuh.manager"
COMPOSE_PROFILES="${COMPOSE_PROFILES:-wazuh}"

TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6}"
OSQUERY_IMAGE="${OSQUERY_IMAGE:-osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd}"
SYFT_NORMALIZER="$ASSET_DIR/normalize-syft-cyclonedx.jq"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'required command missing: %s\n' "$1" >&2
    exit 2
  }
}

record_limit() {
  printf -- '- %s\n' "$*" >> "$OUT/capture-limits.txt"
}
write_json_status() {
  local output="$1"
  local table="$2"
  local query="$3"
  local status="$4"
  local reason="$5"
  jq -n \
    --arg table "$table" \
    --arg query "$query" \
    --arg tool "$OSQUERY_TOOL" \
    --arg status "$status" \
    --arg reason "$reason" \
    '{table: $table, query: $query, tool: $tool, vantage: "containerized osquery Linux image", status: $status, reason: $reason, rows: []}' \
    > "$output"
}

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

require docker
require gzip
require jq
require python3
require sha256sum
require tar

mkdir -p "$OUT"
: > "$OUT/capture-limits.txt"
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

record_limit "This capture used the existing running lab as authorized by the user on 2026-05-29 and did not run aptl lab stop -v && aptl lab start; it is a non-destructive frozen steady-state observation, not clean-lab rebuild proof."
record_limit "Wazuh API credentials, indexer credentials, cluster keys, API tokens, and private key checksums are retained as in-range scenario evidence."
record_limit "The Wazuh manager image does not include ss, netstat, ip, or mount; runtime evidence uses Docker inspect/network records and /proc/net/* listener fallback where in-container tooling is unavailable."

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

COMPOSE_PROFILES="$COMPOSE_PROFILES" docker compose -f "$COMPOSE_FILE" config --format json \
  | jq \
    --arg service "$COMPOSE_SERVICE" \
    '.services[$service]' > "$OUT/compose-service.wazuh.manager.json"

docker inspect "$CONTAINER" | jq . > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" | jq . > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" > "$OUT/docker-history.image.txt"
docker history --no-trunc --format '{{json .}}' "$IMAGE" > "$OUT/docker-history.image.jsonl"

if docker buildx imagetools inspect "$IMAGE" > "$OUT/docker-buildx-imagetools.image.txt" 2>"$OUT/docker-buildx-imagetools.image.err"; then
  docker buildx imagetools inspect "$IMAGE" --raw | jq . > "$OUT/docker-buildx-imagetools.image.raw.json"
  rm -f "$OUT/docker-buildx-imagetools.image.err"
else
  jq -n --arg image "$IMAGE" --arg status "unavailable" \
    '{image: $image, status: $status, manifest: null}' \
    > "$OUT/docker-buildx-imagetools.image.raw.json"
  record_limit "Docker Buildx imagetools inspection failed for $IMAGE; see docker-buildx-imagetools.image.err for non-secret tool stderr."
fi

docker network inspect aptl_aptl-security | jq . > "$OUT/docker-network.aptl-security.json"
docker network inspect aptl_aptl-dmz | jq . > "$OUT/docker-network.aptl-dmz.json"
docker network inspect aptl_aptl-internal | jq . > "$OUT/docker-network.aptl-internal.json"

docker volume inspect aptl_wazuh_api_configuration | jq . > "$OUT/docker-volume.wazuh-api-configuration.json"
docker volume inspect aptl_wazuh_etc | jq . > "$OUT/docker-volume.wazuh-etc.json"
docker volume inspect aptl_wazuh_logs | jq . > "$OUT/docker-volume.wazuh-logs.json"
docker volume inspect aptl_wazuh_queue | jq . > "$OUT/docker-volume.wazuh-queue.json"
docker volume inspect aptl_wazuh_var_multigroups | jq . > "$OUT/docker-volume.wazuh-var-multigroups.json"
docker volume inspect aptl_wazuh_integrations | jq . > "$OUT/docker-volume.wazuh-integrations.json"
docker volume inspect aptl_wazuh_active_response | jq . > "$OUT/docker-volume.wazuh-active-response.json"
docker volume inspect aptl_wazuh_agentless | jq . > "$OUT/docker-volume.wazuh-agentless.json"
docker volume inspect aptl_wazuh_wodles | jq . > "$OUT/docker-volume.wazuh-wodles.json"
docker volume inspect aptl_filebeat_etc | jq . > "$OUT/docker-volume.filebeat-etc.json"
docker volume inspect aptl_filebeat_var | jq . > "$OUT/docker-volume.filebeat-var.json"

docker top "$CONTAINER" > "$OUT/docker-top.txt"

sha256sum \
  "$ROOT/docker-compose.yml" \
  "$ROOT/config/wazuh_cluster/custom-shuffle" \
  "$ROOT/config/wazuh_cluster/filebeat_wazuh_module.yml" \
  "$ROOT/config/wazuh_indexer_ssl_certs/root-ca-manager.pem" \
  "$ROOT/config/wazuh_indexer_ssl_certs/wazuh.manager.pem" \
  "$ROOT/config/wazuh_indexer_ssl_certs/wazuh.manager-key.pem" \
  "$ROOT/config/wazuh_cluster/falco_rules.xml" \
  "$ROOT/config/wazuh_cluster/samba_decoders.xml" \
  "$ROOT/config/wazuh_cluster/postgresql_decoders.xml" \
  "$ROOT/config/wazuh_cluster/ad_rules.xml" \
  "$ROOT/config/wazuh_cluster/webapp_rules.xml" \
  "$ROOT/config/wazuh_cluster/suricata_rules.xml" \
  "$ROOT/config/wazuh_cluster/database_rules.xml" \
  "$ROOT/config/wazuh_cluster/patch-rule-path.py" \
  "$ROOT/.aptl/config/wazuh_cluster/wazuh_manager.conf" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"

docker exec "$CONTAINER" bash -lc '
  rpm -qa --qf "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n" | sort
' > "$OUT/os-packages.txt"

docker exec "$CONTAINER" bash -lc '
  set +e
  echo --python--
  /var/ossec/framework/python/bin/python3 --version 2>&1
  echo --pip-freeze--
  /var/ossec/framework/python/bin/python3 -m pip freeze 2>&1 | sort
  echo --filebeat--
  /usr/share/filebeat/bin/filebeat version 2>&1
  echo --wazuh--
  /var/ossec/bin/wazuh-control info 2>&1
' > "$OUT/language-manifests.txt"

docker exec "$CONTAINER" bash -lc '
  set +e
  echo --os-release--
  cat /etc/os-release
  echo --id--
  id
  echo --pwd--
  pwd
  echo --uname--
  uname -a
  echo --capabilities-pid1--
  grep "^Cap" /proc/1/status || true
  echo --environment--
  env | sort
  echo --listeners--
  (ss -lntup || netstat -lntup || cat /proc/net/tcp /proc/net/udp || true) 2>&1
  echo --network-addresses--
  ip addr show 2>&1 || true
  echo --routes--
  ip route show table all 2>&1 || true
  echo --dns--
  cat /etc/resolv.conf
  echo --hosts--
  cat /etc/hosts
  echo --hostname--
  cat /etc/hostname
  echo --mounts--
  mount | sed -n "1,240p"
  echo --users--
  getent passwd | sed -n "1,240p"
  echo --groups--
  getent group | sed -n "1,260p"
  echo --process-tree--
  ps -eo pid,ppid,user,args || true
' > "$OUT/runtime-baseline.txt"

docker exec "$CONTAINER" bash -lc '
  set +e
  echo --wazuh-info--
  /var/ossec/bin/wazuh-control info 2>&1
  echo --wazuh-status--
  /var/ossec/bin/wazuh-control status 2>&1
  echo --agent-groups--
  /var/ossec/bin/agent_groups -l 2>&1
  echo --agent-list--
  /var/ossec/bin/manage_agents -l 2>&1
  echo --rules-count--
  find /var/ossec/ruleset/rules /var/ossec/etc/rules -type f 2>/dev/null | wc -l
  echo --rules-files--
  find /var/ossec/ruleset/rules /var/ossec/etc/rules -type f 2>/dev/null | sort | sed -n "1,260p"
  echo --decoders-count--
  find /var/ossec/ruleset/decoders /var/ossec/etc/decoders -type f 2>/dev/null | wc -l
  echo --decoders-files--
  find /var/ossec/ruleset/decoders /var/ossec/etc/decoders -type f 2>/dev/null | sort | sed -n "1,260p"
  echo --active-response-files--
  find /var/ossec/active-response/bin -maxdepth 2 -type f 2>/dev/null | sort | sed -n "1,220p"
  echo --integrations-files--
  find /var/ossec/integrations -maxdepth 2 -type f 2>/dev/null | sort | sed -n "1,220p"
  echo --ossec-config--
  sed -n "1,260p" /var/ossec/etc/ossec.conf 2>/dev/null
  echo --filebeat-config--
  sed -n "1,220p" /etc/filebeat/filebeat.yml 2>/dev/null
' > "$OUT/wazuh-manager-state.txt"

docker exec "$CONTAINER" bash -lc '
  set +e
  curl -ks -i https://localhost:55000 2>&1 | sed -n "1,80p"
' \
  | jq -Rs '{vantage: "container localhost", command: "curl -ks -i https://localhost:55000", output: .}' \
  > "$OUT/wazuh-api-probe.json"

tmp_rules="$(mktemp -d)"
docker exec "$CONTAINER" tar -C / -cf - \
  var/ossec/ruleset/rules \
  var/ossec/etc/rules \
  var/ossec/ruleset/decoders \
  var/ossec/etc/decoders \
  | tar -C "$tmp_rules" -xf -
python3 "$ASSET_DIR/extract-wazuh-detection-definitions.py" \
  --root "$tmp_rules" \
  --rules-output "$OUT/wazuh-detection-definitions.rules.json.gz" \
  --decoders-output "$OUT/wazuh-detection-definitions.decoders.json.gz" \
  --summary-output "$OUT/wazuh-detection-definitions.summary.json"
rm -rf "$tmp_rules"

docker exec "$CONTAINER" bash -lc '
  set -euo pipefail
  roots="
    /etc/filebeat
    /var/lib/filebeat
    /var/log/filebeat
    /var/ossec/api/configuration
    /var/ossec/etc
    /var/ossec/logs
    /var/ossec/queue
    /var/ossec/var/multigroups
    /var/ossec/integrations
    /var/ossec/active-response/bin
    /var/ossec/agentless
    /var/ossec/wodles
    /tmp/filebeat-override.yml
    /etc/ssl/root-ca.pem
    /etc/ssl/filebeat.pem
    /etc/ssl/filebeat.key
    /wazuh-config-mount/etc/ossec.conf
    /docker-entrypoint-initdb.d/patch-rule-path.py
  "
  for root in $roots; do
    [ -e "$root" ] || continue
    find "$root" -xdev -maxdepth 6 \( -type f -o -type d -o -type l \) -print
  done | sort -u | while IFS= read -r path; do
    stat -c "%F %A %a %u %U %g %G %s %Y %n" "$path"
  done
' > "$OUT/filesystem-tree.txt"

docker exec "$CONTAINER" bash -lc '
  set -euo pipefail
  roots="
    /etc/filebeat
    /var/lib/filebeat
    /var/log/filebeat
    /var/ossec/api/configuration
    /var/ossec/etc
    /var/ossec/logs
    /var/ossec/queue
    /var/ossec/var/multigroups
    /var/ossec/integrations
    /var/ossec/active-response/bin
    /var/ossec/agentless
    /var/ossec/wodles
    /tmp/filebeat-override.yml
    /etc/ssl/root-ca.pem
    /etc/ssl/filebeat.pem
    /docker-entrypoint-initdb.d/patch-rule-path.py
  "
  for root in $roots; do
    [ -e "$root" ] || continue
    find "$root" -xdev -maxdepth 6 -type f -print
  done | sort -u | xargs -r sha256sum
' > "$OUT/filesystem-checksums.txt"

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" --version \
  > "$OUT/trivy-version.txt"

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" \
  image --format cyclonedx "$IMAGE" \
  | jq -c . \
  | gzip -n > "$OUT/trivy-sbom.cyclonedx.json.gz"

trivy_json="$(mktemp)"
trap 'rm -f "$trivy_json"' EXIT
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" \
  image --format json --scanners vuln "$IMAGE" > "$trivy_json"
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
jq 'group_by(.severity) | map({severity: .[0].severity, count: length})' \
  "$OUT/trivy-vulnerability-list.json" > "$OUT/trivy-vulnerability-counts.json"

docker run --rm "$SYFT_IMAGE" version -o json | jq . > "$OUT/syft-version.json"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$SYFT_IMAGE" \
  "docker:$IMAGE" \
  --output cyclonedx-json \
  --select-catalogers "-file-content-cataloger,-file-digest-cataloger,-file-executable-cataloger,-file-metadata-cataloger" \
  | jq -c -f "$SYFT_NORMALIZER" \
  | gzip -n > "$OUT/syft-sbom.cyclonedx.json.gz"
record_limit "Syft CycloneDX output was deterministically normalized by stripping syft:location:* properties; component identity remains and filesystem provenance is captured separately."
record_limit "Trivy and Syft CycloneDX SBOM evidence is committed as deterministic gzip-compressed minified JSON to satisfy the repository's added-file size gate; compression is lossless."

docker run --rm "$OSQUERY_IMAGE" osqueryi --version > "$OUT/osquery-version.txt"
OSQUERY_TOOL="$(cat "$OUT/osquery-version.txt")"

write_osquery_json "$OUT/osquery-processes.json" processes \
  'select pid, name, path, cmdline, uid, gid, start_time from processes where name != "osqueryi" order by pid;' \
  "containerized osquery sharing aptl-wazuh-manager PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-wazuh-manager network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-wazuh-manager";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%wazuh-manager%";' \
  "containerized osquery host-side Docker socket view" docker

write_json_status "$OUT/osquery-apt-sources.json" apt_sources \
  'select * from apt_sources order by name;' \
  "not_applicable" \
  "apt_sources is Debian/Ubuntu-specific and does not describe the Amazon Linux Wazuh manager target; RPM package state is captured by os-packages.txt and SBOM evidence."
record_limit "osquery apt_sources was not applicable for the Amazon Linux Wazuh manager target."

write_json_status "$OUT/osquery-installed-applications.json" installed_applications \
  'select * from installed_applications;' \
  "unavailable" \
  "osquery table installed_applications is not present in the Linux osquery registry for the digest-pinned osquery 4.9.0 scanner image"
record_limit "osquery installed_applications was unavailable in the digest-pinned Linux osquery scanner image."

write_json_status "$OUT/osquery-programs.json" programs \
  'select * from programs;' \
  "unavailable" \
  "osquery table programs is not present in the Linux osquery registry for the digest-pinned osquery 4.9.0 scanner image"
record_limit "osquery programs was unavailable in the digest-pinned Linux osquery scanner image."

(
  cd "$ROOT"
  find docs/aces/inventory/wazuh.manager/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
