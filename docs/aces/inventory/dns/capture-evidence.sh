#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
OUT="$ROOT/docs/aces/inventory/dns/evidence"
CONTAINER="${CONTAINER:-aptl-dns}"
IMAGE="${IMAGE:-aptl-dns:latest}"

# Tool images are digest-pinned so a later maintainer can rerun the same
# scanner binaries even when floating tags move.
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6}"
OSQUERY_IMAGE="${OSQUERY_IMAGE:-osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd}"

mkdir -p "$OUT"
: > "$OUT/capture-limits.txt"

record_limit() {
  printf -- "- %s\n" "$*" >> "$OUT/capture-limits.txt"
}

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

record_limit "Capture uses the already-running local lab and did not run aptl lab stop -v && aptl lab start; this is a steady-state observation, not clean-reset rebuild proof."

yq -o=json '.services.dns' "$ROOT/docker-compose.yml" \
  | jq . > "$OUT/compose-service.dns.json"

docker inspect "$CONTAINER" | jq . > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" | jq . > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" > "$OUT/docker-history.image.txt"
docker network inspect aptl_aptl-dmz | jq . > "$OUT/docker-network.aptl-dmz.json"
docker network inspect aptl_aptl-internal | jq . > "$OUT/docker-network.aptl-internal.json"
docker network inspect aptl_aptl-security | jq . > "$OUT/docker-network.aptl-security.json"
docker volume inspect aptl_dns_logs | jq . > "$OUT/docker-volume.dns-logs.json"
docker top "$CONTAINER" > "$OUT/docker-top.txt"

sha256sum \
  "$ROOT/containers/dns/Dockerfile" \
  "$ROOT/containers/dns/named.conf" \
  "$ROOT/containers/dns/supervisord.conf" \
  "$ROOT/containers/dns/zones/172.20.rev" \
  "$ROOT/containers/dns/zones/techvault.local.zone" \
  "$ROOT/containers/_wazuh-agent/install.sh" \
  "$ROOT/containers/_wazuh-agent/wazuh-agent.sh" \
  "$ROOT/containers/_wazuh-agent/ossec.conf.template" \
  "$ROOT/containers/_wazuh-agent/aptl-firewall-drop.sh" \
  "$ROOT/config/wazuh_cluster/etc/lists/active-response-whitelist" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"

docker exec "$CONTAINER" sh -lc '
  dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${Architecture}\n" | sort
' > "$OUT/os-packages.txt"

{
  echo "--bind-version--"
  docker exec "$CONTAINER" sh -lc "named -v"
  echo "--dig-version--"
  docker exec "$CONTAINER" sh -lc "dig -v"
  echo "--named-checkconf--"
  docker exec "$CONTAINER" sh -lc "named-checkconf -p /etc/bind/named.conf | sed -n '1,220p'"
  echo "--zone-techvault-local--"
  docker exec "$CONTAINER" sh -lc "named-checkzone techvault.local /etc/bind/zones/techvault.local.zone"
  echo "--zone-172-20-reverse--"
  docker exec "$CONTAINER" sh -lc "named-checkzone 20.172.in-addr.arpa /etc/bind/zones/172.20.rev"
} > "$OUT/language-manifests.txt"

docker exec "$CONTAINER" sh -lc '
  for path in \
    /etc/bind \
    /etc/bind/named.conf \
    /etc/bind/named.conf.default-zones \
    /etc/bind/named.conf.local \
    /etc/bind/named.conf.options \
    /etc/bind/zones \
    /etc/bind/zones/172.20.rev \
    /etc/bind/zones/techvault.local.zone \
    /etc/supervisor/conf.d/dns.conf \
    /opt/aptl/wazuh/ossec.conf.template \
    /opt/aptl/wazuh/wazuh-agent.sh \
    /var/log/named \
    /var/log/named/default.log \
    /var/log/named/query.log \
    /var/ossec/etc/ossec.conf \
    /etc/supervisor/conf.d \
    /opt/aptl/wazuh
  do
    stat -c "%A %U %G %s %n" "$path"
  done
' > "$OUT/filesystem-tree.txt"

docker exec "$CONTAINER" sh -lc '
  sha256sum \
    /etc/bind/named.conf \
    /etc/bind/named.conf.default-zones \
    /etc/bind/named.conf.local \
    /etc/bind/named.conf.options \
    /etc/bind/zones/172.20.rev \
    /etc/bind/zones/techvault.local.zone \
    /etc/supervisor/conf.d/dns.conf \
    /opt/aptl/wazuh/ossec.conf.template \
    /opt/aptl/wazuh/wazuh-agent.sh \
    /var/log/named/default.log \
    /var/log/named/query.log \
    /var/ossec/etc/ossec.conf
' > "$OUT/filesystem-checksums.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
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
  (ss -lntup || netstat -lntup || true) 2>&1
  echo --mounts--
  mount | sed -n "1,120p"
  echo --users--
  getent passwd | sed -n "1,160p"
  echo --groups--
  getent group | sed -n "1,120p"
  echo --supervisor--
  supervisorctl status || true
  echo --dns-soa--
  dig @localhost techvault.local SOA +short || true
  echo --dns-forward-records--
  dig @localhost techvault.local AXFR || true
  echo --dns-reverse-zone--
  dig @localhost 20.172.in-addr.arpa AXFR || true
  echo --process-tree--
  ps -eo pid,ppid,user,args \
    | awk '\''NR == 1 || ($0 !~ /sh -lc/ && $0 !~ /ps -eo pid,ppid,user,args/)'\'' \
    || true
' > "$OUT/runtime-baseline.txt"
sed -i 's/[[:space:]]\+$//' "$OUT/runtime-baseline.txt" "$OUT/docker-top.txt"

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" --version \
  > "$OUT/trivy-version.txt"

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" \
  image --format cyclonedx "$IMAGE" \
  | jq -c . > "$OUT/trivy-sbom.cyclonedx.json"

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
  | jq -c -f "$ROOT/docs/aces/inventory/dns/normalize-syft-cyclonedx.jq" \
    > "$OUT/syft-sbom.cyclonedx.json"
record_limit "Syft CycloneDX output was deterministically normalized by stripping syft:location:* properties; filesystem provenance is recorded in filesystem-tree.txt and filesystem-checksums.txt."

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
  "containerized osquery sharing aptl-dns PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-dns network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-dns";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%aptl-dns%";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-apt-sources.json" apt_sources \
  'select * from apt_sources order by name;' \
  "containerized osquery host-side view; target rootfs apt source parsing is not supported by this capture" docker

write_unavailable_osquery_json "$OUT/osquery-installed-applications.json" installed_applications \
  'select * from installed_applications;'
record_limit "osquery installed_applications was unavailable in the digest-pinned Linux osquery scanner image."

write_unavailable_osquery_json "$OUT/osquery-programs.json" programs \
  'select * from programs;'
record_limit "osquery programs was unavailable in the digest-pinned Linux osquery scanner image."

(
  cd "$ROOT"
  find docs/aces/inventory/dns/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
