#!/usr/bin/env bash
set -euo pipefail

# SCN-010 / issue #351 — thehive-cassandra steady-state asset inventory capture.
#
# The thehive-cassandra asset is the Apache Cassandra 4.1 graph-storage
# backend for TheHive (cassandra:4.1, upstream registry image) running as
# aptl-thehive-cassandra on aptl-security. It exposes CQL on 9042 to the
# security network only (no host-published ports) and persists data in the
# thehive_cassandra_data volume at /var/lib/cassandra. The cluster name is
# "thehive" (CASSANDRA_CLUSTER_NAME) and authentication is the stock
# AllowAllAuthenticator default of the upstream image.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ASSET_DIR="$ROOT/docs/aces/inventory/thehive-cassandra"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-thehive-cassandra}"
IMAGE="${IMAGE:-cassandra:4.1}"
CONTAINER_IP="${CONTAINER_IP:-172.20.0.4}"

export PATH="$HOME/.local/bin:$PATH"

# Tool images are digest-pinned so reruns use the same scanner binaries even
# when floating tags move.
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6}"
OSQUERY_IMAGE="${OSQUERY_IMAGE:-osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd}"
SYFT_NORMALIZER="${SYFT_NORMALIZER:-$ASSET_DIR/normalize-syft-cyclonedx.jq}"
# Trivy vulnerability/Java DBs are cached in a named volume so the sequential
# SCN-010 captures download each DB once; the cache does not affect findings.
TRIVY_CACHE_VOLUME="${TRIVY_CACHE_VOLUME:-aptl-trivy-db-cache}"

mkdir -p "$OUT"
: > "$OUT/capture-limits.txt"

record_limit() {
  printf -- '- %s\n' "$*" >> "$OUT/capture-limits.txt"
}

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

# The thehive-cassandra compose block is extracted directly from
# docker-compose.yml with yq. A profile-filtered `docker compose config`
# cannot be used because the soc profile pulls in services that depend_on
# wazuh.manager and profile filtering invalidates the project.
yq -o=json '.services."thehive-cassandra"' "$ROOT/docker-compose.yml" | jq . > "$OUT/compose-service.thehive-cassandra.json"
record_limit "compose-service.thehive-cassandra.json is the authored docker-compose.yml service block (yq-extracted); a profile-filtered docker compose config could not be used because soc-profile services depend_on wazuh.manager and profile filtering invalidates the project."

docker inspect "$CONTAINER" | jq . > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" \
  | jq . > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" > "$OUT/docker-history.image.txt"
docker history --no-trunc --format '{{json .}}' "$IMAGE" > "$OUT/docker-history.image.jsonl"

if docker buildx imagetools inspect "$IMAGE" > "$OUT/docker-buildx-imagetools.image.txt" 2>"$OUT/docker-buildx-imagetools.image.err"; then
  docker buildx imagetools inspect "$IMAGE" --raw \
    | jq . > "$OUT/docker-buildx-imagetools.image.raw.json"
  rm -f "$OUT/docker-buildx-imagetools.image.err"
else
  rm -f "$OUT/docker-buildx-imagetools.image.txt"
  record_limit "Docker Buildx imagetools inspection failed for $IMAGE; see docker-buildx-imagetools.image.err for non-secret tool stderr. Image identity falls back to the local config ID in docker-inspect.image.json."
fi

docker network inspect aptl_aptl-security | jq . > "$OUT/docker-network.aptl-security.json"
docker volume inspect aptl_thehive_cassandra_data | jq . > "$OUT/docker-volume.thehive_cassandra_data.json"
docker top "$CONTAINER" > "$OUT/docker-top.txt"
docker logs "$CONTAINER" --tail 500 2>&1 > "$OUT/docker-logs.thehive-cassandra.txt"

record_limit "Capture used the already-running aptl project (soc profile up) per operator direction and did not run aptl lab stop -v && aptl lab start; this bundle is a steady-state observation of that local lab, not a clean-reset rebuild proof."
record_limit "thehive_cassandra_data volume contents (/var/lib/cassandra: commitlog, data, hints, saved_caches) are runtime database state and out of manifest scope; only top-level directory rows are recorded in filesystem-tree.txt.gz. Schema-level database state is captured in cassandra-state.txt instead."

# Build provenance: no repo-authored bind files exist for this service; the
# compose file is the only authored input.
sha256sum \
  "$ROOT/docker-compose.yml" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"
record_limit "source-checksums.txt covers only docker-compose.yml; the thehive-cassandra service has no repo-authored bind files (configuration is upstream-image defaults plus compose environment)."

docker exec "$CONTAINER" sh -lc "dpkg-query -W -f='\${binary:Package}\t\${Version}\t\${Architecture}\n'" \
  | sort > "$OUT/os-packages.txt"

# Java application runtime: the bundled JRE runs Cassandra.
{
  printf "%s\n" "--java-version--"
  docker exec "$CONTAINER" java -version 2>&1 || true
  printf "%s\n" "--java-home--"
  docker exec "$CONTAINER" sh -lc 'command -v java && readlink -f "$(command -v java)"' 2>&1 || true
  printf "%s\n" "--cassandra-version--"
  docker exec "$CONTAINER" sh -lc '/opt/cassandra/bin/cassandra -v 2>/dev/null || /opt/cassandra/bin/nodetool version' 2>&1 || true
  printf "%s\n" "--python-cqlsh-runtime--"
  docker exec "$CONTAINER" sh -lc 'python3 --version 2>&1; head -1 /opt/cassandra/bin/cqlsh' 2>&1 || true
  printf "%s\n" "--pip-npm-presence--"
  docker exec "$CONTAINER" sh -lc 'for t in pip pip3 node npm; do if command -v "$t" >/dev/null 2>&1; then printf "%s present: %s\n" "$t" "$(command -v "$t")"; else printf "%s absent\n" "$t"; fi; done' 2>&1 || true
} > "$OUT/language-manifests.txt"

# Filesystem manifest: the Cassandra config and install trees, os-release, and
# top-level rows only for the volume-backed /var/lib/cassandra data tree.
docker exec "$CONTAINER" sh -lc '
  set -eu
  {
    for root in /etc/cassandra /opt/cassandra /etc/os-release; do
      [ -e "$root" ] || continue
      find "$root" -xdev \( -type f -o -type d -o -type l -o -type s -o -type p \) -print
    done
    if [ -d /var/lib/cassandra ]; then
      find /var/lib/cassandra -maxdepth 1 -xdev \( -type d -o -type l \) -print
    fi
  } \
    | grep -Ev "/__pycache__(/|$)" \
    | sort -u \
    | while IFS= read -r path; do
        stability=stable
        sensitivity=plain
        case "$path" in
          /var/lib/cassandra*)
            stability=runtime_created
            ;;
        esac
        stat -c "%F\t%A\t%a\t%u\t%U\t%g\t%G\t%s\t%Y\t${stability}\t${sensitivity}\t%n" "$path"
      done
' | gzip -n > "$OUT/filesystem-tree.txt.gz"
record_limit "filesystem-tree.txt.gz scopes the manifest to the application surfaces (/etc/cassandra config, /opt/cassandra install, /etc/os-release) plus top-level directory rows for the volume-backed /var/lib/cassandra tree, excluding __pycache__ bytecode; volume runtime data content is out of manifest scope."

# Stable-content checksums over the config and install trees. /opt/cassandra
# data and logs entries are symlinks into runtime trees and are not followed.
docker exec "$CONTAINER" sh -lc '
  set -eu
  for root in /etc/cassandra /opt/cassandra; do
    [ -e "$root" ] || continue
    find "$root" -xdev -type f -print0
  done \
    | sort -zu \
    | grep -zEv "/__pycache__/" \
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
  (ss -lntup || netstat -lntup || cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp || true) 2>&1
  printf "%s\n" --outbound-connections--
  (ss -ntp || netstat -ntp || cat /proc/net/tcp /proc/net/tcp6 || true) 2>&1
  printf "%s\n" --mounts--
  mount | sed -n "1,220p"
  printf "%s\n" --users--
  getent passwd | sed -n "1,260p" || true
  printf "%s\n" --groups--
  getent group | sed -n "1,260p" || true
  printf "%s\n" --sudoers--
  (cat /etc/sudoers 2>/dev/null; ls /etc/sudoers.d 2>/dev/null) || true
  printf "%s\n" --process-tree--
  (ps -eo pid,ppid,user,args || for p in /proc/[0-9]*; do printf "%s %s\n" "${p#/proc/}" "$(tr "\0" " " < "$p/cmdline" 2>/dev/null)"; done) 2>&1
' > "$OUT/runtime-baseline.txt"

# Service-specific state: cluster membership, node info, CQL-visible cluster
# identity and keyspaces.
{
  printf "%s\n" --nodetool-status--
	  docker exec "$CONTAINER" /opt/cassandra/bin/nodetool status 2>&1 || true
	  printf "%s\n" --nodetool-info--
	  docker exec "$CONTAINER" /opt/cassandra/bin/nodetool info 2>&1 | sed -n "1,30p" || true
	  printf "%s\n" --cqlsh-describe-cluster--
	  docker exec "$CONTAINER" /opt/cassandra/bin/cqlsh -e "describe cluster" 2>&1 || true
	  printf "%s\n" --cqlsh-describe-keyspaces--
	  docker exec "$CONTAINER" /opt/cassandra/bin/cqlsh -e "describe keyspaces" 2>&1 || true
	  printf "%s\n" --cqlsh-system-local--
	  docker exec "$CONTAINER" /opt/cassandra/bin/cqlsh -e "SELECT cluster_name, release_version FROM system.local;" 2>&1 || true
} > "$OUT/cassandra-state.txt"

# Per-keyspace replication strategy + factor (system_schema.keyspaces). Needed to
# characterise the wide-column data distribution: the thehive keyspace and the
# SimpleStrategy system keyspaces carry a replication_factor; the LocalStrategy
# (system, system_schema) and virtual (system_virtual_schema, system_views)
# keyspaces are node-local/virtual and carry no replication factor.
docker exec "$CONTAINER" /opt/cassandra/bin/cqlsh -e "SELECT keyspace_name, durable_writes, replication FROM system_schema.keyspaces;" \
  2>&1 > "$OUT/cassandra-keyspaces.txt" || true
record_limit "The LocalStrategy keyspaces (system, system_schema) and virtual keyspaces (system_virtual_schema, system_views) carry no replication_factor and are Cassandra engine-internal catalogs; they are recorded in cassandra-keyspaces.txt evidence but are not encoded as wide_column keyspace partitions (the profile models replicated keyspaces). The participant-relevant thehive keyspace and the replicated SimpleStrategy system keyspaces are encoded as partitions."

# Attacker vantage: kali. Cassandra is on security-net only and publishes no
# host ports; record what an in-range attacker can resolve/reach on CQL 9042.
if docker inspect aptl-kali >/dev/null 2>&1; then
  docker exec aptl-kali sh -lc '
    set +e
    printf "%s\n" --dns--
    getent hosts thehive-cassandra aptl-thehive-cassandra '"$CONTAINER_IP"' 2>&1
    printf "%s\n" --route-to-security-net--
    ip route get '"$CONTAINER_IP"' 2>&1
    printf "%s\n" --tcp-probe--
    timeout 8 sh -c "nc -vz -w 3 '"$CONTAINER_IP"' 9042 2>&1" 2>&1
    printf "%s\n" --ping--
    ping -c 1 -W 2 '"$CONTAINER_IP"' 2>&1 | sed -n "1,4p"
    true
  ' > "$OUT/participant-discovery.kali.txt"
else
  record_limit "Kali participant-vantage discovery was skipped because aptl-kali was not present."
  printf 'aptl-kali container unavailable\n' > "$OUT/participant-discovery.kali.txt"
fi

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$TRIVY_CACHE_VOLUME:/root/.cache/trivy" "$TRIVY_IMAGE" --version \
  > "$OUT/trivy-version.txt"

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$TRIVY_CACHE_VOLUME:/root/.cache/trivy" "$TRIVY_IMAGE" \
  image --format cyclonedx "$IMAGE" \
  | jq -c . \
  | gzip -n > "$OUT/trivy-sbom.cyclonedx.json.gz"

trivy_json="$(mktemp)"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$TRIVY_CACHE_VOLUME:/root/.cache/trivy" "$TRIVY_IMAGE" \
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
record_limit "Trivy and Syft CycloneDX SBOM evidence is committed as deterministic gzip-compressed minified JSON to satisfy the repository's added-file size gate; compression is lossless."

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
  "containerized osquery sharing aptl-thehive-cassandra PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-thehive-cassandra network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-thehive-cassandra";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%cassandra:4.1%";' \
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
  echo "- osquery apt_sources reflects the host-side scanner vantage; the target rootfs Debian apt state is captured directly in os-packages.txt."
} >> "$OUT/capture-limits.txt"

sed -i 's/[[:space:]]\+$//' "$OUT"/*.txt

(
  cd "$ROOT"
  find docs/aces/inventory/thehive-cassandra/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
