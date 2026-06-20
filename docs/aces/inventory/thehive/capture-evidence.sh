#!/usr/bin/env bash
set -euo pipefail

# SCN-010 / issue #350 — thehive steady-state asset inventory capture.
#
# The thehive asset is the TheHive 5.4 case-management platform
# (strangebee/thehive:5.4, upstream registry image) running as aptl-thehive on
# aptl-security (172.20.0.18) with host-published port 9000:9000 (HTTPS,
# lab-CA-signed keystore per SEC-006 / ADR-034). It persists graph data via
# Cassandra (thehive-cassandra) and full-text index via Elasticsearch
# (thehive-es); local volumes thehive_data and thehive_index back
# /opt/thp/thehive/{data,index}.
#
# The compose command carries "--secret aptl-thehive-lab-secret-key-2024-purple",
# a committed scenario fixture visible in docker-compose.yml. It is retained
# as authored scenario content (secret_fixture, not an operator secret) in the
# compose-service extraction and the container inspect Cmd/Args.
#
# The lab-CA-signed TLS keystore /etc/thehive/keystore.p12 and its env_file
# password (HTTPS_KEYSTORE_PASSWORD) are generated scenario lab material. They
# are retained verbatim in capture evidence because they are scenario target
# content.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ASSET_DIR="$ROOT/docs/aces/inventory/thehive"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-thehive}"
IMAGE="${IMAGE:-strangebee/thehive:5.4}"
CONTAINER_IP="${CONTAINER_IP:-172.20.0.18}"

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

# The thehive compose block is extracted directly from docker-compose.yml with
# yq. A profile-filtered `docker compose config` cannot be used because the
# soc profile pulls in services that depend_on wazuh.manager and profile
# filtering invalidates the project.
yq -o=json '.services.thehive' "$ROOT/docker-compose.yml" | jq . > "$OUT/compose-service.thehive.json"
record_limit "compose-service.thehive.json is the authored docker-compose.yml service block (yq-extracted); a profile-filtered docker compose config could not be used because soc-profile services depend_on wazuh.manager and profile filtering invalidates the project. The authored command retains the committed scenario fixture '--secret aptl-thehive-lab-secret-key-2024-purple' (secret_fixture, visible in docker-compose.yml), not an operator secret."

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
docker volume inspect aptl_thehive_data | jq . > "$OUT/docker-volume.thehive_data.json"
docker volume inspect aptl_thehive_index | jq . > "$OUT/docker-volume.thehive_index.json"
docker top "$CONTAINER" > "$OUT/docker-top.txt"
docker logs "$CONTAINER" --tail 500 2>&1 > "$OUT/docker-logs.thehive.txt"

record_limit "Capture used the already-running aptl project (soc profile up) per operator direction and did not run aptl lab stop -v && aptl lab start; this bundle is a steady-state observation of that local lab, not a clean-reset rebuild proof."
record_limit "/etc/thehive/keystore.p12 is the lab-CA-signed TLS keystore generated at aptl lab start; it is scenario fixture material and is included in filesystem metadata and checksum evidence."
record_limit "config/soc_certs/thehive/keystore.p12.password injects HTTPS_KEYSTORE_PASSWORD into the runtime environment; the live value is captured verbatim in docker-inspect.container.json and runtime-baseline.txt."
record_limit "thehive_data and thehive_index volume contents (/opt/thp/thehive/data, /opt/thp/thehive/index) are runtime data and out of manifest scope; only top-level directory rows are recorded in filesystem-tree.txt.gz and a top-level ls in thehive-state.txt."
record_limit "The entrypoint-generated /tmp/thehive-*.conf Play configuration (assembled at start from the compose command args, including the committed --secret scenario fixture) is runtime-created and out of manifest scope; its authored inputs are the compose command and /etc/thehive/application.conf."
record_limit "The TheHive image does not include ss, netstat, or ps; listener and connection evidence falls back to raw /proc/net/tcp,tcp6,udp tables and the process tree to a /proc PID walk, complemented by docker top and osquery namespace-sharing evidence."

# Build provenance for the authored binds and generated lab TLS inputs available
# in this checkout.
source_inputs=(
  "$ROOT/docker-compose.yml"
  "$ROOT/config/thehive/application.conf"
)
for generated_input in \
  "$ROOT/config/soc_certs/lab-ca.pem" \
  "$ROOT/config/soc_certs/thehive/keystore.p12" \
  "$ROOT/config/soc_certs/thehive/keystore.p12.password"; do
  if [[ -f "$generated_input" ]]; then
    source_inputs+=("$generated_input")
  else
    record_limit "${generated_input#$ROOT/} is not present in this checkout; the running container bind/env value is captured from Docker/runtime evidence."
  fi
done
sha256sum "${source_inputs[@]}" | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"
record_limit "source-checksums.txt covers the compose file, TheHive application.conf overlay, lab CA certificate, and any generated TheHive TLS source inputs present in this checkout; missing generated inputs are paired with runtime Docker/container evidence."

docker exec "$CONTAINER" sh -lc "dpkg-query -W -f='\${binary:Package}\t\${Version}\t\${Architecture}\n'" \
  | sort > "$OUT/os-packages.txt"

# Java application runtime: the bundled Amazon Corretto JVM runs TheHive.
{
  printf "%s\n" "--java-version--"
  docker exec "$CONTAINER" java -version 2>&1 || true
  printf "%s\n" "--java-home--"
  docker exec "$CONTAINER" sh -lc 'command -v java && readlink -f "$(command -v java)"' 2>&1 || true
  printf "%s\n" "--thehive-jars--"
  docker exec "$CONTAINER" sh -lc 'ls /opt/thehive/lib | grep -E "^org\.thp\." | sed -n "1,40p"' 2>&1 || true
  printf "%s\n" "--pip-npm-presence--"
  docker exec "$CONTAINER" sh -lc 'for t in python3 pip pip3 node npm; do if command -v "$t" >/dev/null 2>&1; then printf "%s present: %s\n" "$t" "$(command -v "$t")"; else printf "%s absent\n" "$t"; fi; done' 2>&1 || true
} > "$OUT/language-manifests.txt"

# Filesystem manifest: the TheHive install (/opt/thehive), the mounted config
# and CA trust inputs, os-release, and top-level rows only for the
# volume-backed /opt/thp data/index tree.
docker exec "$CONTAINER" sh -lc '
  set -eu
  {
    for root in /opt/thehive /etc/thehive /etc/lab-ca /etc/os-release; do
      [ -e "$root" ] || continue
      find "$root" -xdev \( -type f -o -type d -o -type l -o -type s -o -type p \) -print
    done
    if [ -d /opt/thp ]; then
      find /opt/thp -maxdepth 2 -xdev \( -type d -o -type l \) -print
    fi
  } \
    | sort -u \
    | while IFS= read -r path; do
        stability=stable
        sensitivity=plain
        case "$path" in
          /opt/thp/thehive/data*|/opt/thp/thehive/index*)
            stability=runtime_created
            ;;
        esac
        case "$path" in
          /etc/thehive/keystore.p12)
            sensitivity=secret_fixture
            ;;
        esac
        stat -c "%F\t%A\t%a\t%u\t%U\t%g\t%G\t%s\t%Y\t${stability}\t${sensitivity}\t%n" "$path"
      done
' | gzip -n > "$OUT/filesystem-tree.txt.gz"
record_limit "filesystem-tree.txt.gz scopes the manifest to the application surfaces (/opt/thehive install, /etc/thehive config mounts, /etc/lab-ca trust input, /etc/os-release) plus top-level directory rows for the volume-backed /opt/thp tree; volume runtime data content is out of manifest scope."

# Stable-content checksums over the install, mounted config, keystore, and CA
# input.
docker exec "$CONTAINER" sh -lc '
  set -eu
  for root in /opt/thehive /etc/thehive /etc/lab-ca; do
    [ -e "$root" ] || continue
    find "$root" -xdev -type f -print0
  done \
    | sort -zu \
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

# Service-specific state: API status over the lab-CA HTTPS listener, the
# mounted application.conf overlay, top-level data
# and index directory listings, and JVM process identity.
{
  printf "%s\n" --api-status--
  docker exec "$CONTAINER" curl -ks https://localhost:9000/api/status 2>&1 || true
  printf "\n%s\n" --application-conf--
  docker exec "$CONTAINER" cat /etc/thehive/application.conf 2>&1 || true
  printf "%s\n" --data-dir-top-level--
  docker exec "$CONTAINER" ls -la /opt/thp/thehive/data 2>&1 || true
  printf "%s\n" --index-dir-top-level--
  docker exec "$CONTAINER" ls -la /opt/thp/thehive/index 2>&1 || true
  printf "%s\n" --jvm-java-version--
  docker exec "$CONTAINER" java -version 2>&1 || true
  printf "%s\n" --jvm-pid1-cmdline--
  docker exec "$CONTAINER" sh -lc 'tr "\0" "\n" < /proc/1/cmdline' 2>&1 || true
  printf "%s\n" --jvm-pid1-status--
  docker exec "$CONTAINER" sh -lc 'grep -E "^(Name|Pid|PPid|Uid|Gid|Threads|VmSize|VmRSS):" /proc/1/status' 2>&1 || true
  # Rendered search-index backend: confirms the --index-backend lucene command
  # arg took effect (TheHive indexes in local Lucene at /data/index, not in the
  # deployed thehive-es Elasticsearch — which it does not use).
  printf "%s\n" --rendered-index-backend--
  docker exec "$CONTAINER" sh -lc 'grep -hE "index.search" /tmp/thehive-*.conf 2>/dev/null' 2>&1 || true
} > "$OUT/thehive-state.txt"

# Attacker vantage: kali. TheHive listens on 9000 (HTTPS) on aptl-security and
# the port is host-published; record what an in-range attacker can
# resolve/reach, including the host-published listener via the gateway.
if docker inspect aptl-kali >/dev/null 2>&1; then
  docker exec aptl-kali sh -lc '
    set +e
    printf "%s\n" --dns--
    getent hosts thehive aptl-thehive '"$CONTAINER_IP"' 2>&1
    printf "%s\n" --route-to-security-net--
    ip route get '"$CONTAINER_IP"' 2>&1
    printf "%s\n" --tcp-probe--
    timeout 8 sh -c "nc -vz -w 3 '"$CONTAINER_IP"' 9000 2>&1" 2>&1
    printf "%s\n" --host-published-probe--
    timeout 8 sh -c "nc -vz -w 3 172.20.0.1 9000 2>&1" 2>&1
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
  "containerized osquery sharing aptl-thehive PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-thehive network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-thehive";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%strangebee/thehive%";' \
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
  find docs/aces/inventory/thehive/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
