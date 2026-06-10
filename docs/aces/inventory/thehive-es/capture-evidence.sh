#!/usr/bin/env bash
set -euo pipefail

# SCN-010 / issue #352 — thehive-es steady-state asset inventory capture.
#
# The thehive-es asset is the Elasticsearch 7.17.28 full-text index backend
# for TheHive (docker.elastic.co/elasticsearch/elasticsearch:7.17.28, upstream
# registry image) running as aptl-thehive-es on aptl-security. It runs
# single-node with xpack.security.enabled=false (no authentication), exposes
# HTTP 9200 and transport 9300 to the security network only (no host-published
# ports), and persists index data in the thehive_es_data volume at
# /usr/share/elasticsearch/data.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ASSET_DIR="$ROOT/docs/aces/inventory/thehive-es"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-thehive-es}"
IMAGE="${IMAGE:-docker.elastic.co/elasticsearch/elasticsearch:7.17.28}"
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

# The thehive-es compose block is extracted directly from docker-compose.yml
# with yq. A profile-filtered `docker compose config` cannot be used because
# the soc profile pulls in services that depend_on wazuh.manager and profile
# filtering invalidates the project. The env redaction rule is applied
# uniformly to the environment array.
yq -o=json '.services."thehive-es"' "$ROOT/docker-compose.yml" \
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
    ' > "$OUT/compose-service.thehive-es.json"
record_limit "compose-service.thehive-es.json is the authored docker-compose.yml service block (yq-extracted); a profile-filtered docker compose config could not be used because soc-profile services depend_on wazuh.manager and profile filtering invalidates the project."

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
  rm -f "$OUT/docker-buildx-imagetools.image.txt"
  record_limit "Docker Buildx imagetools inspection failed for $IMAGE; see docker-buildx-imagetools.image.err for non-secret tool stderr. Image identity falls back to the local config ID in docker-inspect.image.json."
fi

docker network inspect aptl_aptl-security | jq . > "$OUT/docker-network.aptl-security.json"
docker volume inspect aptl_thehive_es_data | jq . > "$OUT/docker-volume.thehive_es_data.json"
docker top "$CONTAINER" | redact_stream > "$OUT/docker-top.txt"
docker logs "$CONTAINER" --tail 500 2>&1 | redact_stream > "$OUT/docker-logs.thehive-es.txt"

record_limit "Capture used the already-running aptl project (soc profile up) per operator direction and did not run aptl lab stop -v && aptl lab start; this bundle is a steady-state observation of that local lab, not a clean-reset rebuild proof."
record_limit "thehive_es_data volume contents (/usr/share/elasticsearch/data) are runtime index state and out of manifest scope; only top-level directory rows are recorded in filesystem-tree.txt.gz. Index-level state is captured in elasticsearch-state.txt instead."
record_limit "/usr/share/elasticsearch/config/elasticsearch.keystore is the entrypoint-generated service keystore (bootstrap seed): recorded as path/metadata only with sensitivity=operator_secret in filesystem-tree.txt.gz and excluded from filesystem-checksums.txt.xz."
record_limit "/usr/share/elasticsearch/modules and plugins are recorded as manifest listing rows only (no per-file checksums); module jar content integrity is evidenced by the registry image digest and the SBOMs. The plugins directory is empty in this image."
record_limit "The Elasticsearch image does not include ss or netstat; listener and connection evidence falls back to raw /proc/net/tcp,tcp6,udp tables, complemented by docker top and osquery namespace-sharing evidence."

# Build provenance: no repo-authored bind files exist for this service; the
# compose file is the only authored input.
sha256sum \
  "$ROOT/docker-compose.yml" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"
record_limit "source-checksums.txt covers only docker-compose.yml; the thehive-es service has no repo-authored bind files (configuration is upstream-image defaults plus compose environment)."

docker exec "$CONTAINER" sh -lc "dpkg-query -W -f='\${binary:Package}\t\${Version}\t\${Architecture}\n'" \
  | sort > "$OUT/os-packages.txt"

# Java application runtime: the bundled Elasticsearch JDK runs the node.
{
  printf "%s\n" "--java-version--"
  docker exec "$CONTAINER" /usr/share/elasticsearch/jdk/bin/java --version 2>&1 || true
  printf "%s\n" "--elasticsearch-version--"
  docker exec "$CONTAINER" sh -lc 'ls /usr/share/elasticsearch/lib/elasticsearch-[0-9]*.jar' 2>&1 || true
  printf "%s\n" "--pip-npm-presence--"
  docker exec "$CONTAINER" sh -lc 'for t in java python3 pip pip3 node npm; do if command -v "$t" >/dev/null 2>&1; then printf "%s present: %s\n" "$t" "$(command -v "$t")"; else printf "%s absent\n" "$t"; fi; done' 2>&1 || true
} > "$OUT/language-manifests.txt"

# Filesystem manifest: the Elasticsearch config and bin trees, listing rows
# for modules and plugins, os-release, and top-level rows only for the
# volume-backed data tree.
docker exec "$CONTAINER" sh -lc '
  set -eu
  {
    for root in /usr/share/elasticsearch/config /usr/share/elasticsearch/bin /usr/share/elasticsearch/modules /usr/share/elasticsearch/plugins /etc/os-release; do
      [ -e "$root" ] || continue
      find "$root" -xdev \( -type f -o -type d -o -type l -o -type s -o -type p \) -print
    done
    if [ -d /usr/share/elasticsearch/data ]; then
      find /usr/share/elasticsearch/data -maxdepth 1 -xdev \( -type d -o -type l \) -print
    fi
  } \
    | sort -u \
    | while IFS= read -r path; do
        stability=stable
        sensitivity=plain
        case "$path" in
          /usr/share/elasticsearch/data*)
            stability=runtime_created
            ;;
          /usr/share/elasticsearch/config/elasticsearch.keystore)
            stability=runtime_created
            sensitivity=operator_secret
            ;;
        esac
        stat -c "%F\t%A\t%a\t%u\t%U\t%g\t%G\t%s\t%Y\t${stability}\t${sensitivity}\t%n" "$path"
      done
' | gzip -n > "$OUT/filesystem-tree.txt.gz"
record_limit "filesystem-tree.txt.gz scopes the manifest to the application surfaces (/usr/share/elasticsearch config, bin, modules and plugins listings, /etc/os-release) plus top-level directory rows for the volume-backed data tree; volume runtime data content and runtime logs are out of manifest scope."

# Stable-content checksums over the config and bin trees. The generated
# elasticsearch.keystore is excluded (metadata row only above); modules and
# plugins are listing-level evidence per the dedicated limit.
docker exec "$CONTAINER" sh -lc '
  set -eu
  for root in /usr/share/elasticsearch/config /usr/share/elasticsearch/bin; do
    [ -e "$root" ] || continue
    find "$root" -xdev -type f -print0
  done \
    | sort -zu \
    | grep -zEv "^/usr/share/elasticsearch/config/elasticsearch\.keystore$" \
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
' | redact_stream > "$OUT/runtime-baseline.txt"

# Service-specific state: node identity, cluster health, indices, nodes, and
# installed plugin/module names (names only; full module detail omitted).
{
  printf "%s\n" --root--
  docker exec "$CONTAINER" curl -s http://localhost:9200/ 2>&1 || true
  printf "%s\n" --cluster-health--
  docker exec "$CONTAINER" curl -s "http://localhost:9200/_cluster/health?pretty" 2>&1 || true
  printf "%s\n" --cat-indices--
  docker exec "$CONTAINER" curl -s "http://localhost:9200/_cat/indices?v" 2>&1 || true
  printf "%s\n" --cat-nodes--
  docker exec "$CONTAINER" curl -s "http://localhost:9200/_cat/nodes?v" 2>&1 || true
  printf "%s\n" --nodes-plugins-names-only--
  docker exec "$CONTAINER" curl -s http://localhost:9200/_nodes/_local/plugins 2>/dev/null \
    | jq '{cluster_name, nodes: (.nodes | map_values({name, version, plugins: [.plugins[].name], modules: [.modules[].name]}))}' 2>&1 || true
} | redact_stream > "$OUT/elasticsearch-state.txt"

# Index mapping manifests. At steady state the only index is the ES-internal
# .geoip_databases system index; its _mapping and _field_caps APIs return a
# reserved-access error, so the field schema is captured from the operator
# _cluster/state/metadata vantage (which does expose system-index mappings).
# TheHive uses local Lucene (index.search.backend=lucene), so it creates no
# data lives in Cassandra, so no participant-created indices exist pre-attack.
docker exec "$CONTAINER" curl -s "http://localhost:9200/_cluster/state/metadata/.geoip_databases" 2>/dev/null \
  | jq . > "$OUT/thehive-es-index-mappings.json" 2>&1 || \
  docker exec "$CONTAINER" curl -s "http://localhost:9200/_cluster/state/metadata/.geoip_databases" > "$OUT/thehive-es-index-mappings.json"
record_limit "Only the ES-internal .geoip_databases system index exists at steady state (TheHive uses local Lucene, index.search.backend=lucene, so it creates no indices in this ES; primary data is in Cassandra). Its _mapping/_field_caps APIs return a reserved-access error, so the field schema (data/name/chunk) was captured via the operator _cluster/state/metadata vantage in thehive-es-index-mappings.json. No participant-created index mappings exist to capture."

# Attacker vantage: kali. Elasticsearch is on security-net only and publishes
# no host ports; record what an in-range attacker can resolve/reach on 9200.
if docker inspect aptl-kali >/dev/null 2>&1; then
  docker exec aptl-kali sh -lc '
    set +e
    printf "%s\n" --dns--
    getent hosts thehive-es aptl-thehive-es '"$CONTAINER_IP"' 2>&1
    printf "%s\n" --route-to-security-net--
    ip route get '"$CONTAINER_IP"' 2>&1
    printf "%s\n" --tcp-probe--
    timeout 8 sh -c "nc -vz -w 3 '"$CONTAINER_IP"' 9200 2>&1" 2>&1
    printf "%s\n" --ping--
    ping -c 1 -W 2 '"$CONTAINER_IP"' 2>&1 | sed -n "1,4p"
    true
  ' | redact_stream > "$OUT/participant-discovery.kali.txt"
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
  "containerized osquery sharing aptl-thehive-es PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-thehive-es network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-thehive-es";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%elasticsearch%";' \
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
  echo "- osquery apt_sources reflects the host-side scanner vantage; the target rootfs Ubuntu apt state is captured directly in os-packages.txt."
} >> "$OUT/capture-limits.txt"

sed -i 's/[[:space:]]\+$//' "$OUT"/*.txt

(
  cd "$ROOT"
  find docs/aces/inventory/thehive-es/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
