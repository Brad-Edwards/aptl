#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
ASSET_ID="wazuh.indexer"
ASSET_DIR="$ROOT/docs/aces/inventory/$ASSET_ID"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-wazuh-indexer}"
IMAGE="${IMAGE:-wazuh/wazuh-indexer:4.12.0}"
COMPOSE_FILE="$ROOT/docker-compose.yml"
COMPOSE_SERVICE="wazuh.indexer"
COMPOSE_PROFILES="${COMPOSE_PROFILES:-wazuh}"

TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6}"
OSQUERY_IMAGE="${OSQUERY_IMAGE:-osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd}"
SYFT_NORMALIZER="$ASSET_DIR/normalize-syft-cyclonedx.jq"

SECRET_NAME_REGEX="(token|secret|password|passwd|credential|cookie|session|private_key|api_key|jwt|flag_key|access_key|shared_key|enrollment_key|client_key|cluster_key|ssl_key|key$)"

# Source INDEXER_USERNAME / INDEXER_PASSWORD from the lab .env so the
# in-container OpenSearch state probe can authenticate. The values are passed
# to docker exec via -e and never written to evidence; redact_stream and the
# script-level redactors are still the final line of defence if anything
# leaks downstream.
if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/.env"
  set +a
fi
: "${INDEXER_USERNAME:=admin}"
: "${INDEXER_PASSWORD:=admin}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'required command missing: %s\n' "$1" >&2
    exit 2
  }
}

record_limit() {
  printf -- '- %s\n' "$*" >> "$OUT/capture-limits.txt"
}

redact_stream() {
  sed -E \
    -e 's#(^|[^[:alnum:]_./-])(([-[:alnum:]_.]*(token|secret|password|passwd|credential|cookie|session|private_key|api_key|jwt|flag_key|access_key|shared_key|enrollment_key|client_key|cluster_key|ssl_key)[-[:alnum:]_.]*|[-[:alnum:]_.]*key)[[:space:]]*[:=][[:space:]]*)("[^"]*"|[^[:space:],;]+)#\1\2<REDACTED-SECRET>#Ig' \
    -e 's#(<([-[:alnum:]_.:]*(token|secret|password|passwd|credential|cookie|session|private_key|api_key|jwt|flag_key|access_key|shared_key|enrollment_key|client_key|cluster_key|ssl_key)[-[:alnum:]_.:]*|[-[:alnum:]_.:]*key)[^>]*>)[^<]*(</\2>)#\1<REDACTED-SECRET>\4#Ig' \
    -e 's/(PASSWORD|PASS|SECRET|TOKEN|COOKIE|SESSION|PRIVATE_KEY|API_KEY|JWT|ACCESS_KEY|SHARED_KEY|ENROLLMENT_KEY|CLIENT_KEY|CLUSTER_KEY|SSL_KEY)=([^[:space:]]+)/\1=<REDACTED>/Ig' \
    -e 's#(hash:[[:space:]]*)"?\$2[ay]\$[^"[:space:]]+"?#\1"<REDACTED-INDEXER-INTERNAL-USER-HASH>"#Ig' \
    -e 's#(Authorization:[[:space:]]*)[^[:space:]]+([[:space:]]+[^[:space:]]+)?#\1<REDACTED-AUTHORIZATION>#Ig'
}

redact_env_jq='
  def redact_env($secret_re):
    if contains("=") then
      capture("^(?<name>[^=]+)=(?<value>.*)$") as $m
      | if ($m.name | test($secret_re; "i")) then
          "\($m.name)=<REDACTED-\($m.name | gsub("_"; "-"))>"
        else
          .
        end
    else
      .
    end;

  def redact_sensitive_keys($secret_re):
    walk(
      if type == "object" then
        with_entries(
          if (.key | test($secret_re; "i")) then
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

record_limit "This capture used the existing running lab as authorized by the user on 2026-06-05 and did not run aptl lab stop -v && aptl lab start; it is a non-destructive frozen steady-state observation, not clean-lab rebuild proof."
record_limit "Raw OpenSearch admin credentials, internal_users.yml bcrypt hashes, indexer keystore values, private TLS keys, and API session tokens are intentionally absent from committed evidence; paths, metadata, redacted setting names, role-mapping shapes, and safe hashes are retained where permitted."
record_limit "The Wazuh indexer image does not include ss, netstat, ip, mount, or ps; runtime evidence uses Docker inspect/network records, /proc inspection, and the in-container OpenSearch HTTP API where in-container tooling is unavailable."

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

COMPOSE_PROFILES="$COMPOSE_PROFILES" docker compose -f "$COMPOSE_FILE" config --format json \
  | jq \
    --arg service "$COMPOSE_SERVICE" \
    --arg secret_re "$SECRET_NAME_REGEX" '
      .services[$service]
      | .environment = (
          (.environment // {})
          | with_entries(
              if (.key | test($secret_re; "i")) then
                .value = ("<REDACTED-" + (.key | gsub("_"; "-")) + ">")
              else
                .
              end
            )
        )
    ' > "$OUT/compose-service.wazuh.indexer.json"

docker inspect "$CONTAINER" \
  | jq --arg secret_re "$SECRET_NAME_REGEX" \
      "$redact_env_jq
      .[].Config.Env |= ((. // []) | map(redact_env(\$secret_re)))
      | redact_sensitive_keys(\$secret_re)" \
  > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" \
  | jq --arg secret_re "$SECRET_NAME_REGEX" "$redact_env_jq redact_sensitive_keys(\$secret_re)" \
  > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" | redact_stream > "$OUT/docker-history.image.txt"
docker history --no-trunc --format '{{json .}}' "$IMAGE" | redact_stream > "$OUT/docker-history.image.jsonl"

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

docker volume inspect aptl_wazuh-indexer-data | jq . > "$OUT/docker-volume.wazuh-indexer-data.json"

docker top "$CONTAINER" | redact_stream > "$OUT/docker-top.txt"

sha256sum \
  "$ROOT/docker-compose.yml" \
  "$ROOT/config/wazuh_indexer/wazuh.indexer.yml" \
  "$ROOT/config/wazuh_indexer/internal_users.yml" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"

docker exec "$CONTAINER" bash -lc '
  rpm -qa --qf "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n" | sort
' > "$OUT/os-packages.txt"

docker exec "$CONTAINER" bash -lc '
  set +e
  echo --opensearch--
  /usr/share/wazuh-indexer/bin/opensearch --version 2>&1 || true
  echo --jdk-release--
  cat /usr/share/wazuh-indexer/jdk/release 2>/dev/null || true
  echo --jdk-java-version--
  /usr/share/wazuh-indexer/jdk/bin/java -version 2>&1 || true
  echo --performance-analyzer-version--
  cat /usr/share/wazuh-indexer/plugins/opensearch-performance-analyzer/plugin-descriptor.properties 2>/dev/null | grep -E "^(name|version|opensearch.version)=" || true
  echo --security-plugin--
  cat /usr/share/wazuh-indexer/plugins/opensearch-security/plugin-descriptor.properties 2>/dev/null | grep -E "^(name|version|opensearch.version)=" || true
  echo --indexer-version--
  cat /usr/share/wazuh-indexer/VERSION.json 2>/dev/null || true
' | redact_stream > "$OUT/language-manifests.txt"

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
  echo --pid1-cmdline--
  tr "\0" " " < /proc/1/cmdline; echo
  echo --pid1-status--
  cat /proc/1/status 2>/dev/null | head -20
  echo --environment--
  env | sort
  echo --listeners-tcp--
  cat /proc/net/tcp /proc/net/tcp6 2>/dev/null
  echo --listeners-udp--
  cat /proc/net/udp /proc/net/udp6 2>/dev/null
  echo --network-addresses--
  cat /proc/net/dev 2>/dev/null
  echo --routes--
  cat /proc/net/route 2>/dev/null
  echo --dns--
  cat /etc/resolv.conf
  echo --hosts--
  cat /etc/hosts
  echo --hostname--
  cat /etc/hostname
  echo --mounts--
  cat /proc/1/mountinfo 2>/dev/null | sed -n "1,240p"
  echo --users--
  getent passwd | sed -n "1,240p"
  echo --groups--
  getent group | sed -n "1,260p"
  echo --process-list--
  for pidpath in /proc/[0-9]*; do
    pid="$(basename "$pidpath")"
    [ -r "$pidpath/status" ] || continue
    name="$(grep "^Name:" "$pidpath/status" | cut -f2)"
    uid="$(grep "^Uid:" "$pidpath/status" | awk "{print \$2}")"
    cmdline="$(tr "\0" " " < "$pidpath/cmdline" | sed "s/[[:space:]]*$//")"
    printf "%s\t%s\t%s\t%s\n" "$pid" "$uid" "$name" "$cmdline"
  done | sort -n
' | redact_stream > "$OUT/runtime-baseline.txt"

docker exec \
  -e "INDEXER_USERNAME=$INDEXER_USERNAME" \
  -e "INDEXER_PASSWORD=$INDEXER_PASSWORD" \
  "$CONTAINER" bash -lc '
  set +e
  cred="${INDEXER_USERNAME}:${INDEXER_PASSWORD}"
  echo --cluster-health--
  curl -ks -u "$cred" https://localhost:9200/_cluster/health?pretty 2>&1
  echo --cluster-stats-summary--
  curl -ks -u "$cred" "https://localhost:9200/_cluster/stats?human&filter_path=cluster_name,cluster_uuid,status,indices.count,indices.shards.total,indices.shards.primaries,indices.docs.count,indices.store.size_in_bytes,nodes.count,nodes.os.mem.total_in_bytes,nodes.versions" 2>&1
  echo --cluster-settings--
  curl -ks -u "$cred" "https://localhost:9200/_cluster/settings?include_defaults=false&pretty" 2>&1
  echo --nodes-local-summary--
  curl -ks -u "$cred" "https://localhost:9200/_nodes/_local?filter_path=cluster_name,nodes.*.name,nodes.*.host,nodes.*.ip,nodes.*.transport_address,nodes.*.version,nodes.*.build_type,nodes.*.build_hash,nodes.*.roles,nodes.*.attributes,nodes.*.process.id,nodes.*.process.mlockall,nodes.*.jvm.version,nodes.*.jvm.vm_name,nodes.*.jvm.vm_vendor,nodes.*.jvm.mem.heap_init_in_bytes,nodes.*.jvm.mem.heap_max_in_bytes,nodes.*.http.publish_address,nodes.*.transport.publish_address,nodes.*.settings.path,nodes.*.settings.network,nodes.*.settings.http,nodes.*.settings.transport,nodes.*.settings.discovery&pretty" 2>&1
  echo --cat-nodes--
  curl -ks -u "$cred" "https://localhost:9200/_cat/nodes?v&h=ip,name,node.role,master,version,heap.percent,ram.percent,load_1m" 2>&1
  echo --cat-indices--
  curl -ks -u "$cred" "https://localhost:9200/_cat/indices?h=health,status,index,uuid,pri,rep,docs.count,docs.deleted,store.size,creation.date.string&format=json&s=index" 2>&1
  echo --cat-templates--
  curl -ks -u "$cred" "https://localhost:9200/_cat/templates?h=name,index_patterns,order,version&format=json&s=name" 2>&1
  echo --cat-plugins--
  curl -ks -u "$cred" "https://localhost:9200/_cat/plugins?h=name,component,version&format=json&s=component" 2>&1
  echo --security-config-summary--
  curl -ks -u "$cred" "https://localhost:9200/_plugins/_security/api/securityconfig?filter_path=config.dynamic.authc.*.http_enabled,config.dynamic.authc.*.transport_enabled,config.dynamic.authc.*.order,config.dynamic.authc.*.http_authenticator.type,config.dynamic.authc.*.http_authenticator.challenge,config.dynamic.authc.*.authentication_backend.type,config.dynamic.authz.*.http_enabled,config.dynamic.authz.*.transport_enabled,config.dynamic.authz.*.authorization_backend.type&pretty" 2>&1
  echo --security-roles--
  curl -ks -u "$cred" "https://localhost:9200/_plugins/_security/api/roles?filter_path=admin.*,kibana_*.*,readall.*,manage_snapshots.*,security_*.*,logstash.*,snapshot_management*.*,all_access.*&pretty" 2>&1
  echo --security-rolesmapping--
  curl -ks -u "$cred" "https://localhost:9200/_plugins/_security/api/rolesmapping?pretty" 2>&1
  echo --security-internalusers-shape--
  curl -ks -u "$cred" "https://localhost:9200/_plugins/_security/api/internalusers?filter_path=*.reserved,*.hidden,*.backend_roles,*.attributes,*.opendistro_security_roles,*.description&pretty" 2>&1
  echo --opensearch-yml--
  cat /usr/share/wazuh-indexer/opensearch.yml 2>/dev/null
  echo --internal-users-yml--
  cat /usr/share/wazuh-indexer/opensearch-security/internal_users.yml 2>/dev/null
  echo --roles-yml--
  cat /usr/share/wazuh-indexer/opensearch-security/roles.yml 2>/dev/null
  echo --roles-mapping-yml--
  cat /usr/share/wazuh-indexer/opensearch-security/roles_mapping.yml 2>/dev/null
  echo --action-groups-yml--
  cat /usr/share/wazuh-indexer/opensearch-security/action_groups.yml 2>/dev/null
  echo --jvm-options--
  cat /usr/share/wazuh-indexer/jvm.options 2>/dev/null
' | redact_stream > "$OUT/wazuh-indexer-state.txt"

docker exec "$CONTAINER" bash -lc '
  set +e
  curl -ks -i https://localhost:9200 2>&1 | sed -n "1,80p"
' | redact_stream \
  | jq -Rs '{vantage: "container localhost", command: "curl -ks -i https://localhost:9200", output: .}' \
  > "$OUT/wazuh-indexer-api-probe.json"

docker exec "$CONTAINER" bash -lc '
  set -euo pipefail
  roots="
    /usr/share/wazuh-indexer/opensearch.yml
    /usr/share/wazuh-indexer/jvm.options
    /usr/share/wazuh-indexer/jvm.options.d
    /usr/share/wazuh-indexer/opensearch-security
    /usr/share/wazuh-indexer/certs
    /usr/share/wazuh-indexer/plugins/opensearch-security
    /usr/share/wazuh-indexer/plugins/opensearch-performance-analyzer
    /etc/wazuh-indexer
    /var/lib/wazuh-indexer
    /var/log/wazuh-indexer
  "
  for root in $roots; do
    [ -e "$root" ] || continue
    find "$root" -xdev -maxdepth 6 \( -type f -o -type d -o -type l \) -print
  done | sort -u | while IFS= read -r path; do
    stat -c "%F %A %a %u %U %g %G %s %Y %n" "$path"
  done
' | redact_stream > "$OUT/filesystem-tree.txt"

docker exec "$CONTAINER" bash -lc '
  set -euo pipefail
  roots="
    /usr/share/wazuh-indexer/opensearch.yml
    /usr/share/wazuh-indexer/jvm.options
    /usr/share/wazuh-indexer/jvm.options.d
    /usr/share/wazuh-indexer/opensearch-security
    /usr/share/wazuh-indexer/certs
    /usr/share/wazuh-indexer/plugins/opensearch-security
    /usr/share/wazuh-indexer/plugins/opensearch-performance-analyzer
    /etc/wazuh-indexer
  "
  for root in $roots; do
    [ -e "$root" ] || continue
    find "$root" -xdev -maxdepth 6 -type f \
      ! -name "*-key.pem" \
      ! -name "*.key" \
      ! -name "esnode-key.pem" \
      ! -name "admin-key.pem" \
      ! -name "wazuh.indexer.key" \
      ! -name "kirk-key.pem" \
      -print
  done | sort -u | xargs -r sha256sum
' > "$OUT/filesystem-checksums.txt"
printf '<OMITTED-OPERATOR-SECRET-CHECKSUM>  /usr/share/wazuh-indexer/certs/wazuh.indexer.key\n' >> "$OUT/filesystem-checksums.txt"
printf '<OMITTED-OPERATOR-SECRET-CHECKSUM>  /usr/share/wazuh-indexer/certs/admin-key.pem\n' >> "$OUT/filesystem-checksums.txt"

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
  "containerized osquery sharing aptl-wazuh-indexer PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-wazuh-indexer network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-wazuh-indexer";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%wazuh-indexer%";' \
  "containerized osquery host-side Docker socket view" docker

write_json_status "$OUT/osquery-apt-sources.json" apt_sources \
  'select * from apt_sources order by name;' \
  "not_applicable" \
  "apt_sources is Debian/Ubuntu-specific and does not describe the Amazon Linux Wazuh indexer target; RPM package state is captured by os-packages.txt and SBOM evidence."
record_limit "osquery apt_sources was not applicable for the Amazon Linux Wazuh indexer target."

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
  find docs/aces/inventory/wazuh.indexer/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
