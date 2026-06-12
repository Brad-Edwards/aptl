#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
ASSET_ID="wazuh.dashboard"
ASSET_DIR="$ROOT/docs/aces/inventory/$ASSET_ID"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-wazuh-dashboard}"
IMAGE="${IMAGE:-wazuh/wazuh-dashboard:4.12.0}"
COMPOSE_FILE="$ROOT/docker-compose.yml"
COMPOSE_SERVICE="wazuh.dashboard"
COMPOSE_PROFILES="${COMPOSE_PROFILES:-wazuh}"

TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6}"
OSQUERY_IMAGE="${OSQUERY_IMAGE:-osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd}"
SYFT_NORMALIZER="$ASSET_DIR/normalize-syft-cyclonedx.jq"
EVIDENCE_CHUNK_SIZE="${EVIDENCE_CHUNK_SIZE:-450k}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'required command missing: %s\n' "$1" >&2
    exit 2
  }
}

record_limit() {
  printf -- '- %s\n' "$*" >> "$OUT/capture-limits.txt"
}

write_chunked_stream() {
  local base="$1"
  rm -f "$OUT/$base" "$OUT/$base".part-*
  split -b "$EVIDENCE_CHUNK_SIZE" -d -a 3 - "$OUT/$base.part-"
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
require sha256sum
require sort
require tar
require xz

mkdir -p "$OUT"
: > "$OUT/capture-limits.txt"
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

record_limit "This capture used the existing running lab as authorized by the user on 2026-06-06 and did not run aptl lab stop -v && aptl lab start; it is a non-destructive frozen steady-state observation, not clean-lab rebuild proof."
record_limit "HTTP response headers, transient HTTP cookie values, scenario fixture credentials, and private-key file checksums are retained in committed evidence as captured range facts."
record_limit "The Wazuh dashboard image does not include find, tar, ps, ss, netstat, ip, or mount; runtime evidence uses Docker inspect/network records, docker top, osquery namespace sharing, /proc/net/* listener fallback, and host-side docker export filesystem capture."

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

COMPOSE_PROFILES="$COMPOSE_PROFILES" docker compose -f "$COMPOSE_FILE" config --format json \
  | jq --arg service "$COMPOSE_SERVICE" '.services[$service]' \
  > "$OUT/compose-service.wazuh.dashboard.json"

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
docker volume inspect aptl_wazuh-dashboard-config | jq . > "$OUT/docker-volume.wazuh-dashboard-config.json"
docker volume inspect aptl_wazuh-dashboard-custom | jq . > "$OUT/docker-volume.wazuh-dashboard-custom.json"
docker top "$CONTAINER" > "$OUT/docker-top.txt"

sha256sum \
  "$ROOT/docker-compose.yml" \
  "$ROOT/config/wazuh_dashboard/opensearch_dashboards.yml" \
  "$ROOT/config/wazuh_dashboard/wazuh.yml" \
  "$ROOT/.aptl/config/wazuh_dashboard/wazuh.yml" \
  "$ROOT/config/wazuh_indexer_ssl_certs/root-ca.pem" \
  "$ROOT/config/wazuh_indexer_ssl_certs/wazuh.dashboard.pem" \
  "$ROOT/config/wazuh_indexer_ssl_certs/wazuh.dashboard-key.pem" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"

{
  echo --opensearch-dashboards-yml--
  sed -n "1,240p" "$ROOT/config/wazuh_dashboard/opensearch_dashboards.yml"
  echo --template-wazuh-yml--
  sed -n "1,160p" "$ROOT/config/wazuh_dashboard/wazuh.yml"
  echo --generated-wazuh-yml--
  sed -n "1,160p" "$ROOT/.aptl/config/wazuh_dashboard/wazuh.yml"
  echo --runtime-opensearch-dashboards-yml--
  docker exec "$CONTAINER" bash -lc 'sed -n "1,240p" /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml 2>/dev/null'
  echo --runtime-wazuh-yml--
  docker exec "$CONTAINER" bash -lc 'sed -n "1,160p" /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml 2>/dev/null'
} > "$OUT/dashboard-config-files.txt"

docker exec "$CONTAINER" bash -lc '
  rpm -qa --qf "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n" | sort
' > "$OUT/os-packages.txt"

docker exec "$CONTAINER" bash -lc '
  set +e
  echo --dashboard-version--
  /usr/share/wazuh-dashboard/bin/opensearch-dashboards --version 2>&1 || true
  echo --version-json--
  cat /usr/share/wazuh-dashboard/VERSION.json 2>&1 || true
  echo --package-json--
  sed -n "1,120p" /usr/share/wazuh-dashboard/package.json 2>&1 || true
  echo --node--
  /usr/share/wazuh-dashboard/node/bin/node --version 2>&1 || true
  echo --plugin-directories--
  ls -la /usr/share/wazuh-dashboard/plugins 2>&1 || true
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
  echo --dns--
  cat /etc/resolv.conf
  echo --hosts--
  cat /etc/hosts
  echo --hostname--
  cat /etc/hostname
  echo --users--
  getent passwd | sed -n "1,240p"
  echo --groups--
  getent group | sed -n "1,260p"
  echo --process-tree--
  ps -eo pid,ppid,user,args || true
' | sed -E 's/[[:space:]]+$//' > "$OUT/runtime-baseline.txt"

docker exec "$CONTAINER" bash -lc '
  set +e
  echo --root--
  ls -la /usr/share/wazuh-dashboard 2>&1
  echo --config--
  ls -la /usr/share/wazuh-dashboard/config 2>&1
  echo --data-wazuh-config--
  ls -la /usr/share/wazuh-dashboard/data/wazuh/config 2>&1
  echo --certs--
  ls -la /usr/share/wazuh-dashboard/certs 2>&1
  echo --custom-assets--
  ls -la /usr/share/wazuh-dashboard/plugins/wazuh/public/assets/custom 2>&1
  echo --wazuh-plugin-package--
  sed -n "1,120p" /usr/share/wazuh-dashboard/plugins/wazuh/package.json 2>&1 || true
' > "$OUT/wazuh-dashboard-state.txt"

docker exec "$CONTAINER" bash -lc '
  set +e
  curl -ks -i https://localhost:5601/api/status 2>&1 | sed -n "1,120p"
  echo --root-probe--
  curl -ks -i https://localhost:5601/ 2>&1 | sed -n "1,80p"
' \
  | jq -Rs '{vantage: "container localhost", commands: ["curl -ks -i https://localhost:5601/api/status", "curl -ks -i https://localhost:5601/"], output: .}' \
  > "$OUT/wazuh-dashboard-probe.json"

docker export "$CONTAINER" \
  | tar -tvf - \
  | gzip -n \
  | write_chunked_stream "filesystem-tree.txt.gz"

tmp_root="$(mktemp -d)"
trivy_json=""
cleanup() {
  chmod -R u+w "$tmp_root" 2>/dev/null || true
  rm -rf "$tmp_root"
  if [[ -n "$trivy_json" ]]; then
    rm -f "$trivy_json"
  fi
}
trap cleanup EXIT

docker export "$CONTAINER" \
  | tar -C "$tmp_root" \
      --no-same-owner \
      --no-same-permissions \
      --exclude='dev/*' \
      --exclude='./dev/*' \
      -xf -
(
  cd "$tmp_root"
  find . -type f \
    ! -path './etc/shadow' \
    ! -path './etc/shadow-' \
    ! -path './etc/gshadow' \
    ! -path './etc/gshadow-' \
    -print0 \
    | sort -z \
    | xargs -0 -r sha256sum \
    | sed 's#  \./#  /#'
) | xz -T0 -9e \
  | write_chunked_stream "filesystem-checksums.txt.xz"
record_limit "Filesystem checksums exclude host identity databases such as /etc/shadow, /etc/shadow-, /etc/gshadow, and /etc/gshadow-; dashboard fixture config and private-key file checksums are retained."
record_limit "Large compressed filesystem manifests are split into ${EVIDENCE_CHUNK_SIZE} chunks (filesystem-tree.txt.gz.part-* and filesystem-checksums.txt.xz.part-*) to preserve full evidence while satisfying the repository added-file size gate."

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" --version \
  > "$OUT/trivy-version.txt"

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" \
  image --format cyclonedx "$IMAGE" \
  | jq -c . \
  | gzip -n > "$OUT/trivy-sbom.cyclonedx.json.gz"

trivy_json="$(mktemp)"
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
  "containerized osquery sharing aptl-wazuh-dashboard PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-wazuh-dashboard network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-wazuh-dashboard";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%wazuh-dashboard%";' \
  "containerized osquery host-side Docker socket view" docker

write_json_status "$OUT/osquery-apt-sources.json" apt_sources \
  'select * from apt_sources order by name;' \
  "not_applicable" \
  "apt_sources is Debian/Ubuntu-specific and does not describe the Amazon Linux Wazuh dashboard target; RPM package state is captured by os-packages.txt and SBOM evidence."
record_limit "osquery apt_sources was not applicable for the Amazon Linux Wazuh dashboard target."

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
  find docs/aces/inventory/wazuh.dashboard/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
