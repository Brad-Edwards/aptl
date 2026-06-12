#!/usr/bin/env bash
set -euo pipefail

# SCN-010 / issue #357 — cortex steady-state asset inventory capture.
#
# Target: compose service cortex, container aptl-cortex, upstream image
# thehiveproject/cortex:3.1.8, security-net address 172.20.0.22. Capture is
# taken after a clean aptl lab start, with TheHive integrated via the fixture
# Cortex API key and Cortex using the shared thehive-es Elasticsearch backend.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ASSET_DIR="$ROOT/docs/aces/inventory/cortex"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-cortex}"
IMAGE="${IMAGE:-thehiveproject/cortex:3.1.8}"
CONTAINER_IP="${CONTAINER_IP:-172.20.0.22}"

export PATH="$HOME/.local/bin:$PATH"

TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6}"
OSQUERY_IMAGE="${OSQUERY_IMAGE:-osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd}"
SYFT_NORMALIZER="${SYFT_NORMALIZER:-$ASSET_DIR/normalize-syft-cyclonedx.jq}"
TRIVY_CACHE_VOLUME="${TRIVY_CACHE_VOLUME:-aptl-trivy-db-cache}"

mkdir -p "$OUT"
: > "$OUT/capture-limits.txt"

record_limit() {
  printf -- '- %s\n' "$*" >> "$OUT/capture-limits.txt"
}
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

yq -o=json '.services.cortex' "$ROOT/docker-compose.yml" \
  | jq '
      if (has("environment") and (.environment | type == "array")) then
        .environment |= map(.)
      else . end
    ' > "$OUT/compose-service.cortex.json"
record_limit "compose-service.cortex.json is the authored docker-compose.yml service block (yq-extracted). The container uses HTTP only on the aptl-security network; TheHive consumes it with the fixture API key provisioned by scripts/cortex-apikey.sh."

yq -o=json '.services["cortex-index-init"]' "$ROOT/docker-compose.yml" \
  > "$OUT/compose-service.cortex-index-init.json"

docker inspect "$CONTAINER" | jq . > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" | jq . > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" > "$OUT/docker-history.image.txt"
docker history --no-trunc --format '{{json .}}' "$IMAGE" > "$OUT/docker-history.image.jsonl"

if docker buildx imagetools inspect "$IMAGE" > "$OUT/docker-buildx-imagetools.image.txt" 2>"$OUT/docker-buildx-imagetools.image.err"; then
  docker buildx imagetools inspect "$IMAGE" --raw | jq . > "$OUT/docker-buildx-imagetools.image.raw.json"
  rm -f "$OUT/docker-buildx-imagetools.image.err"
else
  rm -f "$OUT/docker-buildx-imagetools.image.txt"
  record_limit "Docker Buildx imagetools inspection failed for $IMAGE; see docker-buildx-imagetools.image.err for non-secret stderr. Image identity falls back to docker-inspect.image.json."
fi

docker network inspect aptl_aptl-security | jq . > "$OUT/docker-network.aptl-security.json"
docker volume inspect aptl_cortex_data | jq . > "$OUT/docker-volume.cortex_data.json"
docker top "$CONTAINER" > "$OUT/docker-top.txt"
docker logs "$CONTAINER" --tail 500 2>&1 > "$OUT/docker-logs.cortex.txt"

record_limit "Capture followed a clean aptl lab stop -v && COMPOSE_BAKE=false aptl lab start immediately before inventory; COMPOSE_BAKE=false is a local Docker Compose workaround because Buildx Bake hung in this environment, not a scenario setting."
record_limit "Cortex HTTPS is intentionally deferred by ADR-034 because the Cortex 3.1.8 bundled Play SSL provider fails at runtime. The participant-visible service is HTTP on the security network, with TheHive using the fixture API key over the internal network."
record_limit "The Cortex API key and bootstrap password are fixture credentials; raw key/password values are retained as in-range scenario evidence."
record_limit "The cortex_data volume backs /opt/cortex/jobs. At the steady-state snapshot no analyzer jobs were present; the filesystem manifest records the top-level jobs directory and volume metadata, not future job artifacts."

sha256sum \
  "$ROOT/docker-compose.yml" \
  "$ROOT/config/cortex/application.conf" \
  "$ROOT/config/cortex/thehive-cortex.env" \
  "$ROOT/scripts/cortex-apikey.sh" \
  "$ROOT/scripts/cortex-index-init.sh" \
  "$ROOT/config/soc_certs/lab-ca.pem" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"
record_limit "source-checksums.txt covers docker-compose.yml, the Cortex application overlay, the fixture TheHive-Cortex env file, the Cortex API-key/index bootstrap scripts, and the generated lab CA certificate."

docker exec "$CONTAINER" sh -lc "dpkg-query -W -f='\${binary:Package}\t\${Version}\t\${Architecture}\n'" \
  | sort > "$OUT/os-packages.txt"

{
  printf "%s\n" "--java-version--"
  docker exec "$CONTAINER" java -version 2>&1 || true
  printf "%s\n" "--java-home--"
  docker exec "$CONTAINER" sh -lc 'command -v java && readlink -f "$(command -v java)"' 2>&1 || true
  printf "%s\n" "--python-version--"
  docker exec "$CONTAINER" python3 --version 2>&1 || true
  printf "%s\n" "--cortex-jars--"
  docker exec "$CONTAINER" sh -lc 'ls /opt/cortex/lib | grep -E "(cortex|elastic4play|play_|scala-library|elastic4s)" | sed -n "1,80p"' 2>&1 || true
  printf "%s\n" "--tool-presence--"
  docker exec "$CONTAINER" sh -lc 'for t in python3 pip pip3 node npm ruby gem; do if command -v "$t" >/dev/null 2>&1; then printf "%s present: %s\n" "$t" "$(command -v "$t")"; else printf "%s absent\n" "$t"; fi; done' 2>&1 || true
} > "$OUT/language-manifests.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  {
    for root in /opt/cortex /etc/cortex /etc/lab-ca /var/log/cortex /etc/os-release; do
      [ -e "$root" ] || continue
      find "$root" -xdev \( -type f -o -type d -o -type l -o -type s -o -type p \) -print
    done
    [ -d /opt/cortex/jobs ] && find /opt/cortex/jobs -maxdepth 2 -xdev \( -type f -o -type d -o -type l \) -print
  } \
    | sort -u \
    | while IFS= read -r path; do
        stability=stable
        sensitivity=plain
        case "$path" in
          /opt/cortex/jobs*) stability=runtime_created ;;
          /etc/cortex/application.conf) stability=authored_bind ;;
          /etc/lab-ca/lab-ca.pem) stability=generated_lab_ca ;;
        esac
        stat -c "%F\t%A\t%a\t%u\t%U\t%g\t%G\t%s\t%Y\t${stability}\t${sensitivity}\t%n" "$path"
      done
' | gzip -n > "$OUT/filesystem-tree.txt.gz"

docker exec "$CONTAINER" sh -lc '
  set -eu
  for root in /opt/cortex /etc/cortex /etc/lab-ca; do
    [ -e "$root" ] || continue
    find "$root" -xdev -type f -print0
  done | sort -zu | xargs -0 -r sha256sum
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

{
  printf "%s\n" --api-status--
  docker exec "$CONTAINER" curl -sf http://localhost:9001/api/status 2>&1 || true
  printf "\n%s\n" --application-conf--
  docker exec "$CONTAINER" cat /etc/cortex/application.conf 2>&1 || true
  printf "\n%s\n" --generated-runtime-conf--
  docker exec "$CONTAINER" sh -lc 'ls /tmp/cortex-*.conf 2>/dev/null | head -1 | xargs -r cat' 2>&1 || true
  printf "\n%s\n" --jobs-dir-top-level--
  docker exec "$CONTAINER" ls -la /opt/cortex/jobs 2>&1 || true
  printf "\n%s\n" --es-indices--
  docker exec "$CONTAINER" sh -lc 'curl -sf http://thehive-es:9200/_cat/indices?v' 2>&1 || true
  printf "\n%s\n" --cortex-index-mapping--
  docker exec "$CONTAINER" sh -lc 'curl -sf http://thehive-es:9200/cortex_6/_mapping' 2>&1 || true
  printf "\n%s\n" --cortex-index-count--
  docker exec "$CONTAINER" sh -lc 'curl -sf http://thehive-es:9200/cortex_6/_count' 2>&1 || true
} > "$OUT/cortex-state.txt"

docker exec "$CONTAINER" sh -lc 'curl -sf "http://thehive-es:9200/cortex_6/_search?size=20"' \
  | jq . > "$OUT/cortex-index-documents.json"

docker exec aptl-thehive sh -lc 'curl -sf -H "Authorization: Bearer ${TH_CORTEX_KEYS}" http://cortex:9001/api/user/current' \
  | jq 'del(.key, .password)' > "$OUT/thehive-cortex-auth-current-user.json"

{
  printf "%s\n" --kali-route--
  docker exec aptl-kali sh -lc 'ip route' 2>&1 || true
  printf "%s\n" --kali-hosts--
  docker exec aptl-kali sh -lc 'getent hosts cortex || true' 2>&1 || true
  printf "%s\n" --kali-cortex-port--
  docker exec aptl-kali sh -lc "timeout 3 bash -lc '</dev/tcp/${CONTAINER_IP}/9001' && echo tcp-open || echo tcp-closed" 2>&1 || true
  printf "%s\n" --kali-cortex-status--
  docker exec aptl-kali sh -lc "curl -sf --max-time 5 http://${CONTAINER_IP}:9001/api/status" 2>&1 || true
  printf "%s\n" --thehive-cortex-status--
  docker exec aptl-thehive sh -lc 'curl -sf http://cortex:9001/api/status' 2>&1 || true
} > "$OUT/participant-discovery.kali.txt"

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$TRIVY_CACHE_VOLUME:/root/.cache/" "$TRIVY_IMAGE" --version \
  > "$OUT/trivy-version.txt"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$TRIVY_CACHE_VOLUME:/root/.cache/" "$TRIVY_IMAGE" \
  image --format cyclonedx "$IMAGE" | jq -c . | gzip -n > "$OUT/trivy-sbom.cyclonedx.json.gz"

trivy_json="$(mktemp)"
trap 'rm -f "$trivy_json"' EXIT
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$TRIVY_CACHE_VOLUME:/root/.cache/" "$TRIVY_IMAGE" \
  image --format json --scanners vuln "$IMAGE" > "$trivy_json"
xz -9 -c "$trivy_json" > "$OUT/trivy-vulnerabilities.json.xz"
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

if [[ -f "$SYFT_NORMALIZER" ]] && docker run --rm "$SYFT_IMAGE" version -o json | jq . > "$OUT/syft-version.json"; then
  if docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$SYFT_IMAGE" \
    "docker:$IMAGE" \
    --output cyclonedx-json \
    --select-catalogers "-file-content-cataloger,-file-digest-cataloger,-file-executable-cataloger,-file-metadata-cataloger" \
    | jq -c -f "$SYFT_NORMALIZER" | gzip -n > "$OUT/syft-sbom.cyclonedx.json.gz"; then
    record_limit "Syft CycloneDX output was deterministically normalized by stripping syft:location:* properties; filesystem-tree.txt.gz and filesystem-checksums.txt.xz provide separate filesystem provenance."
  else
    rm -f "$OUT/syft-sbom.cyclonedx.json.gz"
    record_limit "Syft SBOM capture failed; command is preserved in capture-evidence.sh and Trivy CycloneDX remains the required SBOM."
  fi
else
  record_limit "Syft SBOM capture skipped; normalizer or digest-pinned Syft scanner was unavailable."
fi

if docker run --rm "$OSQUERY_IMAGE" osqueryi --version > "$OUT/osquery-version.txt"; then
  osquery_tool="$(cat "$OUT/osquery-version.txt")"
  rows="$(docker run --rm --pid="container:$CONTAINER" --network="container:$CONTAINER" \
    "$OSQUERY_IMAGE" osqueryi --json \
    'select pid, name, path, cmdline, uid, gid, start_time from processes where name != "osqueryi" order by pid;')"
  jq -n --arg table processes --arg tool "$osquery_tool" --argjson rows "$rows" \
    '{table: $table, tool: $tool, vantage: "container pid namespace", status: "captured", rows: $rows}' \
    > "$OUT/osquery-processes.json"
  rows="$(docker run --rm --pid="container:$CONTAINER" --network="container:$CONTAINER" \
    "$OSQUERY_IMAGE" osqueryi --json \
    'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;')"
  jq -n --arg table listening_ports --arg tool "$osquery_tool" --argjson rows "$rows" \
    '{table: $table, tool: $tool, vantage: "container network namespace", status: "captured", rows: $rows}' \
    > "$OUT/osquery-listening-ports.json"
  for table in installed_applications programs apt_sources docker_containers docker_images; do
    case "$table" in
      installed_applications) out_name="osquery-installed-applications.json" ;;
      apt_sources) out_name="osquery-apt-sources.json" ;;
      docker_containers) out_name="osquery-docker-containers.json" ;;
      docker_images) out_name="osquery-docker-images.json" ;;
      *) out_name="osquery-$table.json" ;;
    esac
    jq -n --arg table "$table" --arg tool "$osquery_tool" \
      '{table: $table, tool: $tool, vantage: "digest-pinned Linux osquery scanner", status: "not_available", rows: [], limit: "Table unavailable or not meaningful from the container namespace scanner for this asset; docker/OS/package evidence is captured through Docker inspect and dpkg-query."}' \
      > "$OUT/$out_name"
  done
  record_limit "osquery installed_applications/programs/apt_sources/docker_containers/docker_images were attempted but are not meaningful from the digest-pinned namespace-sharing scanner; Docker inspect, dpkg-query, and runtime-baseline carry those facts."
else
  record_limit "osquery capture skipped because the digest-pinned osquery scanner was unavailable."
fi

(
  cd "$ASSET_DIR"
  find evidence -maxdepth 1 -type f ! -name evidence-sha256sums.txt -print \
    | sort \
    | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
