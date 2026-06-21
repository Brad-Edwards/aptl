#!/usr/bin/env bash
set -euo pipefail

# SCN-010 / issue #349 — misp-suricata-sync steady-state asset inventory capture.
#
# The misp-suricata-sync asset is a *MISP-to-Suricata IOC synchronization
# service*: a custom python:3.11-slim build (aptl-misp-suricata-sync) running
# the aptl-misp-suricata-sync console script as PID 1 (root, per the
# Dockerfile's bind-mount ownership rationale). Every SYNC_INTERVAL_SECONDS
# (300) it pulls indicators tagged IOC_TAG_FILTER (aptl:enforce) from the MISP
# HTTPS API, translates them into Suricata alert rules (ADR-019), atomically
# rewrites /var/lib/suricata/rules/misp/misp-iocs.rules in the shared
# suricata_misp_rules named volume (ADR-043; formerly a .aptl host bind), and
# triggers a Suricata rule reload over the shared unix-command socket volume.
# It exposes no inbound listener — it dials OUT to MISP and writes files/sockets.
#
# The image is a local custom build, not a registry artifact, so build
# provenance is the repo Dockerfile + build-context inputs (source-checksums.txt),
# not a registry manifest digest. docker buildx imagetools inspect is attempted
# but expected to fail for the local-only tag; that is recorded as a limit.
#
# MISP_API_KEY in the runtime env is the lab's MISP admin API key — the same
# secret_fixture value already disclosed on nodes.techvault.misp runtime
# environment (ADMIN_KEY). It is TechVault scenario content and is captured
# verbatim in committed evidence.

ROOT="$(git rev-parse --show-toplevel)"
ASSET_DIR="$ROOT/docs/aces/inventory/misp-suricata-sync"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-misp-suricata-sync}"
SURICATA_CONTAINER="${SURICATA_CONTAINER:-aptl-suricata}"
IMAGE="${IMAGE:-aptl-misp-suricata-sync:latest}"
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

capture_stream() {
  cat
}

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

# The misp-suricata-sync compose block is extracted directly from
# docker-compose.yml with yq. A profile-filtered `docker compose config` cannot
# be used because the soc profile pulls in services that depend_on
# wazuh.manager and profile filtering invalidates the project. The authored
# MISP_API_KEY entry is an ${MISP_API_KEY:?...} interpolation template, not a
# literal secret, and is captured exactly as authored.
yq -o=json '.services."misp-suricata-sync"' "$ROOT/docker-compose.yml" \
  | jq . > "$OUT/compose-service.misp-suricata-sync.json"
record_limit "compose-service.misp-suricata-sync.json is the authored docker-compose.yml service block (yq-extracted); a profile-filtered docker compose config could not be used because soc-profile services depend_on wazuh.manager and profile filtering invalidates the project. The authored MISP_API_KEY value is an \${MISP_API_KEY:?...} interpolation template and is captured exactly as authored."

docker inspect "$CONTAINER" \
  | jq . \
  > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" \
  | jq . \
  > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" | capture_stream > "$OUT/docker-history.image.txt"
docker history --no-trunc --format '{{json .}}' "$IMAGE" | capture_stream > "$OUT/docker-history.image.jsonl"

if docker buildx imagetools inspect "$IMAGE" > "$OUT/docker-buildx-imagetools.image.txt" 2>"$OUT/docker-buildx-imagetools.image.err"; then
  docker buildx imagetools inspect "$IMAGE" --raw \
    | jq . > "$OUT/docker-buildx-imagetools.image.raw.json"
  rm -f "$OUT/docker-buildx-imagetools.image.err"
else
  rm -f "$OUT/docker-buildx-imagetools.image.txt"
  record_limit "Docker Buildx imagetools inspection failed for $IMAGE because it is a locally built tag with no registry manifest; see docker-buildx-imagetools.image.err. Image identity is the local config ID in docker-inspect.image.json plus the build recipe in source-checksums.txt."
fi

docker network inspect aptl_aptl-security | jq . > "$OUT/docker-network.aptl-security.json"
docker volume inspect aptl_suricata_command_socket | jq . > "$OUT/docker-volume.suricata_command_socket.json"
# ADR-043: the MISP rules tree is now the shared suricata_misp_rules named
# volume (seeded at lab start), not a .aptl host bind mount (issue #325).
docker volume inspect aptl_suricata_misp_rules | jq . > "$OUT/docker-volume.suricata_misp_rules.json"
docker top "$CONTAINER" | capture_stream > "$OUT/docker-top.txt"
docker logs "$CONTAINER" --tail 500 2>&1 | capture_stream > "$OUT/docker-logs.misp-suricata-sync.txt"

record_limit "Recaptured after ADR-043 (issue #325) on a clean-rebuilt lab: two consecutive 'aptl lab stop -v && aptl lab start' cycles preceded this capture, so the bundle reflects the named-volume-seeded steady state, not the pre-fix host-bind topology."
record_limit "MISP_API_KEY (runtime env) is the lab MISP admin API key — the same secret_fixture value already disclosed on nodes.techvault.misp (ADMIN_KEY). It is retained verbatim in committed evidence and SDL because it is TechVault scenario content."
record_limit "/var/run/suricata is the shared suricata_command_socket volume owned by the suricata asset; only the socket path/metadata is recorded here. /var/lib/suricata/rules/misp is the shared suricata_misp_rules named volume (ADR-043; seeded at lab start, formerly a .aptl host bind) whose misp-iocs.rules content is generated by this service and recorded as a runtime-created file."

# Build-recipe provenance: the Dockerfile COPYs pyproject.toml and the entire
# repo src/ tree, then pip-installs the aptl package. The executed application
# is the aptl.services.misp_suricata_sync package (console script
# aptl-misp-suricata-sync); its source files and the packaging metadata are
# checksummed here. The full src/ copy inside the image is covered by the
# in-image filesystem manifest (/app) rather than per-file repo checksums.
sha256sum \
  "$ROOT/docker-compose.yml" \
  "$ROOT/containers/misp-suricata-sync/Dockerfile" \
  "$ROOT/pyproject.toml" \
  "$ROOT"/src/aptl/services/misp_suricata_sync/*.py \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"
record_limit "source-checksums.txt covers the compose file, Dockerfile, pyproject.toml, and the executed aptl.services.misp_suricata_sync package sources. The Dockerfile COPYs the entire repo src/ tree into /app; that full copy is evidenced by the in-image filesystem manifest under /app and /usr/local/lib/python3.11/site-packages/aptl, not by per-file repo checksums of unrelated aptl subpackages."

docker exec "$CONTAINER" sh -lc "dpkg-query -W -f='\${binary:Package}\t\${Version}\t\${Architecture}\n'" \
  | sort > "$OUT/os-packages.txt"

# Python application runtime: record interpreter + installed distributions
# (the app's dependency closure) via pip.
{
  printf "%s\n" "--python-version--"
  docker exec "$CONTAINER" python3 --version 2>&1 || true
  printf "%s\n" "--pip-version--"
  docker exec "$CONTAINER" pip --version 2>&1 || true
  printf "%s\n" "--console-script--"
  docker exec "$CONTAINER" sh -lc 'command -v aptl-misp-suricata-sync && head -2 "$(command -v aptl-misp-suricata-sync)"' 2>&1 || true
  printf "%s\n" "--pip-distributions--"
  docker exec "$CONTAINER" pip list --format json 2>/dev/null | jq . || true
} > "$OUT/language-manifests.txt"

# Filesystem manifest: the /app build-context copy, the installed aptl package
# + dist-info, the console script, the CA trust input, the rules output bind,
# the suricata command socket dir, and os-release. Third-party site-packages
# dependencies are evidenced by SBOMs + pip list, not per-file rows.
docker exec "$CONTAINER" sh -lc '
  set -eu
  roots="
    /app
    /usr/local/lib/python3.11/site-packages/aptl
    /usr/local/bin/aptl-misp-suricata-sync
    /etc/lab-ca
    /var/lib/suricata/rules/misp
    /var/run/suricata
    /etc/os-release
  "
  for root in $roots; do
    [ -e "$root" ] || continue
    find "$root" -xdev \( -type f -o -type d -o -type l -o -type s -o -type p \) -print
  done \
    | grep -Ev "/__pycache__(/|$)" \
    | sort -u \
    | while IFS= read -r path; do
        stability=stable
        sensitivity=plain
        case "$path" in
          /var/lib/suricata/rules/misp/*)
            stability=runtime_created
            ;;
          /var/run/suricata*)
            stability=runtime_created
            ;;
        esac
        stat -c "%F\t%A\t%a\t%u\t%U\t%g\t%G\t%s\t%Y\t${stability}\t${sensitivity}\t%n" "$path"
      done
' | gzip -n > "$OUT/filesystem-tree.txt.gz"
record_limit "filesystem-tree.txt.gz scopes the manifest to the application surfaces (/app, installed aptl package, console script, CA input, rules output, socket dir, os-release) and excludes __pycache__ bytecode and third-party site-packages dependency trees; the dependency closure is evidenced by the SBOMs and pip list instead."

# Stable-content checksums over the application code + packaging + CA input.
# The runtime-created rules output and socket are excluded (recorded as
# metadata rows above); __pycache__ bytecode is excluded.
docker exec "$CONTAINER" sh -lc '
  set -eu
  roots="
    /app
    /usr/local/lib/python3.11/site-packages/aptl
    /usr/local/bin/aptl-misp-suricata-sync
    /etc/lab-ca
    /etc/os-release
  "
  for root in $roots; do
    [ -e "$root" ] || continue
    find "$root" -xdev -type f -print0
  done \
    | sort -zu \
    | grep -zEv "(/__pycache__/|\.(sock|pid)$)" \
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
  (ps -eo pid,ppid,user,args || for p in /proc/[0-9]*; do printf "%s %s\n" "${p#/proc/}" "$(tr "\0" " " < "$p/cmdline" 2>/dev/null)"; done) 2>&1
  printf "%s\n" --python-version--
  python3 --version 2>&1 || true
' | capture_stream > "$OUT/runtime-baseline.txt"

# Service-specific state: the generated Suricata rules output, the command
# socket, the CA trust input, and the sync loop's recent activity.
docker exec "$CONTAINER" sh -lc '
  set -eu
  printf "%s\n" --rules-output--
  ls -la /var/lib/suricata/rules/misp/ 2>&1 || true
  printf "%s\n" --rules-content--
  cat /var/lib/suricata/rules/misp/misp-iocs.rules 2>&1 || true
  printf "%s\n" --suricata-socket--
  ls -la /var/run/suricata/ 2>&1 || true
  printf "%s\n" --ca-cert-fingerprint--
  (command -v openssl >/dev/null 2>&1 && openssl x509 -in /etc/lab-ca/lab-ca.pem -noout -fingerprint -sha256 -subject -dates) 2>&1 \
    || sha256sum /etc/lab-ca/lab-ca.pem 2>&1 || true
' | capture_stream > "$OUT/sync-service-state.txt"

# Observer vantage: the suricata container consumes the rules file and the
# command socket. Record the realized integration from the consumer side.
if docker inspect "$SURICATA_CONTAINER" >/dev/null 2>&1; then
  docker exec "$SURICATA_CONTAINER" sh -lc '
    set +e
    printf "%s\n" --rules-file-from-suricata--
    ls -la /var/lib/suricata/rules/misp/ 2>&1
    head -5 /var/lib/suricata/rules/misp/misp-iocs.rules 2>&1
    printf "%s\n" --command-socket--
    ls -la /var/run/suricata/ 2>&1
    printf "%s\n" --suricata-rule-reload-counters--
    (suricatasc -c "show-all-rules" /var/run/suricata/suricata-command.socket 2>&1 | head -3) 2>&1
    true
  ' | capture_stream > "$OUT/observer-discovery.suricata.txt"
else
  record_limit "Suricata observer-vantage discovery was skipped because $SURICATA_CONTAINER was not present."
  printf '%s container unavailable\n' "$SURICATA_CONTAINER" > "$OUT/observer-discovery.suricata.txt"
fi

# Attacker vantage: kali. The sync service is on security-net only and
# publishes no host ports; record what an in-range attacker can resolve/reach.
if docker inspect aptl-kali >/dev/null 2>&1; then
  docker exec aptl-kali sh -lc '
    set +e
    printf "%s\n" --dns--
    getent hosts misp-suricata-sync aptl-misp-suricata-sync 172.20.0.19 2>&1
    printf "%s\n" --route-to-security-net--
    ip route get 172.20.0.19 2>&1
    printf "%s\n" --tcp-probe--
    timeout 8 sh -c "nc -vz -w 3 172.20.0.19 443 2>&1; nc -vz -w 3 172.20.0.19 80 2>&1" 2>&1
    printf "%s\n" --ping--
    ping -c 1 -W 2 172.20.0.19 2>&1 | sed -n "1,4p"
    true
  ' | capture_stream > "$OUT/participant-discovery.kali.txt"
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
  "containerized osquery sharing aptl-misp-suricata-sync PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-misp-suricata-sync network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-misp-suricata-sync";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%misp-suricata-sync%";' \
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
  find docs/aces/inventory/misp-suricata-sync/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
