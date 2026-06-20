#!/usr/bin/env bash
set -euo pipefail

# SCN-010 / issue #355 — shuffle-orborus steady-state asset inventory capture.
#
# The shuffle-orborus asset is the Shuffle execution orchestrator
# (ghcr.io/shuffle/shuffle-orborus:latest, upstream GHCR registry image)
# running as aptl-shuffle-orborus on aptl-security (DHCP address, no static IP).
# It is a single Go static binary (/orborus) running as PID 1 on Alpine Linux.
# It publishes NO host ports. CRITICAL SURFACE: it bind-mounts the host
# /var/run/docker.sock read-write, i.e. it has full host-Docker control and
# spawns Shuffle worker containers (SHUFFLE_WORKER_IMAGE=
# ghcr.io/shuffle/shuffle-worker:latest). It polls the backend execution queue
# at BASE_URL=http://shuffle-backend:5001. Non-destructive: observes the
# already-running lab and does NOT run aptl lab stop/start. The /orborus binary
# is NEVER invoked here (invoking it without an exiting flag starts the daemon
# and would spawn worker containers); identity is captured from binary metadata
# and embedded strings, the SBOMs, and the running PID-1 process.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ASSET_DIR="$ROOT/docs/aces/inventory/shuffle-orborus"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-shuffle-orborus}"
IMAGE="${IMAGE:-ghcr.io/shuffle/shuffle-orborus:latest}"

export PATH="$HOME/.local/bin:$PATH"

# Tool images are digest-pinned so reruns use the same scanner binaries even
# when floating tags move.
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6}"
OSQUERY_IMAGE="${OSQUERY_IMAGE:-osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd}"
SYFT_NORMALIZER="${SYFT_NORMALIZER:-$ASSET_DIR/normalize-syft-cyclonedx.jq}"

mkdir -p "$OUT"
find "$OUT" -maxdepth 1 -type f -delete
: > "$OUT/capture-limits.txt"

record_limit() {
  printf -- '- %s\n' "$*" >> "$OUT/capture-limits.txt"
}
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

# Compose block extracted directly from docker-compose.yml with yq (a
# profile-filtered docker compose config cannot render because soc-profile
# services depend_on wazuh.manager and profile filtering invalidates the
# project).
yq -o=json '.services."shuffle-orborus"' "$ROOT/docker-compose.yml" \
  | jq . > "$OUT/compose-service.shuffle-orborus.json"
record_limit "compose-service.shuffle-orborus.json is the authored docker-compose.yml service block (yq-extracted); a profile-filtered docker compose config could not be used because soc-profile services depend_on wazuh.manager and profile filtering invalidates the project."

docker inspect "$CONTAINER" | jq . > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" | jq . > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" > "$OUT/docker-history.image.txt"
docker history --no-trunc --format '{{json .}}' "$IMAGE" > "$OUT/docker-history.image.jsonl"

if docker buildx imagetools inspect "$IMAGE" > "$OUT/docker-buildx-imagetools.image.txt" 2>"$OUT/docker-buildx-imagetools.image.err"; then
  docker buildx imagetools inspect "$IMAGE" --raw \
    | jq . > "$OUT/docker-buildx-imagetools.image.raw.json"
  rm -f "$OUT/docker-buildx-imagetools.image.err"
else
  rm -f "$OUT/docker-buildx-imagetools.image.txt"
  record_limit "Docker Buildx imagetools inspection failed for $IMAGE; see docker-buildx-imagetools.image.err for non-secret tool stderr. Image identity falls back to the registry RepoDigest in docker-inspect.container.json and the local config ID in docker-inspect.image.json."
fi

docker network inspect aptl_aptl-security | jq . > "$OUT/docker-network.aptl-security.json"
docker top "$CONTAINER" > "$OUT/docker-top.txt"
docker logs "$CONTAINER" --tail 500 > "$OUT/docker-logs.shuffle-orborus.txt" 2>&1

record_limit "Capture used the already-running aptl project (soc profile up) per operator direction and did not run aptl lab stop -v && aptl lab start; this bundle is a steady-state observation of that local lab, not a clean-reset rebuild proof."
record_limit "shuffle-orborus has no named Docker volume; its only mount is the host /var/run/docker.sock bind. No docker-volume.*.json is emitted for this asset."
record_limit "shuffle-orborus joins aptl-security with the static address 172.20.0.7 (pinned via the compose service's ipv4_address) and publishes NO host ports; its network identity is recorded in docker-inspect.container.json and docker-network.aptl-security.json. The address was previously DHCP-assigned, which let it drift between capture runs and made this bundle internally inconsistent; it is now pinned for reproducible capture."

# --- HOST-CONTROL SURFACE: docker.sock bind --------------------------------
# Make the privileged surface a first-class, dedicated evidence fact.
record_limit "PRIVILEGED HOST-CONTROL SURFACE: shuffle-orborus bind-mounts the host /var/run/docker.sock read-write into the container (Mode=rw). This grants the orborus process full control of the host Docker daemon: it spawns/stops Shuffle worker containers (SHUFFLE_WORKER_IMAGE=ghcr.io/shuffle/shuffle-worker:latest) via the host daemon. A compromise of orborus is effectively host-Docker root. The mount source/destination/RW flag is captured verbatim in docker-inspect.container.json (Mounts) and orborus-state.txt (--docker-sock-mount--)."

# Build provenance: orborus has no repo-authored bind files beyond the compose
# definition (the docker.sock bind is the host socket, not a repo file).
sha256sum \
  "$ROOT/docker-compose.yml" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"
record_limit "source-checksums.txt covers only docker-compose.yml; the shuffle-orborus service has no repo-authored bind files (its single mount is the host /var/run/docker.sock, not a repo-tracked file), and the rootfs is the upstream image."

# --- OS packages (Alpine apk) ------------------------------------------------
docker exec "$CONTAINER" sh -lc '
  set -eu
  arch="$(cat /etc/apk/arch 2>/dev/null || echo unknown)"
  apk info -vv 2>/dev/null | sort | while IFS= read -r line; do
    printf "%s\t%s\n" "$line" "$arch"
  done
' > "$OUT/os-packages.txt"

# --- Language / runtime manifest (Go static binary /orborus) -----------------
# The /orborus binary is NEVER executed (running it starts the daemon and would
# spawn worker containers). Identity is taken from binary metadata, the embedded
# source file the image ships (/orborus.go), and embedded module/version strings.
{
  printf "%s\n" "--orborus-binary-metadata--"
  docker exec "$CONTAINER" sh -lc 'ls -l /orborus /orborus.go 2>&1' || true
  printf "%s\n" "--orborus-binary-file-type--"
  docker exec "$CONTAINER" sh -lc 'command -v file >/dev/null 2>&1 && file /orborus 2>&1 || echo "file(1) absent; /orborus is a statically linked Go ELF binary per docker history and SBOM"' || true
  printf "%s\n" "--go-toolchain-presence--"
  docker exec "$CONTAINER" sh -lc 'for t in go file strings; do if command -v "$t" >/dev/null 2>&1; then printf "%s present: %s\n" "$t" "$(command -v "$t")"; else printf "%s absent\n" "$t"; fi; done' 2>&1 || true
  printf "%s\n" "--go-buildinfo-embedded--"
  docker exec "$CONTAINER" sh -lc 'command -v go >/dev/null 2>&1 && go version -m /orborus 2>/dev/null | sed -n "1,40p" || echo "go toolchain not present in runtime image; embedded module table is captured via syft/trivy SBOM"' 2>&1 || true
  printf "%s\n" "--orborus-go-version-string--"
  docker exec "$CONTAINER" sh -lc 'command -v strings >/dev/null 2>&1 && strings /orborus 2>/dev/null | grep -aoE "go1\.[0-9]+(\.[0-9]+)?" | sort -u | head -5 || echo "strings(1) absent"' 2>&1 || true
  printf "%s\n" "--orborus-shuffle-version-refs--"
  docker exec "$CONTAINER" sh -lc 'command -v strings >/dev/null 2>&1 && strings /orborus 2>/dev/null | grep -aiE "shuffle-(orborus|worker|backend)" | sort -u | head -20 || echo "strings(1) absent"' 2>&1 || true
} > "$OUT/language-manifests.txt"
record_limit "The /orborus Go binary was NEVER executed during capture: invoking it (even with --version) starts the orborus daemon, which would poll the backend and spawn worker containers via the host docker.sock. Binary identity is therefore captured from file metadata, the image-shipped /orborus.go source, embedded Go-version and Shuffle-image strings, and the trivy/syft go-module SBOM catalog instead of a runtime version flag."

# --- Filesystem manifest + checksums (orborus binary + its dir + os-release) -
FS_ROOTS='/orborus /orborus.go /etc/os-release'
docker exec "$CONTAINER" sh -lc "
  set -eu
  for root in $FS_ROOTS; do
    [ -e \"\$root\" ] || continue
    find \"\$root\" -xdev \\( -type f -o -type d -o -type l -o -type s -o -type p \\) -print
  done \
    | sort -u \
    | while IFS= read -r path; do
        stability=stable
        sensitivity=plain
        case \"\$path\" in
          /etc/*shadow*|/etc/*gshadow*) sensitivity=operator_secret ;;
        esac
        stat -c \"%F\t%A\t%a\t%u\t%U\t%g\t%G\t%s\t%Y\t\${stability}\t\${sensitivity}\t%n\" \"\$path\"
      done
" | awk '{gsub(/\\t/,"\t"); print}' > "$OUT/filesystem-tree.txt"

# Full rootfs manifest retained as evidence (backend-pattern); the SDL encodes
# the curated application-surface rows from filesystem-tree.txt above.
docker exec "$CONTAINER" sh -lc '
  set -eu
  find / -xdev \( -type f -o -type d -o -type l -o -type s -o -type p \) -print \
    | sort -u \
    | while IFS= read -r path; do
        stability=stable
        sensitivity=plain
        case "$path" in
          /run/*|/tmp/*|/var/run/*|/var/tmp/*|/root/*) stability=runtime_created ;;
        esac
        case "$path" in
          /etc/*shadow*|/etc/*gshadow*) sensitivity=operator_secret ;;
        esac
        stat -c "%F\t%A\t%a\t%u\t%U\t%g\t%G\t%s\t%Y\t${stability}\t${sensitivity}\t%n" "$path" 2>/dev/null || true
      done
' | awk '{gsub(/\\t/,"\t"); print}' | gzip -n > "$OUT/filesystem-tree-full.txt.gz"

docker exec "$CONTAINER" sh -lc "
  set -eu
  for root in $FS_ROOTS; do
    [ -e \"\$root\" ] || continue
    find \"\$root\" -xdev -type f -print0
  done \
    | sort -zu \
    | xargs -0 -r sha256sum
" > "$OUT/filesystem-checksums.txt"
record_limit "filesystem-tree.txt and filesystem-checksums.txt scope the curated manifest (and the SDL filesystem_inventory rows) to the orborus application surface (the /orborus Go binary, the image-shipped /orborus.go source, and /etc/os-release); the FULL Alpine rootfs manifest is retained as evidence in filesystem-tree-full.txt.gz (no per-file checksums beyond the curated set; rootfs integrity is evidenced by the registry image digest and the SBOMs). The host /var/run/docker.sock bind is a socket on the host, not part of the container rootfs manifest, and is captured in docker-inspect.container.json and orborus-state.txt."

# --- Runtime baseline --------------------------------------------------------
# Alpine orborus image has netstat but no ss; listeners/connections use
# netstat with a /proc/net fallback.
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
  printf "%s\n" --environment--
  env | sort
  printf "%s\n" --listeners--
  (ss -lntup || netstat -lntup || cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 || true) 2>&1
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
  printf "%s\n" --pid1-capabilities--
  grep -E "^(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp)" /proc/1/status 2>/dev/null || true
  printf "%s\n" --process-tree--
  (ps -eo pid,ppid,user,args 2>/dev/null || ps -ef || for p in /proc/[0-9]*; do printf "%s %s\n" "${p#/proc/}" "$(tr "\0" " " < "$p/cmdline" 2>/dev/null)"; done) 2>&1
' > "$OUT/runtime-baseline.txt"

# --- Service-specific state: orborus orchestrator + docker.sock surface ------
{
  printf "%s\n" --pid1-process--
  docker exec "$CONTAINER" sh -lc 'echo "cmdline: $(tr "\0" " " < /proc/1/cmdline)"; ps -eo pid,ppid,user,args 2>/dev/null | sed -n "1,20p"' 2>&1 || true
  printf "%s\n" --docker-sock-mount--
  docker inspect "$CONTAINER" --format '{{json .Mounts}}' | jq . 2>&1 || true
  printf "%s\n" --docker-sock-in-container--
  docker exec "$CONTAINER" sh -lc 'ls -l /var/run/docker.sock 2>&1; echo "type: $(stat -c %F /var/run/docker.sock 2>/dev/null || echo unknown)"' 2>&1 || true
  printf "%s\n" --orchestration-environment--
  docker exec "$CONTAINER" sh -lc 'env | grep -E "^(BASE_URL|SHUFFLE_WORKER_IMAGE|DOCKER_API_VERSION|ORBORUS_CONTAINER_NAME|ENVIRONMENT_NAME|ORG_ID|SHUFFLE_ORBORUS_EXECUTION_TIMEOUT|SHUFFLE_APP_SDK_TIMEOUT|SHUFFLE_STATS_DISABLED|SHUFFLE_LOGS_DISABLED|SHUFFLE_SKIP_PIPELINES|CLEANUP)=" | sort' 2>&1 || true
  printf "%s\n" --outbound-target-backend--
  docker exec "$CONTAINER" sh -lc 'getent hosts shuffle-backend 2>&1; echo "---tcp 5001 probe---"; (timeout 6 nc -vz shuffle-backend 5001 2>&1 || timeout 6 wget -q --spider http://shuffle-backend:5001/ 2>&1; echo "rc=$?")' 2>&1 || true
  printf "%s\n" --host-control-note--
  printf "%s\n" "orborus runs as PID 1 (the /orborus Go static binary) and is bound to the host Docker daemon via the read-write /var/run/docker.sock bind. It does not listen on any TCP port (no published ports, no listeners); it is an OUTBOUND poller against http://shuffle-backend:5001 and a host-Docker controller. The docker.sock bind is the dominant attack surface of this asset: full host-Docker control == host root."
} > "$OUT/orborus-state.txt"

# --- Participant-vantage discovery: kali ------------------------------------
# orborus has no static IP and no published ports, so its DHCP address is read
# from docker inspect at capture time; record what an in-range attacker can
# resolve/reach (expected: no open ports — orborus is outbound-only).
ORBORUS_IP="$(docker inspect "$CONTAINER" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo "")"
if docker inspect aptl-kali >/dev/null 2>&1; then
  docker exec -e "ORBORUS_IP=$ORBORUS_IP" aptl-kali sh -lc '
    set +e
    printf "%s\n" --orborus-dhcp-ip-at-capture--
    printf "%s\n" "$ORBORUS_IP"
    printf "%s\n" --dns--
    getent hosts shuffle-orborus aptl-shuffle-orborus 2>&1
    printf "%s\n" --route-to-security-net--
    [ -n "$ORBORUS_IP" ] && ip route get "$ORBORUS_IP" 2>&1
    printf "%s\n" --tcp-probe-common-ports--
    for p in 22 5001 8080 9999; do
      [ -n "$ORBORUS_IP" ] && timeout 5 sh -c "nc -vz -w 2 $ORBORUS_IP $p 2>&1" 2>&1
    done
    printf "%s\n" --ping--
    [ -n "$ORBORUS_IP" ] && ping -c 1 -W 2 "$ORBORUS_IP" 2>&1 | sed -n "1,4p"
    true
  ' > "$OUT/participant-discovery.kali.txt"
else
  record_limit "Kali participant-vantage discovery was skipped because aptl-kali was not present."
  printf 'aptl-kali container unavailable\n' > "$OUT/participant-discovery.kali.txt"
fi

# --- Trivy: SBOM + vulnerabilities ------------------------------------------
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

# --- Syft: SBOM --------------------------------------------------------------
docker run --rm "$SYFT_IMAGE" version -o json | jq . > "$OUT/syft-version.json"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$SYFT_IMAGE" \
  "docker:$IMAGE" \
  --output cyclonedx-json \
  --select-catalogers "-file-content-cataloger,-file-digest-cataloger,-file-executable-cataloger,-file-metadata-cataloger" \
  | jq -c -f "$SYFT_NORMALIZER" \
  | gzip -n > "$OUT/syft-sbom.cyclonedx.json.gz"
record_limit "Syft CycloneDX output was deterministically normalized by stripping syft:location:* properties; component identity remains and filesystem provenance is captured in filesystem-tree.txt and filesystem-checksums.txt."
record_limit "Trivy and Syft CycloneDX SBOM evidence is committed as deterministic gzip-compressed minified JSON to satisfy the repository's added-file size gate; compression is lossless."

# --- osquery: host-side + container-namespace views -------------------------
docker run --rm "$OSQUERY_IMAGE" osqueryi --version > "$OUT/osquery-version.txt"
OSQUERY_TOOL="$(cat "$OUT/osquery-version.txt")"

write_osquery_json() {
  local output="$1" table="$2" query="$3" vantage="$4" mode="$5" rows
  if [[ "$mode" == "container" ]]; then
    rows="$(docker run --rm --pid="container:$CONTAINER" --network="container:$CONTAINER" "$OSQUERY_IMAGE" osqueryi --json "$query")"
  else
    rows="$(docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$OSQUERY_IMAGE" osqueryi --json "$query")"
  fi
  jq -n --arg table "$table" --arg query "$query" --arg tool "$OSQUERY_TOOL" \
    --arg vantage "$vantage" --argjson rows "$rows" \
    '{table: $table, query: $query, tool: $tool, vantage: $vantage, status: "captured", rows: $rows}' \
    > "$output"
}

write_unavailable_osquery_json() {
  local output="$1" table="$2" query="$3"
  jq -n --arg table "$table" --arg query "$query" --arg tool "$OSQUERY_TOOL" \
    --arg reason "osquery table $table is not present in the Linux osquery registry for the digest-pinned osquery 4.9.0 scanner image" \
    '{table: $table, query: $query, tool: $tool, vantage: "containerized osquery Linux image", status: "unavailable", reason: $reason, rows: []}' \
    > "$output"
}

write_osquery_json "$OUT/osquery-processes.json" processes \
  'select pid, name, path, cmdline, uid, gid, start_time from processes where name != "osqueryi" order by pid;' \
  "containerized osquery sharing aptl-shuffle-orborus PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-shuffle-orborus network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-shuffle-orborus";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%shuffle-orborus%";' \
  "containerized osquery host-side Docker socket view" docker

write_unavailable_osquery_json "$OUT/osquery-apt-sources.json" apt_sources \
  'select * from apt_sources order by name;'

write_unavailable_osquery_json "$OUT/osquery-installed-applications.json" installed_applications \
  'select * from installed_applications;'

write_unavailable_osquery_json "$OUT/osquery-programs.json" programs \
  'select * from programs;'

{
  echo "- osquery apt_sources table is not meaningful for an Alpine (apk) target; recorded as unavailable."
  echo "- osquery installed_applications table unavailable in the digest-pinned Linux scanner image."
  echo "- osquery programs table unavailable in the digest-pinned Linux scanner image."
} >> "$OUT/capture-limits.txt"

# --- EOF normalization (strip trailing whitespace AND trailing blank lines) --
for f in "$OUT"/*.txt; do
  sed -i 's/[[:space:]]\+$//' "$f"
  sed -i -e :a -e '/^\n*$/{$d;N;ba}' "$f"
done

(
  cd "$ROOT"
  find docs/aces/inventory/shuffle-orborus/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"

echo "capture complete: $OUT"
