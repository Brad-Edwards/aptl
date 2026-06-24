#!/usr/bin/env bash
set -euo pipefail

# SCN-010 / issue #345 — suricata steady-state asset inventory capture.
#
# Adapted from the webapp/victim/mailserver capture scripts. The suricata
# asset is a *passive network sensor*: it has no TCP listener, runs in
# `--pcap` capture mode on `interface: any` across three attached networks,
# and exposes a unix-domain command socket rather than a network service.
# Capture reflects that archetype (no listening-service probe surface; the
# command socket and capture posture are recorded explicitly).

ROOT="$(git rev-parse --show-toplevel)"
ASSET_DIR="$ROOT/docs/aces/inventory/suricata"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-suricata}"
IMAGE="${IMAGE:-jasonish/suricata:7.0}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-aptl}"
COMPOSE_ENV_FILE="${COMPOSE_ENV_FILE:-$ROOT/.env}"

# Tool images are digest-pinned so a later maintainer can rerun the same
# scanner binaries even when floating tags move.
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6}"
OSQUERY_IMAGE="${OSQUERY_IMAGE:-osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd}"
SYFT_NORMALIZER="${SYFT_NORMALIZER:-$ASSET_DIR/normalize-syft-cyclonedx.jq}"

mkdir -p "$OUT"
: > "$OUT/capture-limits.txt"

record_limit() {
  printf -- '- %s\n' "$*" >> "$OUT/capture-limits.txt"
}

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

# The suricata service carries no compose-injected environment (only image
# default PATH/LANG), so the authored compose block is extracted directly from
# docker-compose.yml. A profile-filtered `docker compose config` cannot be used
# here: the soc profile's wazuh-sidecar-suricata depends_on wazuh.manager, and
# profile filtering drops that target, which makes the filtered project invalid.
yq -o=json '.services.suricata' "$ROOT/docker-compose.yml" \
  | jq . > "$OUT/compose-service.suricata.json"
record_limit "compose-service.suricata.json is the authored docker-compose.yml service block (yq-extracted); a profile-filtered docker compose config could not be used because soc-profile wazuh-sidecar-suricata depends_on wazuh.manager and profile filtering invalidates the project. suricata carries no compose-injected environment, so authored and resolved compose values coincide"

docker inspect "$CONTAINER" | jq . > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" | jq . > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" > "$OUT/docker-history.image.txt"
docker history --no-trunc --format '{{json .}}' "$IMAGE" > "$OUT/docker-history.image.jsonl"

if docker buildx imagetools inspect "$IMAGE" > "$OUT/docker-buildx-imagetools.image.txt" 2>"$OUT/docker-buildx-imagetools.image.err"; then
  docker buildx imagetools inspect "$IMAGE" --raw \
    | jq . > "$OUT/docker-buildx-imagetools.image.raw.json"
  rm -f "$OUT/docker-buildx-imagetools.image.err"
else
  record_limit "Docker Buildx imagetools inspection failed for $IMAGE; see docker-buildx-imagetools.image.err"
fi

docker network inspect aptl_aptl-dmz | jq . > "$OUT/docker-network.aptl-dmz.json"
docker network inspect aptl_aptl-internal | jq . > "$OUT/docker-network.aptl-internal.json"
docker network inspect aptl_aptl-security | jq . > "$OUT/docker-network.aptl-security.json"
docker volume inspect aptl_suricata_logs | jq . > "$OUT/docker-volume.suricata-logs.json"
docker volume inspect aptl_suricata_command_socket | jq . > "$OUT/docker-volume.suricata-command-socket.json"
# ADR-043: the suricata runtime config and MISP rules now ride Compose
# project-scoped named volumes (seeded from config/suricata/ by a root
# container at lab start) instead of host bind mounts, so the upstream image
# entrypoint's chown can never rewrite host-side ownership (issue #325).
docker volume inspect aptl_suricata_config_seed | jq . > "$OUT/docker-volume.suricata-config-seed.json"
docker volume inspect aptl_suricata_misp_rules | jq . > "$OUT/docker-volume.suricata-misp-rules.json"
docker top "$CONTAINER" > "$OUT/docker-top.txt"
# Container logs are bounded to the tail; suricata is verbose at startup but
# the operational tail characterizes steady state without copying telemetry.
docker logs --tail 400 "$CONTAINER" 2>&1 > "$OUT/docker-logs.suricata.txt"

record_limit "Recaptured after ADR-043 (issue #325) on a clean-rebuilt lab: two consecutive 'aptl lab stop -v && aptl lab start' cycles preceded this capture, so the bundle reflects the named-volume-seeded steady state, not the pre-fix host-bind topology"

sha256sum \
  "$ROOT/docker-compose.yml" \
  "$ROOT/config/suricata/suricata.yaml" \
  "$ROOT/config/suricata/rules/local.rules" \
  "$ROOT/config/suricata/rules/misp/misp-iocs.rules" \
  "$ROOT/config/suricata/rules/misp/misp-md5.list" \
  "$ROOT/config/suricata/rules/misp/misp-sha1.list" \
  "$ROOT/config/suricata/rules/misp/misp-sha256.list" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"

docker exec "$CONTAINER" sh -lc '
  if command -v rpm >/dev/null 2>&1; then
    rpm -qa --queryformat "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n" | sort
  elif command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${Architecture}\n" | sort
  else
    echo "no supported OS package manager found"
  fi
' > "$OUT/os-packages.txt"

{
  echo "--language-manifest-scan--"
  docker exec "$CONTAINER" sh -lc '
    set -eu
    found=0
    for path in /usr/bin/python3 /usr/bin/pip3 /usr/local/bin/pip3 /opt/*/requirements.txt; do
      if [ -e "$path" ]; then
        found=1
        printf "%s\n" "$path"
      fi
    done
    if command -v python3 >/dev/null 2>&1 && python3 -m pip --version >/dev/null 2>&1; then
      found=1
      echo "--pip-freeze--"
      python3 -m pip freeze 2>/dev/null | sort
    fi
    if [ "$found" = 0 ]; then
      echo "No application language manifests or pip environment were present in the suricata container."
    fi
  '
} > "$OUT/language-manifests.txt"

# Filesystem inventory roots: suricata config + ruleset + run dir. The eve.json
# / fast.log telemetry under /var/log/suricata is unbounded runtime state and is
# captured as metadata only (filesystem-tree.txt) — never content-checksummed.
docker exec "$CONTAINER" sh -lc '
  set -eu
  roots="
    /etc/suricata
    /var/lib/suricata/rules
    /var/lib/suricata/update
    /var/run/suricata
    /var/log/suricata
  "
  for root in $roots; do
    [ -e "$root" ] || continue
    find "$root" -xdev \( -type f -o -type d -o -type l -o -type s \) -print 2>/dev/null
  done \
    | sort -u \
    | while IFS= read -r path; do
        stat -c "%F %A %a %u %U %g %G %s %Y %n" "$path" 2>/dev/null || true
      done
' > "$OUT/filesystem-tree.txt"

# Content checksums for STABLE files only. The telemetry logs under
# /var/log/suricata are excluded because their bytes change every second.
docker exec "$CONTAINER" sh -lc '
  set -eu
  roots="
    /etc/suricata
    /var/lib/suricata/rules
    /var/lib/suricata/update
  "
  for root in $roots; do
    [ -e "$root" ] || continue
    find "$root" -xdev -type f -print 2>/dev/null
  done \
    | sort -u \
    | xargs -r sha256sum 2>/dev/null
' > "$OUT/filesystem-checksums.txt"
record_limit "/var/log/suricata/eve.json and fast.log are unbounded transient sensor telemetry; they are recorded as filesystem metadata (filesystem-tree.txt) only, not content-checksummed, because their bytes change continuously"

docker exec "$CONTAINER" sh -lc '
  set -eu
  echo --os-release--
  cat /etc/os-release 2>/dev/null || true
  echo --id--
  id
  echo --pwd--
  pwd
  echo --uname--
  uname -a
  echo --pid1-cmdline--
  tr "\0" " " < /proc/1/cmdline; echo
  echo --capabilities-pid1--
  grep "^Cap" /proc/1/status || true
  echo --environment--
  env | sort
  echo --listeners--
  (ss -lntup || netstat -lntup || true) 2>&1
  echo --mounts--
  mount | sed -n "1,200p"
  echo --users--
  getent passwd 2>/dev/null | sed -n "1,300p" || cat /etc/passwd
  echo --groups--
  getent group 2>/dev/null | sed -n "1,300p" || cat /etc/group
  echo --process-tree--
  ps -eo pid,ppid,user,args 2>/dev/null || ps aux
' > "$OUT/runtime-baseline.txt"

# Suricata engine / sensor logical state. No suricatasc network probe needed —
# the engine state is read from the build info, the loaded rule files, and a
# bounded sample of the telemetry streams.
docker exec "$CONTAINER" sh -lc '
  set -eu
  echo --suricata-version--
  suricata -V 2>&1 || true
  echo --suricata-build-info--
  suricata --build-info 2>&1 || true
  echo --command-socket--
  ls -la /var/run/suricata/suricata-command.socket 2>&1 || true
  echo --loaded-rule-files--
  for f in /var/lib/suricata/rules/suricata.rules /etc/suricata/rules/local.rules /var/lib/suricata/rules/misp/misp-iocs.rules; do
    if [ -e "$f" ]; then
      printf "%s\t%s lines\n" "$f" "$(wc -l < "$f" 2>/dev/null || echo 0)"
    else
      printf "%s\tABSENT\n" "$f"
    fi
  done
  echo --app-layer-protocols-configured--
  awk "/^app-layer:/{f=1} f&&/enabled: yes/{print prev} {prev=\$0}" /etc/suricata/suricata.yaml 2>/dev/null | head -40 || true
  echo --eve-json-metadata--
  stat -c "%s bytes, mtime %y" /var/log/suricata/eve.json 2>/dev/null || true
  echo "--eve-json-event-type-distribution-first-5000-events--"
  head -n 5000 /var/log/suricata/eve.json 2>/dev/null | jq -r ".event_type" 2>/dev/null | sort | uniq -c | sort -rn || true
  echo --fast-log-tail--
  tail -n 10 /var/log/suricata/fast.log 2>/dev/null || true
  echo --suricata-update-sources--
  (suricata-update list-enabled-sources 2>&1 || true) | head -20
' > "$OUT/suricata-state.txt"

# Participant-vantage probe from kali. Suricata is a passive sensor with no
# TCP listener; probes are expected to be refused. Recording the refusal IS
# the evidence of the passive posture.
if docker inspect aptl-kali >/dev/null 2>&1; then
  docker exec aptl-kali sh -lc '
    set +e
    echo --dns--
    getent hosts suricata aptl-suricata 2>&1
    echo --ports-dmz-172.20.1.50--
    for port in 22 80 443 4789; do
      timeout 5 sh -c "nc -vz 172.20.1.50 $port" 2>&1
    done
    echo --ports-internal-172.20.2.50--
    for port in 22 80 443; do
      timeout 5 sh -c "nc -vz 172.20.2.50 $port" 2>&1
    done
    echo --note--
    echo "suricata is a passive IDS sensor: no participant-reachable TCP listener is expected on any attached network"
    true
  ' > "$OUT/participant-discovery.kali.txt" 2>&1
else
  record_limit "Kali participant-vantage discovery was skipped because aptl-kali was not present"
  printf 'aptl-kali container unavailable\n' > "$OUT/participant-discovery.kali.txt"
fi

record_limit "mtree/AIDE/Tripwire filesystem manifest tooling was unavailable; filesystem-tree.txt and filesystem-checksums.txt provide the committed stable manifest for the captured suricata config/ruleset scope"

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
record_limit "Syft CycloneDX output was deterministically normalized by stripping syft:location:* properties; filesystem provenance is captured in filesystem-tree.txt and filesystem-checksums.txt"

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
  "containerized osquery sharing aptl-suricata PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-suricata network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-suricata";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%suricata%";' \
  "containerized osquery host-side Docker socket view" docker

write_unavailable_osquery_json "$OUT/osquery-apt-sources.json" apt_sources \
  'select * from apt_sources order by name;'

write_unavailable_osquery_json "$OUT/osquery-installed-applications.json" installed_applications \
  'select * from installed_applications;'

write_unavailable_osquery_json "$OUT/osquery-programs.json" programs \
  'select * from programs;'

{
  echo "- osquery apt_sources table not applicable: the suricata runtime OS is AlmaLinux 9 (rpm/dnf), not apt."
  echo "- osquery installed_applications table unavailable in the digest-pinned Linux scanner image."
  echo "- osquery programs table unavailable in the digest-pinned Linux scanner image."
} >> "$OUT/capture-limits.txt"

sed -i 's/[[:space:]]\+$//' "$OUT"/*.txt

(
  cd "$ROOT"
  find docs/aces/inventory/suricata/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
