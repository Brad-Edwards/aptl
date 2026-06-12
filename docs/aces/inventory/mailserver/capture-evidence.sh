#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
ASSET_DIR="$ROOT/docs/aces/inventory/mailserver"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-mailserver}"
IMAGE="${IMAGE:-ghcr.io/docker-mailserver/docker-mailserver:latest}"
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

compose_cmd() {
  local cmd=(docker compose --project-name "$COMPOSE_PROJECT_NAME")
  if [[ -f "$COMPOSE_ENV_FILE" ]]; then
    cmd+=(--env-file "$COMPOSE_ENV_FILE")
  else
    record_limit "Compose env file $COMPOSE_ENV_FILE was unavailable; compose config may rely only on shell environment"
  fi
  cmd+=(--profile mail "$@")
  "${cmd[@]}"
}

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

compose_cmd config --format json \
  | jq '.services.mailserver' > "$OUT/compose-service.mailserver.json"

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
docker volume inspect aptl_mailserver_data | jq . > "$OUT/docker-volume.mailserver-data.json"
docker volume inspect aptl_mailserver_state | jq . > "$OUT/docker-volume.mailserver-state.json"
docker volume inspect aptl_mailserver_logs | jq . > "$OUT/docker-volume.mailserver-logs.json"
docker top "$CONTAINER" > "$OUT/docker-top.txt"
docker logs "$CONTAINER" > "$OUT/docker-logs.mailserver.txt" 2>&1

record_limit "Capture used the already-running aptl project and started only the mail profile service non-destructively; no aptl lab stop -v && aptl lab start clean reset was run for this bundle"
record_limit "The mounted containers/mailserver/setup.sh was executed manually after container start before capture because the upstream docker-mailserver image waited for accounts and did not automatically run the mounted script"

sha256sum \
  "$ROOT/docker-compose.yml" \
  "$ROOT/containers/mailserver/setup.sh" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"

docker exec "$CONTAINER" sh -lc '
  if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${Architecture}\n" | sort
  elif command -v rpm >/dev/null 2>&1; then
    rpm -qa --queryformat "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n" | sort
  else
    echo "no supported OS package manager found"
  fi
' > "$OUT/os-packages.txt"

{
  echo "--language-manifest-scan--"
  docker exec "$CONTAINER" sh -lc '
    set -eu
    found=0
    for path in /app/package.json /app/package-lock.json /app/requirements.txt /usr/local/bin/pip /usr/bin/pip3 /usr/bin/python3; do
      if [ -e "$path" ]; then
        found=1
        printf "%s\n" "$path"
      fi
    done
    if command -v python3 >/dev/null 2>&1 && python3 -m pip --version >/dev/null 2>&1; then
      found=1
      echo "--pip-freeze--"
      python3 -m pip freeze | sort
    fi
    if [ "$found" = 0 ]; then
      echo "No application language manifests or pip environment were present in the mailserver container."
    fi
  '
} > "$OUT/language-manifests.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  roots="
    /tmp/setup.sh
    /tmp/docker-mailserver
    /etc/postfix
    /etc/dovecot
    /etc/opendkim
    /etc/opendmarc
    /etc/postsrsd
    /etc/supervisor
    /var/mail
    /var/mail-state
    /var/log/mail
  "
  for root in $roots; do
    [ -e "$root" ] || continue
    find "$root" -xdev \( -type f -o -type d -o -type l \) -print
  done \
    | sort -u \
    | while IFS= read -r path; do
        stat -c "%F %A %a %u %U %g %G %s %Y %n" "$path"
      done
' > "$OUT/filesystem-tree.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  roots="
    /tmp/setup.sh
    /tmp/docker-mailserver
    /etc/postfix
    /etc/dovecot
    /etc/opendkim
    /etc/opendmarc
    /etc/postsrsd
    /etc/supervisor
    /var/mail
    /var/mail-state
    /var/log/mail
  "
  for root in $roots; do
    [ -e "$root" ] || continue
    find "$root" -xdev -type f -print
  done \
    | sort -u \
    | xargs -r sha256sum
' > "$OUT/filesystem-checksums.txt"

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
  echo --capabilities-pid1--
  grep "^Cap" /proc/1/status || true
  echo --environment--
  env | sort
  echo --listeners--
  (ss -lntup || netstat -lntup || true) 2>&1
  echo --mounts--
  mount | sed -n "1,180p"
  echo --users--
  getent passwd | sed -n "1,240p" || true
  echo --groups--
  getent group | sed -n "1,240p" || true
  echo --process-tree--
  ps -eo pid,ppid,user,args || true
  echo --mail-versions--
  (postconf mail_version || true) 2>&1
  (dovecot --version || true) 2>&1
  (amavis -V || true) 2>&1
  (rspamadm --version || true) 2>&1
' > "$OUT/runtime-baseline.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  echo --setup-email-list--
  (setup email list || true) 2>&1
  echo --setup-alias-list--
  (setup alias list || true) 2>&1
  echo --postfix-non-default-config--
  (postconf -n || true) 2>&1
  echo --dovecot-non-default-config--
  (doveconf -n || true) 2>&1
  echo --postqueue--
  (postqueue -p || true) 2>&1
  echo --supervisor--
  (supervisorctl status || true) 2>&1
' > "$OUT/mailserver-state.txt"

if docker inspect aptl-kali >/dev/null 2>&1; then
  docker exec aptl-kali sh -lc '
    set +e
    echo --dns--
    getent hosts mail.techvault.local mailserver aptl-mailserver 2>&1
    echo --ports--
    for port in 25 143 465 587 993; do
      timeout 5 sh -c "nc -vz 172.20.1.21 $port" 2>&1
    done
    echo --smtp-banner--
    timeout 5 sh -c "printf '\''EHLO kali.techvault.local\r\nQUIT\r\n'\'' | nc 172.20.1.21 25" 2>&1
    echo --submission-banner--
    timeout 5 sh -c "printf '\''EHLO kali.techvault.local\r\nQUIT\r\n'\'' | nc 172.20.1.21 587" 2>&1
    echo --imap-banner--
    timeout 5 sh -c "printf '\''a001 CAPABILITY\r\na002 LOGOUT\r\n'\'' | nc 172.20.1.21 143" 2>&1
    echo --smtps-probe--
    timeout 8 sh -c "printf '\''QUIT\r\n'\'' | openssl s_client -connect 172.20.1.21:465 -servername mail.techvault.local -brief" 2>&1
    echo --imaps-probe--
    timeout 8 sh -c "printf '\''a001 CAPABILITY\r\na002 LOGOUT\r\n'\'' | openssl s_client -connect 172.20.1.21:993 -servername mail.techvault.local -brief" 2>&1
    true
  ' > "$OUT/participant-discovery.kali.txt"
else
  record_limit "Kali participant-vantage discovery was skipped because aptl-kali was not present"
  printf 'aptl-kali container unavailable\n' > "$OUT/participant-discovery.kali.txt"
fi

if command -v mtree >/dev/null 2>&1; then
  docker export "$CONTAINER" \
    | tar -tf - \
    | grep -E '^(tmp/setup\.sh|tmp/docker-mailserver|etc/(postfix|dovecot|opendkim|opendmarc|postsrsd|supervisor)|var/(mail|mail-state|log/mail))' \
    | sort > "$OUT/filesystem-mtree-input.txt"
  record_limit "mtree was available on the host, but container tar stream was recorded as path input rather than a native in-container mtree manifest"
else
  record_limit "mtree/AIDE/Tripwire filesystem manifest tooling was unavailable; filesystem-tree.txt and filesystem-checksums.txt provide the committed stable manifest for the captured mailserver scope"
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
  "containerized osquery sharing aptl-mailserver PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-mailserver network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-mailserver";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%docker-mailserver%";' \
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
} >> "$OUT/capture-limits.txt"

sed -i 's/[[:space:]]\+$//' "$OUT"/*.txt

(
  cd "$ROOT"
  find docs/aces/inventory/mailserver/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
