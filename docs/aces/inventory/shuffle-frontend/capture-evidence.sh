#!/usr/bin/env bash
set -euo pipefail

# SCN-010 / issue #354 — shuffle-frontend steady-state asset inventory capture.
#
# The shuffle-frontend asset is the nginx-served Shuffle web UI
# (ghcr.io/shuffle/shuffle-frontend:latest, upstream GHCR registry image)
# running as aptl-shuffle-frontend on aptl-security at static IP 172.20.0.21.
# It is a pre-built static React app served by nginx on container ports 80 and
# 443 (TLS), published to the host as 3443:443 and 3001:3001. TLS is terminated
# in nginx with the soc_certs material bind-mounted read-only: the public
# server.pem fullchain, the server.key PRIVATE KEY (scenario fixture captured
# verbatim), and the lab CA cert. It proxies the API to
# shuffle-backend:5001 (BACKEND_HOSTNAME=shuffle-backend). Non-destructive:
# observes the already-running lab and does NOT run aptl lab stop/start.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ASSET_DIR="$ROOT/docs/aces/inventory/shuffle-frontend"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-shuffle-frontend}"
IMAGE="${IMAGE:-ghcr.io/shuffle/shuffle-frontend:latest}"
CONTAINER_IP="${CONTAINER_IP:-172.20.0.21}"

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

# The shuffle-frontend compose block is extracted directly from
# docker-compose.yml with yq. A profile-filtered docker compose config cannot
# be used because the soc profile pulls in services that depend_on
# wazuh.manager and profile filtering invalidates the project.
yq -o=json '.services."shuffle-frontend"' "$ROOT/docker-compose.yml" | jq . > "$OUT/compose-service.shuffle-frontend.json"
record_limit "compose-service.shuffle-frontend.json is the authored docker-compose.yml service block (yq-extracted); a profile-filtered docker compose config could not be used because soc-profile services depend_on wazuh.manager and profile filtering invalidates the project."

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
  record_limit "Docker Buildx imagetools inspection failed for $IMAGE; see docker-buildx-imagetools.image.err for non-secret tool stderr. Image identity falls back to the registry RepoDigest in docker-inspect.container.json and the local config ID in docker-inspect.image.json."
fi

docker network inspect aptl_aptl-security | jq . > "$OUT/docker-network.aptl-security.json"
docker top "$CONTAINER" > "$OUT/docker-top.txt"
docker logs "$CONTAINER" --tail 500 2>&1 > "$OUT/docker-logs.shuffle-frontend.txt"

record_limit "Capture used the already-running aptl project (soc profile up) per operator direction and did not run aptl lab stop -v && aptl lab start; this bundle is a steady-state observation of that local lab, not a clean-reset rebuild proof."
record_limit "shuffle-frontend has no named Docker volume (its rootfs is the upstream image); it only bind-mounts the three soc_certs TLS files read-only. No docker-volume.*.json is emitted for this asset."
record_limit "The bind-mounted /etc/nginx/privkey.pem (host ./config/soc_certs/shuffle-frontend/server.key) is the frontend TLS PRIVATE KEY: captured as scenario fixture content in filesystem-tree.txt, filesystem-checksums.txt, and filesystem-sensitive-paths.txt."

# Build provenance: include any generated TLS source files present in this
# checkout; absent generated inputs are still captured from the running
# container bind targets.
source_inputs=("$ROOT/docker-compose.yml")
for generated_input in \
  "$ROOT/config/soc_certs/shuffle-frontend/server.pem" \
  "$ROOT/config/soc_certs/shuffle-frontend/server.key" \
  "$ROOT/config/soc_certs/lab-ca.pem"; do
  if [[ -f "$generated_input" ]]; then
    source_inputs+=("$generated_input")
  else
    record_limit "${generated_input#$ROOT/} is not present in this checkout; the running container bind target is captured from Docker/runtime evidence."
  fi
done
sha256sum "${source_inputs[@]}" | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"
record_limit "source-checksums.txt covers docker-compose.yml and any generated Shuffle frontend TLS source inputs present in this checkout; missing generated inputs are paired with runtime Docker/container evidence."

# --- OS packages (Debian dpkg) ----------------------------------------------
docker exec "$CONTAINER" sh -lc "dpkg-query -W -f='\${binary:Package}\t\${Version}\t\${Architecture}\n'" \
  | sort > "$OUT/os-packages.txt"

# --- Language / runtime manifests (nginx; static React build) ----------------
{
  printf "%s\n" "--nginx-version--"
  docker exec "$CONTAINER" nginx -v 2>&1 || true
  printf "%s\n" "--runtime-presence--"
  docker exec "$CONTAINER" sh -lc 'for t in nginx node npm yarn python3; do if command -v "$t" >/dev/null 2>&1; then printf "%s present: %s\n" "$t" "$(command -v "$t")"; else printf "%s absent\n" "$t"; fi; done' 2>&1 || true
  printf "%s\n" "--web-root-build-manifest--"
  docker exec "$CONTAINER" sh -lc 'ls -1 /usr/share/nginx/html 2>/dev/null | head -40' 2>&1 || true
  printf "%s\n" "--web-root-file-count--"
  docker exec "$CONTAINER" sh -lc 'find /usr/share/nginx/html -type f 2>/dev/null | wc -l' 2>&1 || true
  printf "%s\n" "--bundled-js-asset-names--"
  docker exec "$CONTAINER" sh -lc 'find /usr/share/nginx/html -type f \( -name "*.js" -o -name "*.css" \) 2>/dev/null | sort | head -40' 2>&1 || true
} > "$OUT/language-manifests.txt"
record_limit "shuffle-frontend serves a pre-built static React bundle from /usr/share/nginx/html; the runtime image has no node/npm/yarn and ships no package.json or node_modules, so language-manifests.txt records nginx version, runtime tool presence, and the built web-asset inventory rather than a JS package manifest. The authoritative JS dependency catalog (if recoverable) comes from the trivy/syft SBOMs."

# --- Filesystem manifest + checksums (nginx config + web root + os-release) --
docker exec "$CONTAINER" sh -lc '
  set -eu
  for root in /etc/nginx /usr/share/nginx/html /etc/lab-ca /etc/os-release; do
    [ -e "$root" ] || continue
    find "$root" -xdev \( -type f -o -type d -o -type l -o -type s -o -type p \) -print
  done \
    | sort -u \
    | while IFS= read -r path; do
        stability=stable
        sensitivity=plain
        case "$path" in
	          /etc/nginx/privkey.pem) sensitivity=secret_fixture ;;
	          /etc/*shadow*|/etc/*gshadow*) sensitivity=secret_fixture ;;
        esac
        stat -c "%F\t%A\t%a\t%u\t%U\t%g\t%G\t%s\t%Y\t${stability}\t${sensitivity}\t%n" "$path"
      done
' | awk '{gsub(/\\t/,"\t"); print}' > "$OUT/filesystem-tree.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  for root in /etc/nginx /usr/share/nginx/html /etc/lab-ca /etc/os-release; do
    [ -e "$root" ] || continue
    find "$root" -xdev -type f -print0
  done \
    | sort -zu \
    | xargs -0 -r sha256sum
' > "$OUT/filesystem-checksums.txt"
{
  printf "%s\n" "--/etc/nginx/privkey.pem--"
  docker exec "$CONTAINER" cat /etc/nginx/privkey.pem
} > "$OUT/filesystem-sensitive-paths.txt"
record_limit "filesystem-tree.txt scopes the manifest to the application surfaces (/etc/nginx config, /usr/share/nginx/html static React build, /etc/lab-ca CA, /etc/os-release); the rest of the upstream Debian rootfs is out of manifest scope (covered by os-packages.txt and the SBOMs). filesystem-checksums.txt includes /etc/nginx/privkey.pem as scenario TLS fixture content."

# --- Runtime baseline --------------------------------------------------------
# The Debian frontend image has no ss/netstat; listener/connection evidence
# falls back to raw /proc/net/tcp,tcp6,udp tables.
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
  (ps -eo pid,ppid,user,args || for p in /proc/[0-9]*; do printf "%s %s\n" "${p#/proc/}" "$(tr "\0" " " < "$p/cmdline" 2>/dev/null)"; done) 2>&1
' > "$OUT/runtime-baseline.txt"
record_limit "The shuffle-frontend Debian image does not include ss or netstat; listener and outbound-connection evidence in runtime-baseline.txt falls back to raw /proc/net/tcp,tcp6,udp,udp6 tables, complemented by docker top and osquery namespace-sharing evidence."

# --- Service-specific state: nginx + TLS + frontend reachability -------------
# nginx -T dumps the full active config.
{
  printf "%s\n" --nginx-version--
  docker exec "$CONTAINER" nginx -v 2>&1 || true
  printf "%s\n" --nginx-config-test--
  docker exec "$CONTAINER" nginx -t 2>&1 || true
  printf "%s\n" --nginx-config-dump--
  docker exec "$CONTAINER" nginx -T 2>&1 || true
  printf "%s\n" --listening-sockets--
  docker exec "$CONTAINER" sh -lc '(ss -lntp || netstat -lntp || cat /proc/net/tcp /proc/net/tcp6) 2>&1' || true
  printf "%s\n" --https-localhost-443-status--
  docker exec "$CONTAINER" sh -lc 'curl -ks -o /dev/null -w "https_status=%{http_code}\n" https://localhost:443/ 2>&1' || true
  printf "%s\n" --http-localhost-80-status--
  docker exec "$CONTAINER" sh -lc 'curl -s -o /dev/null -w "http_status=%{http_code}\n" http://localhost:80/ 2>&1' || true
  printf "%s\n" --tls-cert-subject-and-dates--
  docker exec "$CONTAINER" sh -lc 'curl -ksv https://localhost:443/ 2>&1 | grep -iE "subject:|issuer:|expire|start date|SSL connection" | head -10' || true
} > "$OUT/frontend-state.txt"

# --- Participant-vantage discovery: kali ------------------------------------
# Frontend is reachable on the security net (172.20.0.21:443/3001) and on the
# host-published ports 3443/3001; record what an in-range attacker resolves and
# reaches.
if docker inspect aptl-kali >/dev/null 2>&1; then
  docker exec aptl-kali sh -lc '
    set +e
    printf "%s\n" --dns--
    getent hosts shuffle-frontend aptl-shuffle-frontend '"$CONTAINER_IP"' 2>&1
    printf "%s\n" --route-to-security-net--
    ip route get '"$CONTAINER_IP"' 2>&1
    printf "%s\n" --tcp-probe-443--
    timeout 8 sh -c "nc -vz -w 3 '"$CONTAINER_IP"' 443 2>&1" 2>&1
    printf "%s\n" --tcp-probe-3001--
    timeout 8 sh -c "nc -vz -w 3 '"$CONTAINER_IP"' 3001 2>&1" 2>&1
    printf "%s\n" --tcp-probe-host-published-3443--
    timeout 8 sh -c "nc -vz -w 3 host.docker.internal 3443 2>&1" 2>&1
    timeout 8 sh -c "nc -vz -w 3 172.17.0.1 3443 2>&1" 2>&1
    printf "%s\n" --tcp-probe-host-published-3001--
    timeout 8 sh -c "nc -vz -w 3 172.17.0.1 3001 2>&1" 2>&1
    printf "%s\n" --ping--
    ping -c 1 -W 2 '"$CONTAINER_IP"' 2>&1 | sed -n "1,4p"
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
  "containerized osquery sharing aptl-shuffle-frontend PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-shuffle-frontend network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-shuffle-frontend";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%shuffle-frontend%";' \
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
  echo "- osquery apt_sources reflects the host-side scanner vantage; the target rootfs Debian dpkg state is captured directly in os-packages.txt."
} >> "$OUT/capture-limits.txt"

# --- EOF normalization (strip trailing whitespace AND trailing blank lines) --
for f in "$OUT"/*.txt; do
  sed -i 's/[[:space:]]\+$//' "$f"
  sed -i -e :a -e '/^\n*$/{$d;N;ba}' "$f"
done

(
  cd "$ROOT"
  find docs/aces/inventory/shuffle-frontend/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"

echo "capture complete: $OUT"
