#!/usr/bin/env bash
set -euo pipefail

# SCN-010 / issue #360 steady-state asset inventory capture for the
# TechVault `shuffle-backend` container. Non-destructive: it observes the
# already-running local lab and does NOT run `aptl lab stop -v && aptl lab
# start`, so the bundle is steady-state observation, not clean-reset rebuild
# proof. Re-runnable: tool images are digest-pinned and outputs are sorted.

ROOT="$(git rev-parse --show-toplevel)"
ASSET_DIR="$ROOT/docs/aces/inventory/shuffle-backend"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-shuffle-backend}"
OPENSEARCH_CONTAINER="${OPENSEARCH_CONTAINER:-aptl-shuffle-opensearch}"
ORBORUS_CONTAINER="${ORBORUS_CONTAINER:-aptl-shuffle-orborus}"
FRONTEND_CONTAINER="${FRONTEND_CONTAINER:-aptl-shuffle-frontend}"
IMAGE="${IMAGE:-ghcr.io/shuffle/shuffle-backend:latest}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-aptl}"

# Tool images are digest-pinned so reruns use the same scanner binaries even
# when floating tags move (shared with the misp capture bundle).
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6}"
OSQUERY_IMAGE="${OSQUERY_IMAGE:-osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd}"
SYFT_NORMALIZER="${SYFT_NORMALIZER:-$ASSET_DIR/normalize-syft-cyclonedx.jq}"

mkdir -p "$OUT"
# Start from a clean evidence dir so the committed bundle reflects only this
# capture (stale #353 smoke-pass artifacts are tracked in git and restorable).
find "$OUT" -maxdepth 1 -type f -delete
: > "$OUT/capture-limits.txt"

record_limit() {
  printf -- '- %s\n' "$*" >> "$OUT/capture-limits.txt"
}

# Text redaction for raw command output. Catches NAME=value secret env, JSON
# "key":"value" secrets, and PEM private-key envelopes.
redact_stream() {
  sed -E \
    -e 's/(PASSWORD|PASS|SECRET|TOKEN|APIKEY|API_KEY|KEY|COOKIE|SESSION|PRIVATE_KEY|JWT)=([^[:space:]]+)/\1=<REDACTED>/Ig' \
    -e 's/("?(password|pass|secret|token|apikey|api_key|session_key|private_key|jwt|cookie)"?[[:space:]]*[:=][[:space:]]*")[^"]*(")/\1<REDACTED>\3/Ig' \
    -e 's/(31a211c4-ea5c-4a49-b022-5e2434e758a7)/<REDACTED-SCENARIO-APIKEY>/g' \
    -e 's/(ShuffleAdmin2024!|StrongPassword123!)/<REDACTED-SCENARIO-FIXTURE>/g' \
    -e 's/-----BEGIN [A-Z ]*PRIVATE KEY-----/<REDACTED-PRIVATE-KEY-BEGIN>/g' \
    -e 's/-----END [A-Z ]*PRIVATE KEY-----/<REDACTED-PRIVATE-KEY-END>/g'
}

redact_env_jq='
  def redact_env:
    if contains("=") then
      capture("^(?<name>[^=]+)=(?<value>.*)$") as $m
      | if ($m.name | test("(PASSWORD|PASS|SECRET|TOKEN|APIKEY|API_KEY|KEY|COOKIE|SESSION|PRIVATE_KEY|JWT)$"; "i")) then
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
          if (.key | test("(password|pass|secret|token|apikey|api_key|session_key|private_key|jwt|cookie|authorization)$"; "i")) then
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

uv run python -c '
import sys, yaml, json
with open(sys.argv[1]) as fh:
    data = yaml.safe_load(fh)
json.dump(data["services"]["shuffle-backend"], sys.stdout)
' "$ROOT/docker-compose.yml" \
  | jq '
      .environment |= map(
        if test("^(?<name>[^=]+)=") then
          capture("^(?<name>[^=]+)=(?<value>.*)$") as $m
          | if ($m.name | test("(PASSWORD|PASS|SECRET|TOKEN|APIKEY|API_KEY|KEY|COOKIE|SESSION|PRIVATE_KEY|JWT)$"; "i"))
            then "\($m.name)=<REDACTED-\($m.name | gsub("_"; "-"))>"
            else .
            end
        else
          .
        end
      )
    ' > "$OUT/compose-service.shuffle-backend.json"
record_limit "Compose service evidence was extracted from docker-compose.yml with yq because the full local compose project has an unrelated invalid dependency reference that prevents docker compose config from rendering."

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
  # Capture the amd64 SLSA provenance attestation manifest when present.
  attest_digest="$(docker buildx imagetools inspect "$IMAGE" --raw 2>/dev/null \
    | jq -r '.manifests[]? | select(.annotations["vnd.docker.reference.type"]=="attestation-manifest" and (.platform.architecture=="unknown")) | .digest' \
    | head -n1 || true)"
  if [ -n "${attest_digest:-}" ]; then
    docker buildx imagetools inspect "${IMAGE%%:*}@${attest_digest}" --raw 2>/dev/null \
      | jq . > "$OUT/docker-buildx-imagetools.attestation-amd64.raw.json" || \
      record_limit "Attestation manifest ${attest_digest} could not be re-fetched raw."
  else
    record_limit "No attestation-manifest entry was found in the image index for $IMAGE."
  fi
  rm -f "$OUT/docker-buildx-imagetools.image.err"
else
  record_limit "Docker Buildx imagetools inspection failed for $IMAGE; see docker-buildx-imagetools.image.err."
fi

docker network inspect aptl_aptl-security | jq . > "$OUT/docker-network.aptl-security.json"
docker volume inspect aptl_shuffle_data | jq . > "$OUT/docker-volume.shuffle-data.json"
docker top "$CONTAINER" | redact_stream > "$OUT/docker-top.txt"
docker logs "$CONTAINER" --tail 500 2>&1 | redact_stream > "$OUT/docker-logs.shuffle-backend.txt"

record_limit "Capture used the already-running aptl project per operator direction and did not run aptl lab stop -v && aptl lab start; this bundle is a steady-state observation of that local lab, not clean-reset rebuild proof."
record_limit "Full filesystem evidence is captured as compressed manifests. SDL encodes load-bearing participant-visible paths and structured runtime surfaces directly; byte-identical rebuild proof remains out of scope for this inventory issue."
record_limit "Shuffle persistent state lives in the shuffle-opensearch datastore, not in the aptl_shuffle_data volume (which is empty at steady state). Application state was captured via the Shuffle backend HTTP API and OpenSearch _cat/indices, with apikey/password/session fields redacted."
record_limit "Secret env values, the scenario admin password, the SHUFFLE_DEFAULT_APIKEY, and the OpenSearch password are redacted from every committed artifact; their declaration, classification, and mount/source are captured instead."

sha256sum \
  "$ROOT/docker-compose.yml" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"
record_limit "shuffle-backend mounts only the host docker.sock and the aptl_shuffle_data named volume; it has no first-party local config files under config/. The Wazuh-side custom-shuffle integration that posts alerts to this backend is owned by the wazuh-manager inventory, not this asset."

# --- OS packages (Alpine apk) ------------------------------------------------
docker exec "$CONTAINER" sh -lc '
  set -eu
  arch="$(cat /etc/apk/arch 2>/dev/null || echo unknown)"
  apk info -v 2>/dev/null | sort | while IFS= read -r nv; do
    printf "%s\t%s\n" "$nv" "$arch"
  done
' > "$OUT/os-packages.txt"

# --- Language / dependency manifests (Go) ------------------------------------
{
  printf '%s\n' "--manifest-paths--"
  docker exec "$CONTAINER" sh -lc '
    set -eu
    for path in /app/go.mod /app/go.sum; do
      [ -e "$path" ] && stat -c "%n\t%s bytes" "$path" || true
    done
  '
  printf '%s\n' "--go-version-embedded--"
  docker exec "$CONTAINER" sh -lc 'go version -m /app/shufflebackend 2>/dev/null | sed -n "1,5p"' 2>/dev/null \
    || echo "go toolchain not present in runtime image; embedded module table is captured via syft/trivy SBOM"
  printf '%s\n' "--go-mod--"
  docker exec "$CONTAINER" sh -lc 'cat /app/go.mod 2>/dev/null' || true
  printf '%s\n' "--go-sum-module-count--"
  docker exec "$CONTAINER" sh -lc 'awk "{print \$1}" /app/go.sum 2>/dev/null | sort -u | wc -l' || true
} > "$OUT/language-manifests.txt"
record_limit "Go compiler/toolchain is not present in the runtime image; the authoritative Go module dependency table is sourced from the trivy/syft SBOMs (go-module catalog), not from an in-image go list."

# --- Filesystem tree + checksums --------------------------------------------
FS_ROOTS='/app /app_gen /app_sdk /shuffle-database /etc /run'

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
          /shuffle-database/*) stability=volume_backed ;;
          /app/generated/*) stability=runtime_created ;;
          /run/*) stability=runtime_created ;;
          /etc/*shadow*|/etc/*passwd-*) sensitivity=operator_secret ;;
        esac
        stat -c \"%F\t%A\t%a\t%u\t%U\t%g\t%G\t%s\t%Y\t\${stability}\t\${sensitivity}\t%n\" \"\$path\"
      done
" | awk '{gsub(/\\t/,"\t"); print}' | gzip -n > "$OUT/filesystem-tree.txt.gz"
rm -f "$OUT/filesystem-tree.txt"

docker exec "$CONTAINER" sh -lc "
  set -eu
  for root in $FS_ROOTS; do
    [ -e \"\$root\" ] || continue
    find \"\$root\" -xdev -type f -print0
  done \
    | sort -zu \
    | xargs -0 -r sha256sum
" | xz -9 -c > "$OUT/filesystem-checksums.txt.xz"
rm -f "$OUT/filesystem-checksums.txt"

# --- Runtime baseline --------------------------------------------------------
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
  printf "%s\n" --no-new-privs-pid1--
  grep "^NoNewPrivs" /proc/1/status || true
  printf "%s\n" --environment--
  env | sort
  printf "%s\n" --listeners--
  (netstat -lntup || true) 2>&1
  printf "%s\n" --connection-state-summary--
  (netstat -nt 2>/dev/null | awk "NR>2{print \$6}" | sort | uniq -c | sort -rn || true) 2>&1
  printf "%s\n" --established-peer-summary--
  (netstat -nt 2>/dev/null | awk "\$6==\"ESTABLISHED\"{split(\$4,l,\":\"); split(\$5,r,\":\"); lp=l[length(l)]; rp=r[length(r)]; if(lp==\"5001\") print \"inbound  -> local :5001\"; else print \"outbound -> remote :\"rp}" | sort | uniq -c | sort -rn | head -20 || true) 2>&1
  printf "%s\n" --mounts--
  mount | sed -n "1,220p"
  printf "%s\n" --users--
  getent passwd | sed -n "1,260p" || true
  printf "%s\n" --groups--
  getent group | sed -n "1,260p" || true
  printf "%s\n" --process-tree--
  ps -eo pid,ppid,user,args 2>/dev/null || ps -ef || true
  printf "%s\n" --shells--
  cat /etc/shells 2>/dev/null || true
  printf "%s\n" --binary-info--
  ls -l /app/shufflebackend
  file /app/shufflebackend 2>/dev/null || true
' | redact_stream > "$OUT/runtime-baseline.txt"

# --- Shuffle application state (HTTP API + OpenSearch datastore) -------------
# The shuffle-backend Alpine image has no jq, so wget runs in-container (raw
# JSON) and jq/redaction run on the host. jq projections select only structural
# fields; apikey/password/session fields are dropped and redact_stream is the
# defense-in-depth backstop.
fetch_be() {
  docker exec "$CONTAINER" sh -c \
    'wget -qO- --timeout=15 --header="Authorization: Bearer $SHUFFLE_DEFAULT_APIKEY" "http://localhost:5001$1"' _ "$1" 2>/dev/null
}
fetch_os() {
  docker exec "$CONTAINER" sh -c \
    'A="Authorization: Basic $(printf "%s" "$SHUFFLE_OPENSEARCH_USERNAME:$SHUFFLE_OPENSEARCH_PASSWORD" | base64 | tr -d "\n")"; wget -qO- --timeout=15 --no-check-certificate --header="$A" "${SHUFFLE_OPENSEARCH_URL%/}$1"' _ "$1" 2>/dev/null
}
post_os() {
  docker exec "$CONTAINER" sh -c \
    'A="Authorization: Basic $(printf "%s" "$SHUFFLE_OPENSEARCH_USERNAME:$SHUFFLE_OPENSEARCH_PASSWORD" | base64 | tr -d "\n")"; wget -qO- --timeout=15 --no-check-certificate --header="$A" --header="Content-Type: application/json" --post-data="$2" "${SHUFFLE_OPENSEARCH_URL%/}$1"' _ "$1" "$2" 2>/dev/null
}

{
  printf "%s\n" --backend-health--
  fetch_be /api/v1/health | jq "{success, self_test_run_status: (.workflows.run_status // \"\"), self_test_workflow_id: (.workflows.workflow_id // \"\"), self_test_delete: (.workflows.delete // null), self_test_run: (.workflows.run // null)}" 2>/dev/null || echo "health unavailable"

  printf "%s\n" --opensearch-info--
  fetch_os "/" | jq "{cluster_name, version: .version.number, distribution: .version.distribution, lucene: .version.lucene_version}" 2>/dev/null || echo "opensearch info unavailable"

  printf "%s\n" --opensearch-indices--
  fetch_os "/_cat/indices?v&h=index,health,docs.count,store.size&s=index" || echo "opensearch indices unavailable"

  printf "%s\n" --workflows-summary--
  fetch_be /api/v1/workflows | jq "{count: ((.workflows? // .) | if type==\"array\" then length else 0 end), workflows: [((.workflows? // .)[]? | objects) | {id, name, org_id, public, sharing, action_count: ((.actions // []) | length), trigger_count: ((.triggers // []) | length), is_valid}]}" 2>/dev/null || echo "workflows unavailable"

  printf "%s\n" --apps-summary--
  fetch_be /api/v1/apps | jq "{count: ((.apps? // .) | if type==\"array\" then length else 0 end), apps: ([((.apps? // .)[]? | objects) | {name, app_version, is_valid, generated, activated, action_count: ((.actions // []) | length), categories: (.categories // [])}] | sort_by(.name))}" 2>/dev/null || echo "apps unavailable"

  printf "%s\n" --users-summary--
  fetch_be /api/v1/users | jq "{count: ((.users? // .) | if type==\"array\" then length else 0 end), users: [((.users? // .)[]? | objects) | {id, username, role, active, verified, org_count: ((.orgs // []) | length)}]}" 2>/dev/null || echo "users unavailable"

  printf "%s\n" --opensearch-organizations--
  post_os "/organizations/_search" "{\"size\":50,\"_source\":[\"id\",\"name\",\"org\",\"role\",\"creator_org\",\"child_orgs\",\"manager_orgs\",\"region\",\"users.username\",\"users.role\"]}" \
    | jq "{total: .hits.total.value, organizations: [.hits.hits[]?._source]}" 2>/dev/null || echo "organizations search unavailable"

  printf "%s\n" --opensearch-users--
  post_os "/users/_search" "{\"size\":50,\"_source\":[\"id\",\"username\",\"role\",\"active\",\"verified\",\"creationtime\",\"orgs.name\",\"orgs.role\"]}" \
    | jq "{total: .hits.total.value, users: [.hits.hits[]?._source]}" 2>/dev/null || echo "users search unavailable"

  printf "%s\n" --opensearch-workflowapps--
  post_os "/workflowapp-000001/_search" "{\"size\":50,\"_source\":[\"name\",\"app_version\",\"is_valid\",\"generated\",\"activated\",\"sharing\",\"public\",\"categories\"]}" \
    | jq "{total: .hits.total.value, apps: ([.hits.hits[]?._source] | sort_by(.name))}" 2>/dev/null || echo "workflowapp search unavailable"
} | redact_stream > "$OUT/shuffle-state.txt"

# --- Participant-vantage discovery ------------------------------------------
if docker inspect "$ORBORUS_CONTAINER" >/dev/null 2>&1; then
  docker exec "$ORBORUS_CONTAINER" sh -lc '
    set +e
    printf "%s\n" --dns--
    getent hosts shuffle-backend aptl-shuffle-backend 2>&1 || nslookup shuffle-backend 2>&1
    printf "%s\n" --api-base--
    wget -qO- --timeout=8 http://shuffle-backend:5001/api/v1/health 2>&1 | head -c 200; echo
    printf "%s\n" --tcp5001--
    (timeout 5 sh -c "wget -q --spider http://shuffle-backend:5001/ 2>&1; echo rc=$?") 2>&1
    true
  ' | redact_stream > "$OUT/participant-discovery.shuffle-orborus.txt"
else
  record_limit "shuffle-orborus participant-vantage discovery was skipped because $ORBORUS_CONTAINER was not present."
  printf '%s container unavailable\n' "$ORBORUS_CONTAINER" > "$OUT/participant-discovery.shuffle-orborus.txt"
fi

if docker inspect aptl-kali >/dev/null 2>&1; then
  docker exec aptl-kali sh -lc '
    set +e
    printf "%s\n" --dns--
    getent hosts shuffle-backend aptl-shuffle-backend 2>&1
    printf "%s\n" --tcp5001--
    timeout 5 sh -c "nc -vz 172.20.0.20 5001" 2>&1
    timeout 5 sh -c "nc -vz shuffle-backend 5001" 2>&1
    true
  ' | redact_stream > "$OUT/participant-discovery.kali.txt"
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
rm -f "$OUT/trivy-sbom.cyclonedx.json"

trivy_json="$(mktemp)"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" \
  image --format json --scanners vuln "$IMAGE" > "$trivy_json"
gzip -n -c "$trivy_json" > "$OUT/trivy-vulnerabilities.json.gz"
rm -f "$OUT/trivy-vulnerabilities.json"
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
rm -f "$OUT/syft-sbom.cyclonedx.json"
record_limit "Syft CycloneDX output was deterministically normalized by stripping syft:location:* properties; filesystem provenance is captured in filesystem-tree.txt.gz and filesystem-checksums.txt.xz."

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
  "containerized osquery sharing aptl-shuffle-backend PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-shuffle-backend network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-shuffle-backend";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%shuffle-backend%";' \
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

sed -i 's/[[:space:]]\+$//' "$OUT"/*.txt

(
  cd "$ROOT"
  find docs/aces/inventory/shuffle-backend/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"

echo "capture complete: $OUT"
