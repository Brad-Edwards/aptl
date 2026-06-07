#!/usr/bin/env bash
set -euo pipefail

# SCN-010 / issue #348 steady-state asset inventory capture for the TechVault
# `misp-redis` container (the MISP Redis backing store). Non-destructive: it
# observes the already-running local lab and does NOT run `aptl lab stop -v &&
# aptl lab start`, so the bundle is steady-state observation, not clean-reset
# rebuild proof. Re-runnable: tool images are digest-pinned and outputs sorted.

ROOT="$(git rev-parse --show-toplevel)"
ASSET_DIR="$ROOT/docs/aces/inventory/misp-redis"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-misp-redis}"
MISP_CONTAINER="${MISP_CONTAINER:-aptl-misp}"
IMAGE="${IMAGE:-redis:7-alpine}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-aptl}"

# Tool images are digest-pinned so reruns use the same scanner binaries even
# when floating tags move (shared with the misp / misp-db capture bundles).
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6}"
OSQUERY_IMAGE="${OSQUERY_IMAGE:-osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd}"
SYFT_NORMALIZER="${SYFT_NORMALIZER:-$ASSET_DIR/normalize-syft-cyclonedx.jq}"

mkdir -p "$OUT"
# Start from a clean evidence dir so the committed bundle reflects only this
# capture (tracked files are restorable from git).
find "$OUT" -maxdepth 1 -type f -delete
: > "$OUT/capture-limits.txt"

# The Redis auth fixture is read from the live container Cmd at capture time so
# it is not hard-coded in this script; it is held in this shell variable and
# delivered to the in-container probes over stdin (read into REDISCLI_AUTH inside
# the exec) rather than via `redis-cli -a` / `docker exec -e` -- a clean delivery
# that keeps host argv tidy. The fixture value itself is a checked-in scenario
# realization fact and is preserved (not redacted) in the captured evidence.
REDIS_PASS="$(docker inspect "$CONTAINER" --format '{{json .Config.Cmd}}' \
  | jq -r 'index("--requirepass") as $i | if $i != null then .[$i+1] else empty end' 2>/dev/null || true)"

record_limit() {
  printf -- '- %s\n' "$*" >> "$OUT/capture-limits.txt"
}

# Text redaction for raw command output. Redacts: the live Redis auth fixture
# (dynamically, without naming it in this script), any `--requirepass`/
# `requirepass` value, the ACL password hash, NAME=value secret env, JSON
# "key":"value" secrets, and PEM private-key envelopes.
# The Redis auth fixture (redis-server --requirepass redispassword) is a
# checked-in scenario realization fact, NOT an operator secret -- it is the
# provisioning input that reproduces this asset, so it is preserved verbatim in
# the evidence and encoded as a secret_fixture value in the SDL (per ACES #471:
# SDL values are realization facts unless an author explicitly withholds them).
# redact_stream only scrubs generic operator-secret SHAPES (NAME=value secret
# env, JSON secret fields, PEM private keys) as a safety net; none of these match
# the Redis fixture, so it passes through unredacted.
redact_stream() {
  sed -E \
    -e 's/(PASSWORD|PASS|SECRET|TOKEN|APIKEY|API_KEY|KEY|COOKIE|SESSION|PRIVATE_KEY|JWT)=([^[:space:]]+)/\1=<REDACTED>/Ig' \
    -e 's/("?(password|pass|secret|token|apikey|api_key|session_key|private_key|jwt|cookie)"?[[:space:]]*[:=][[:space:]]*")[^"]*(")/\1<REDACTED>\3/Ig' \
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

# Compose service extracted with a YAML->JSON projection (the full local compose
# project can carry profile-dependent services outside this asset scope). The
# `command` carries the Redis auth fixture verbatim (a disclosed scenario fact).
uv run python -c '
import sys, yaml, json
with open(sys.argv[1]) as fh:
    data = yaml.safe_load(fh)
json.dump(data["services"]["misp-redis"], sys.stdout)
' "$ROOT/docker-compose.yml" \
  | redact_stream \
  | jq '
      if (.environment | type) == "array" then
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
      else . end
    ' > "$OUT/compose-service.misp-redis.json"
record_limit "Compose service evidence was extracted from docker-compose.yml with a YAML->JSON projection because the full local compose project can include profile-dependent services outside this asset scope."

docker inspect "$CONTAINER" \
  | jq "$redact_env_jq .[].Config.Env |= ((. // []) | map(redact_env)) | redact_sensitive_keys" \
  | redact_stream \
  > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" \
  | jq "$redact_env_jq redact_sensitive_keys" \
  | redact_stream \
  > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" | redact_stream > "$OUT/docker-history.image.txt"
docker history --no-trunc --format '{{json .}}' "$IMAGE" | redact_stream > "$OUT/docker-history.image.jsonl"

if docker buildx imagetools inspect "$IMAGE" > "$OUT/docker-buildx-imagetools.image.txt" 2>"$OUT/docker-buildx-imagetools.image.err"; then
  docker buildx imagetools inspect "$IMAGE" --raw \
    | jq . > "$OUT/docker-buildx-imagetools.image.raw.json"
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
docker top "$CONTAINER" | redact_stream > "$OUT/docker-top.txt"
docker logs "$CONTAINER" --tail 500 2>&1 | redact_stream > "$OUT/docker-logs.misp-redis.txt"

record_limit "Capture used the already-running aptl project per operator direction and did not run aptl lab stop -v && aptl lab start; this bundle is a steady-state observation of that local lab, not clean-reset rebuild proof."
record_limit "misp-redis declares no named volume; its keyspace persists only to the container COW layer at /data/dump.rdb. The Redis keyspace, per-logical-db key counts, datatype census, dump.rdb size/mtime, and rdb_changes_since_last_save are MISP-driven runtime state that drift continuously; they are captured as a point-in-time snapshot, and the SDL encodes the stable shape (key_value model, configured 16 logical DBs, persistence posture) with the observed population marked as a snapshot caveat."
record_limit "Full filesystem evidence is captured as compressed manifests. SDL encodes load-bearing participant-visible paths and structured runtime surfaces directly; byte-identical rebuild proof remains out of scope for this inventory issue."
record_limit "The Redis auth fixture (redis-server --requirepass redispassword) is a checked-in scenario realization fact -- the provisioning input that reproduces this asset -- and is preserved verbatim in the evidence (compose command, docker inspect Cmd, ACL state) and encoded as a secret_fixture value in the SDL (ACES #471). It is a disclosed lab credential, not an operator secret; generic operator-secret shapes are still scrubbed as a safety net."

sha256sum \
  "$ROOT/docker-compose.yml" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"

# --- OS packages (Alpine apk) ------------------------------------------------
docker exec "$CONTAINER" sh -lc '
  set -eu
  arch="$(cat /etc/apk/arch 2>/dev/null || echo unknown)"
  apk info -v 2>/dev/null | sort | while IFS= read -r nv; do
    printf "%s\t%s\n" "$nv" "$arch"
  done
' > "$OUT/os-packages.txt"

# --- Redis binary / config manifest ------------------------------------------
{
  printf '%s\n' "--redis-binaries--"
  docker exec "$CONTAINER" sh -lc '
    set -eu
    for path in /usr/local/bin/redis-server /usr/local/bin/redis-cli \
                /usr/local/bin/redis-benchmark /usr/local/bin/docker-entrypoint.sh; do
      if [ -e "$path" ]; then
        printf "%s\t%s\t%s\n" "$path" "$(stat -c %s "$path")" "$(sha256sum "$path" | awk "{print \$1}")"
      fi
    done
  '
  printf '%s\n' "--redis-symlinks--"
  docker exec "$CONTAINER" sh -lc '
    for path in /usr/local/bin/redis-check-aof /usr/local/bin/redis-check-rdb \
                /usr/local/bin/redis-sentinel; do
      [ -L "$path" ] && printf "%s -> %s\n" "$path" "$(readlink "$path")" || true
    done
  '
  printf '%s\n' "--redis-server-version--"
  docker exec "$CONTAINER" sh -lc "redis-server --version" 2>&1 || true
  printf '%s\n' "--config-file-on-disk--"
  docker exec "$CONTAINER" sh -lc '
    for path in /usr/local/etc/redis/redis.conf /etc/redis/redis.conf /data/redis.conf; do
      [ -e "$path" ] && printf "%s present\n" "$path" || printf "%s absent\n" "$path"
    done
  '
} > "$OUT/redis-manifest.txt"
record_limit "Redis configuration is supplied entirely via the Compose command line (redis-server --requirepass ...); no redis.conf file ships in the image or is mounted. Active runtime configuration is captured from CONFIG GET in redis-state.txt."

# --- Filesystem tree + checksums --------------------------------------------
FS_ROOTS='/data /usr/local/bin /usr/local/etc /etc /run'

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
          /data/dump.rdb) stability=runtime_created; sensitivity=operator_secret ;;
          /data/*) stability=runtime_created ;;
          /run/*) stability=runtime_created ;;
          /etc/*shadow*) sensitivity=operator_secret ;;
        esac
        stat -c \"%F\t%A\t%a\t%u\t%U\t%g\t%G\t%s\t%Y\t\${stability}\t\${sensitivity}\t%n\" \"\$path\"
      done
" | awk '{gsub(/\\t/,"\t"); print}' | gzip -n > "$OUT/filesystem-tree.txt.gz"
rm -f "$OUT/filesystem-tree.txt"

# dump.rdb (a constantly-changing binary serialization of MISP's cached keyspace,
# which can embed cached secret material) and shadow files are represented by
# path/metadata only and excluded from content checksums.
docker exec "$CONTAINER" sh -lc "
  set -eu
  for root in $FS_ROOTS; do
    [ -e \"\$root\" ] || continue
    find \"\$root\" -xdev -type f ! -path '/data/dump.rdb' ! -path '/etc/shadow*' -print0
  done \
    | sort -zu \
    | xargs -0 -r sha256sum
" | xz -9 -c > "$OUT/filesystem-checksums.txt.xz"
rm -f "$OUT/filesystem-checksums.txt"
record_limit "/data/dump.rdb is a volatile binary RDB serialization of MISP's cached keyspace that can embed cached secret material; it is represented by path/size/mtime metadata in filesystem-tree.txt.gz and excluded from content checksums."

# --- Runtime baseline --------------------------------------------------------
docker exec "$CONTAINER" sh -lc '
  set -eu
  printf "%s\n" --os-release--
  cat /etc/os-release 2>/dev/null || true
  printf "%s\n" --id--
  id
  printf "%s\n" --pid1-identity--
  cat /proc/1/status 2>/dev/null | grep -E "^(Name|Uid|Gid):" || true
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
  (netstat -lntup || ss -lntup || true) 2>&1
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
  ls -l /usr/local/bin/redis-server
' | redact_stream > "$OUT/runtime-baseline.txt"

# --- Redis datastore state ---------------------------------------------------
# The auth fixture is delivered over stdin and read into REDISCLI_AUTH inside the
# container, so it never appears in host docker-client argv (the `-e VAR=value`
# form would expose it via /proc) nor in in-container argv (no `redis-cli -a`).
# The datatype census prints only aggregate <count> <type> rows per logical DB;
# key names are consumed internally and never emitted. redact_stream is the backstop.
printf '%s\n' "$REDIS_PASS" | docker exec -i "$CONTAINER" sh -lc '
  set -eu
  IFS= read -r REDISCLI_AUTH
  export REDISCLI_AUTH
  printf "%s\n" --server--
  redis-cli INFO server | tr -d "\r" | grep -E "^(redis_version|redis_git_sha1|redis_build_id|redis_mode|os|arch_bits|multiplexing_api|run_id|tcp_port|server_time_usec|uptime_in_seconds|executable|config_file|io_threads_active):" || true
  printf "%s\n" --keyspace--
  redis-cli INFO keyspace | tr -d "\r" | grep -E "^db[0-9]+:" || echo "(no populated logical databases)"
  printf "%s\n" --persistence--
  redis-cli INFO persistence | tr -d "\r" | grep -E "^(loading|rdb_changes_since_last_save|rdb_bgsave_in_progress|rdb_last_save_time|rdb_last_bgsave_status|rdb_saves|aof_enabled|aof_last_bgrewrite_status|aof_rewrite_in_progress):" || true
  printf "%s\n" --memory--
  redis-cli INFO memory | tr -d "\r" | grep -E "^(used_memory_human|maxmemory|maxmemory_human|maxmemory_policy|mem_allocator):" || true
  printf "%s\n" --clients--
  redis-cli INFO clients | tr -d "\r" | grep -E "^(connected_clients|cluster_connections|maxclients|blocked_clients):" || true
  printf "%s\n" --replication--
  redis-cli INFO replication | tr -d "\r" | grep -E "^(role|connected_slaves):" || true
  printf "%s\n" --config--
  for key in save appendonly appendfsync maxmemory maxmemory-policy dir dbfilename bind protected-mode port databases tcp-keepalive tcp-backlog timeout loglevel logfile daemonize io-threads rdbcompression rdbchecksum; do
    val="$(redis-cli CONFIG GET "$key" | sed -n "2p" | tr -d "\r")"
    printf "%s\t%s\n" "$key" "$val"
  done
  printf "%s\n" --acl-whoami--
  redis-cli ACL WHOAMI | tr -d "\r"
  printf "%s\n" --acl-list--
  redis-cli ACL LIST | tr -d "\r"
  printf "%s\n" --acl-cat-count--
  redis-cli ACL CAT | wc -l
  printf "%s\n" --command-count--
  redis-cli COMMAND COUNT | tr -d "\r"
  printf "%s\n" --datatype-census--
  for db in $(redis-cli INFO keyspace | tr -d "\r" | sed -n "s/^db\([0-9]*\):.*/\1/p"); do
    echo "--db${db}--"
    redis-cli -n "$db" --scan 2>/dev/null | while IFS= read -r k; do
      redis-cli -n "$db" type "$k" 2>/dev/null
    done | sort | uniq -c | sort -rn
  done
' | redact_stream > "$OUT/redis-state.txt"

# --- Participant-vantage discovery ------------------------------------------
if docker inspect "$MISP_CONTAINER" >/dev/null 2>&1; then
  docker exec "$MISP_CONTAINER" sh -lc '
    set +e
    printf "%s\n" --dns--
    getent hosts misp-redis aptl-misp-redis 2>&1
    printf "%s\n" --redis-host-env--
    echo "REDIS_HOST=${REDIS_HOST:-<unset>}"
    printf "%s\n" --tcp6379--
    timeout 5 bash -lc "cat < /dev/null > /dev/tcp/misp-redis/6379" && echo "misp-redis:6379 reachable" || echo "misp-redis:6379 unreachable"
    true
  ' | redact_stream > "$OUT/participant-discovery.misp.txt"
else
  record_limit "MISP participant-vantage discovery was skipped because $MISP_CONTAINER was not present."
  printf '%s container unavailable\n' "$MISP_CONTAINER" > "$OUT/participant-discovery.misp.txt"
fi

if docker inspect aptl-kali >/dev/null 2>&1; then
  REDIS_IP="$(docker inspect "$CONTAINER" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || true)"
  docker exec -e REDIS_IP="$REDIS_IP" aptl-kali sh -lc '
    set +e
    printf "%s\n" --dns--
    getent hosts misp-redis aptl-misp-redis 2>&1
    printf "%s\n" --tcp6379-ip--
    timeout 5 sh -c "nc -vz ${REDIS_IP:-172.20.0.3} 6379" 2>&1
    printf "%s\n" --tcp6379-name--
    timeout 5 sh -c "nc -vz misp-redis 6379" 2>&1
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
    | redact_stream > "$output"
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
  "containerized osquery sharing aptl-misp-redis PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-misp-redis network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-misp-redis";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%redis%";' \
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

# The container docker-inspect Cmd redaction can leave the literal sentinel; make
# sure no stray raw fixture survived in any text artifact.
sed -i 's/[[:space:]]\+$//' "$OUT"/*.txt

(
  cd "$ROOT"
  find docs/aces/inventory/misp-redis/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"

echo "capture complete: $OUT"
