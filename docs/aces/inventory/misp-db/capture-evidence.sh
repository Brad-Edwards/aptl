#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
ASSET_DIR="$ROOT/docs/aces/inventory/misp-db"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-misp-db}"
MISP_CONTAINER="${MISP_CONTAINER:-aptl-misp}"
IMAGE="${IMAGE:-mariadb:10.11}"
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
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

yq -o=json '.services."misp-db"' "$ROOT/docker-compose.yml" \
  | jq '
      .environment |= map(.)
    ' > "$OUT/compose-service.misp-db.json"
record_limit "Compose service evidence was extracted from docker-compose.yml with yq because the full local compose project can include profile-dependent services outside this asset scope."

docker inspect "$CONTAINER" | jq . > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" | jq . > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" > "$OUT/docker-history.image.txt"
docker history --no-trunc --format '{{json .}}' "$IMAGE" > "$OUT/docker-history.image.jsonl"

if docker buildx imagetools inspect "$IMAGE" > "$OUT/docker-buildx-imagetools.image.txt" 2>"$OUT/docker-buildx-imagetools.image.err"; then
  docker buildx imagetools inspect "$IMAGE" --raw \
    | jq . > "$OUT/docker-buildx-imagetools.image.raw.json"
  rm -f "$OUT/docker-buildx-imagetools.image.err"
else
  record_limit "Docker Buildx imagetools inspection failed for $IMAGE; see docker-buildx-imagetools.image.err."
fi

docker network inspect aptl_aptl-security | jq . > "$OUT/docker-network.aptl-security.json"
docker volume inspect aptl_misp_db_data | jq . > "$OUT/docker-volume.misp-db-data.json"
docker top "$CONTAINER" > "$OUT/docker-top.txt"
docker logs "$CONTAINER" --tail 500 2>&1 > "$OUT/docker-logs.misp-db.txt"

record_limit "Capture used the already-running aptl project per operator direction and did not run aptl lab stop -v && aptl lab start; this bundle is a steady-state observation of that local lab, not clean-reset rebuild proof."
record_limit "Full data-volume filesystem evidence is captured as compressed manifests. SDL encodes participant-visible database, listener, package, runtime, and filesystem surfaces directly; byte-identical rebuild proof remains out of scope for this inventory issue."
record_limit "MariaDB mysql.global_priv table files and other mysql system credential stores are represented by path/metadata but are excluded from checksum capture to avoid publishing password-hash fingerprints."

sha256sum "$ROOT/docker-compose.yml" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"

docker exec "$CONTAINER" dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' \
  | sort > "$OUT/os-packages.txt"

{
  printf "%s\n" "--database-manifest-scan--"
  docker exec "$CONTAINER" sh -lc '
    set -eu
    for path in \
      /usr/local/bin/docker-entrypoint.sh \
      /etc/mysql/my.cnf \
      /etc/mysql/mariadb.cnf \
      /etc/mysql/mariadb.conf.d/50-server.cnf \
      /etc/apt/sources.list \
      /etc/apt/sources.list.d/mariadb.list
    do
      if [ -e "$path" ]; then
        printf "%s\t%s\t%s\n" "$path" "$(stat -c %s "$path")" "$(sha256sum "$path" | awk "{print \$1}")"
      fi
    done
    printf "%s\n" "--mariadb-version--"
    mariadb --version 2>&1 || mysql --version 2>&1 || true
    printf "%s\n" "--entrypoint-help--"
    docker-entrypoint.sh --help 2>&1 | sed -n "1,40p" || true
  '
} > "$OUT/language-manifests.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  roots="
    /var/lib/mysql
    /etc/mysql
    /var/log/mysql
    /run/mysqld
    /usr/local/bin/docker-entrypoint.sh
  "
  for root in $roots; do
    [ -e "$root" ] || continue
    find "$root" -xdev \( -type f -o -type d -o -type l -o -type s -o -type p \) -print
  done \
    | sort -u \
    | while IFS= read -r path; do
        stability=stable
        sensitivity=plain
        case "$path" in
          /var/lib/mysql/*)
            stability=volume_backed
            ;;
          /var/lib/mysql/mysql/global_priv*|/var/lib/mysql/mysql/user*)
            sensitivity=secret_fixture
            ;;
          /run/*)
            stability=runtime_created
            ;;
          /var/log/*)
            stability=log
            ;;
        esac
        stat -c "%F\t%A\t%a\t%u\t%U\t%g\t%G\t%s\t%Y\t${stability}\t${sensitivity}\t%n" "$path"
      done
' | gzip -n > "$OUT/filesystem-tree.txt.gz"

docker exec "$CONTAINER" sh -lc '
  set -eu
  roots="
    /var/lib/mysql
    /etc/mysql
    /var/log/mysql
    /usr/local/bin/docker-entrypoint.sh
  "
  for root in $roots; do
    [ -e "$root" ] || continue
    find "$root" -xdev -type f -print0
  done \
    | sort -zu \
    | grep -zEv "(/var/lib/mysql/mysql/(global_priv|user)\\.|/var/lib/mysql/.*\\.(sock|pid)$)" \
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
  printf "%s\n" --mounts--
  mount | sed -n "1,220p"
  printf "%s\n" --users--
  getent passwd | sed -n "1,260p" || true
  printf "%s\n" --groups--
  getent group | sed -n "1,260p" || true
  printf "%s\n" --process-tree--
  ps -eo pid,ppid,user,args || true
  printf "%s\n" --service-versions--
  mariadb --version 2>&1 || mysql --version 2>&1 || true
  mariadbd --version 2>&1 || true
  healthcheck.sh --help 2>&1 | sed -n "1,20p" || true
' > "$OUT/runtime-baseline.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  query() {
    mariadb --ssl=0 -uroot -p"$MYSQL_ROOT_PASSWORD" --batch --raw "$@"
  }
  printf "%s\n" --mariadb-version--
  query -e "select @@version as version, @@version_comment as version_comment, @@hostname as hostname, @@port as port, @@datadir as datadir, @@socket as socket, @@log_error as log_error;"
  printf "%s\n" --databases--
  query -e "show databases;"
  printf "%s\n" --users--
  query -e "select User,Host,plugin,Super_priv,Create_user_priv,Grant_priv,(authentication_string <> \"\") as has_auth_string from mysql.user order by User,Host;"
  printf "%s\n" --schema-tables--
  query information_schema -e "select TABLE_SCHEMA,TABLE_NAME,TABLE_TYPE,ENGINE,COALESCE(TABLE_ROWS,0) as TABLE_ROWS from TABLES where TABLE_SCHEMA in (\"misp\",\"mysql\",\"sys\") order by TABLE_SCHEMA,TABLE_NAME;"
  printf "%s\n" --misp-table-counts--
  query information_schema -e "select TABLE_NAME,TABLE_ROWS from TABLES where TABLE_SCHEMA=\"misp\" order by TABLE_NAME;"
  printf "%s\n" --settings--
  query -e "show variables where Variable_name in (\"version\",\"version_comment\",\"hostname\",\"port\",\"datadir\",\"socket\",\"bind_address\",\"skip_networking\",\"log_error\",\"general_log\",\"slow_query_log\",\"character_set_server\",\"collation_server\",\"max_connections\",\"sql_mode\");"
  printf "%s\n" --schema-sample--
  query misp -e "show tables;" | sed -n "1,260p"
' > "$OUT/mariadb-state.txt"

if docker inspect "$MISP_CONTAINER" >/dev/null 2>&1; then
  docker exec "$MISP_CONTAINER" sh -lc '
    set +e
    printf "%s\n" --dns--
    getent hosts misp-db aptl-misp-db 2>&1
    printf "%s\n" --tcp3306--
    timeout 5 bash -lc "cat < /dev/null > /dev/tcp/misp-db/3306" && echo "misp-db:3306 reachable" || echo "misp-db:3306 unreachable"
    printf "%s\n" --mysql-client--
    mysql --ssl=0 -h "$MYSQL_HOST" -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" --batch --raw -e "select @@version as version, database() as database_name;" 2>&1
    true
  ' > "$OUT/participant-discovery.misp.txt"
else
  record_limit "MISP participant-vantage discovery was skipped because $MISP_CONTAINER was not present."
  printf '%s container unavailable\n' "$MISP_CONTAINER" > "$OUT/participant-discovery.misp.txt"
fi

if docker inspect aptl-kali >/dev/null 2>&1; then
  docker exec aptl-kali sh -lc '
    set +e
    printf "%s\n" --dns--
    getent hosts misp-db aptl-misp-db 2>&1
    printf "%s\n" --tcp3306--
    timeout 5 sh -c "nc -vz 172.20.0.17 3306" 2>&1
    true
  ' > "$OUT/participant-discovery.kali.txt"
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
  "containerized osquery sharing aptl-misp-db PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-misp-db network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-misp-db";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%mariadb%";' \
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
  find docs/aces/inventory/misp-db/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
