#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
ASSET_DIR="$ROOT/docs/aces/inventory/misp"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-misp}"
DB_CONTAINER="${DB_CONTAINER:-aptl-misp-db}"
SYNC_CONTAINER="${SYNC_CONTAINER:-aptl-misp-suricata-sync}"
IMAGE="${IMAGE:-ghcr.io/misp/misp-docker/misp-core:latest}"
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

compose_cmd() {
  local cmd=(docker compose --project-name "$COMPOSE_PROJECT_NAME")
  if [[ -f "$COMPOSE_ENV_FILE" ]]; then
    cmd+=(--env-file "$COMPOSE_ENV_FILE")
  else
    record_limit "Compose env file $COMPOSE_ENV_FILE was unavailable; compose config may rely only on shell environment."
  fi
  cmd+=(--profile soc "$@")
  "${cmd[@]}"
}

redact_stream() {
  sed -E \
    -e 's/(PASSWORD|PASS|SECRET|TOKEN|KEY|COOKIE|SESSION|PRIVATE_KEY|API_KEY|JWT|AUTHKEY)=([^[:space:]]+)/\1=<REDACTED>/Ig' \
    -e "s/(admin user key set to ')[^']+(')/\1<REDACTED-ADMIN-KEY>\2/Ig" \
    -e "s/(setting admin key to ')[^']+(')/\1<REDACTED-ADMIN-KEY>\2/Ig" \
    -e 's/(misp_db_password|misp_root_password|redispassword|admin@admin\.test[[:space:]]+admin)/<REDACTED-SCENARIO-FIXTURE>/g' \
    -e 's/-----BEGIN [A-Z ]*PRIVATE KEY-----/<REDACTED-PRIVATE-KEY-BEGIN>/g' \
    -e 's/-----END [A-Z ]*PRIVATE KEY-----/<REDACTED-PRIVATE-KEY-END>/g'
}

redact_env_jq='
  def redact_env:
    if contains("=") then
      capture("^(?<name>[^=]+)=(?<value>.*)$") as $m
      | if ($m.name | test("(PASSWORD|PASS|SECRET|TOKEN|KEY|COOKIE|SESSION|PRIVATE_KEY|API_KEY|JWT|AUTHKEY)$"; "i")) then
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
          if (.key | test("(password|pass|secret|token|key|cookie|session|private_key|api_key|jwt|authkey)$"; "i")) then
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

yq -o=json '.services.misp' "$ROOT/docker-compose.yml" \
  | jq '
      .environment |= map(
        if test("^(?<name>[^=]+)=") then
          capture("^(?<name>[^=]+)=(?<value>.*)$") as $m
          | if ($m.name | test("(PASSWORD|PASS|SECRET|TOKEN|KEY|COOKIE|SESSION|PRIVATE_KEY|API_KEY|JWT|AUTHKEY)$"; "i"))
            then "\($m.name)=<REDACTED-\($m.name | gsub("_"; "-"))>"
            else .
            end
        else
          .
        end
      )
    ' > "$OUT/compose-service.misp.json"
record_limit "Compose service evidence was extracted from docker-compose.yml with yq because the full local compose project has an unrelated invalid dependency reference that prevents docker compose config from rendering."

docker inspect "$CONTAINER" \
  | jq "$redact_env_jq .[].Config.Env |= ((. // []) | map(redact_env)) | .[].State.Health.Log |= ((. // []) | map(.Output = \"<REDACTED-HTML-HEALTHCHECK-OUTPUT>\")) | redact_sensitive_keys" \
  > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" \
  | jq "$redact_env_jq redact_sensitive_keys" \
  > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" | redact_stream > "$OUT/docker-history.image.txt"
docker history --no-trunc --format '{{json .}}' "$IMAGE" | redact_stream > "$OUT/docker-history.image.jsonl"

if docker buildx imagetools inspect "$IMAGE" > "$OUT/docker-buildx-imagetools.image.txt" 2>"$OUT/docker-buildx-imagetools.image.err"; then
  docker buildx imagetools inspect "$IMAGE" --raw \
    | jq . > "$OUT/docker-buildx-imagetools.image.raw.json"
  rm -f "$OUT/docker-buildx-imagetools.image.err"
else
  record_limit "Docker Buildx imagetools inspection failed for $IMAGE; see docker-buildx-imagetools.image.err."
fi

docker network inspect aptl_aptl-security | jq . > "$OUT/docker-network.aptl-security.json"
docker volume inspect aptl_misp_data | jq . > "$OUT/docker-volume.misp-data.json"
docker volume inspect aptl_misp_config | jq . > "$OUT/docker-volume.misp-config.json"
docker top "$CONTAINER" | redact_stream > "$OUT/docker-top.txt"
docker logs "$CONTAINER" --tail 500 2>&1 | redact_stream > "$OUT/docker-logs.misp.txt"

record_limit "Capture used the already-running aptl project per operator direction and did not run aptl lab stop -v && aptl lab start; this bundle is a steady-state observation of that local lab, not clean-reset rebuild proof."
record_limit "Full source tree and volume filesystem evidence is captured as compressed manifests. SDL encodes load-bearing participant-visible paths and structured runtime surfaces directly; byte-identical rebuild proof remains out of scope for this inventory issue."
record_limit "Private key file content and secret-bearing config values are not captured or hashed as raw values; their path, mount, ownership, mode, and redaction classification are captured instead."

sha256sum \
  "$ROOT/docker-compose.yml" \
  "$ROOT/scripts/seed-misp.sh" \
  "$ROOT/config/soc_certs/misp/server.pem" \
  "$ROOT/config/soc_certs/lab-ca.pem" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"
record_limit "config/soc_certs/misp/server.key is mounted by the container but intentionally omitted from source-checksums.txt because it is private key material."

docker exec "$CONTAINER" sh -lc '
  dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${Architecture}\n" | sort
' > "$OUT/os-packages.txt"

{
  printf '%s\n' "--language-manifest-scan--"
  docker exec "$CONTAINER" sh -lc '
    set -eu
    for path in \
      /var/www/MISP/VERSION.json \
      /var/www/MISP/app/composer.lock \
      /var/www/MISP/requirements.txt \
      /var/www/MISP/Pipfile
    do
      if [ -e "$path" ]; then
        printf "%s\n" "$path"
      fi
    done
    printf "%s\n" "--php-version--"
    php -v | sed -n "1,4p"
    printf "%s\n" "--python-version--"
    python3 --version 2>&1 || true
    if command -v pip3 >/dev/null 2>&1; then
      printf "%s\n" "--pip-freeze--"
      pip3 freeze | sort
    fi
    printf "%s\n" "--misp-version--"
    cat /var/www/MISP/VERSION.json
  '
} > "$OUT/language-manifests.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  roots="
    /var/www/MISP
    /var/www/MISP/app/files
    /var/www/MISP/app/Config
    /etc/nginx
    /etc/supervisor
    /etc/php
    /run
    /var/log/nginx
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
          */database.php|*/config.php|*/email.php|*/bootstrap.php|/etc/nginx/certs/key.pem)
            stability=volume_backed
            sensitivity=operator_secret
            ;;
          /var/www/MISP/app/files/*)
            stability=volume_backed
            ;;
          /var/www/MISP/app/tmp/*|/run/*)
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
    /var/www/MISP
    /var/www/MISP/app/files
    /var/www/MISP/app/Config
    /etc/nginx
    /etc/supervisor
    /etc/php
    /var/log/nginx
  "
  for root in $roots; do
    [ -e "$root" ] || continue
    find "$root" -xdev -type f -print0
  done \
    | sort -zu \
    | grep -zEv "(/var/www/MISP/app/Config/(database|config|email|bootstrap)\.php|/etc/nginx/certs/key\.pem)$" \
    | xargs -0 -r sha256sum
' | xz -9 -c > "$OUT/filesystem-checksums.txt.xz"
rm -f "$OUT/filesystem-checksums.txt.gz"

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
  php -v | sed -n "1,4p" || true
  nginx -v 2>&1 || true
  python3 --version 2>&1 || true
  mysql --version 2>&1 || true
  redis-cli --version 2>&1 || true
  printf "%s\n" --supervisor--
  supervisorctl status 2>&1 || true
' | redact_stream > "$OUT/runtime-baseline.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  query() {
    mysql --ssl=0 -h "$MYSQL_HOST" -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" --batch --raw "$@"
  }
  printf "%s\n" --misp-version--
  cat /var/www/MISP/VERSION.json
  printf "%s\n" --app-config-summary--
  php -r '\''
    $files = ["/var/www/MISP/app/Config/bootstrap.php", "/var/www/MISP/app/Config/config.php", "/var/www/MISP/app/Config/database.php", "/var/www/MISP/app/Config/email.php"];
    foreach ($files as $f) {
      if (is_file($f)) {
        printf("%s\t%s\t<REDACTED-SECRET-FILE-DIGEST>\n", $f, filesize($f));
      }
    }
  '\''
  printf "%s\n" --db-users--
  query -e "select id,email,org_id,role_id,change_pw,disabled,termsaccepted,external_auth_required,notification_daily,notification_weekly,notification_monthly from users order by id;"
  printf "%s\n" --db-organisations--
  query -e "select id,name,uuid,local,type,nationality,sector from organisations order by id;"
  printf "%s\n" --db-roles--
  query -e "select id,name,perm_add,perm_modify,perm_modify_org,perm_publish,perm_delegate,perm_sync,perm_admin,perm_audit,perm_full,perm_auth,perm_site_admin,perm_tagger,perm_template,perm_sharing_group,perm_tag_editor,perm_sighting,perm_object_template,perm_galaxy_editor,perm_warninglist,perm_analyst_data,perm_skip_otp,default_role,restricted_to_site_admin from roles order by id;"
  printf "%s\n" --db-auth-keys--
  query -e "select id,uuid,user_id,created,expiration,read_only,comment,allowed_ips from auth_keys order by id;"
  printf "%s\n" --db-content-counts--
  query -e "select '\''events'\'' as table_name, count(*) as count from events union all select '\''attributes'\'', count(*) from attributes union all select '\''objects'\'', count(*) from objects union all select '\''tags'\'', count(*) from tags union all select '\''taxonomies'\'', count(*) from taxonomies union all select '\''galaxies'\'', count(*) from galaxies union all select '\''warninglists'\'', count(*) from warninglists union all select '\''feeds'\'', count(*) from feeds;"
  printf "%s\n" --db-schema-sample--
  query -e "show tables;" | sed -n "1,220p"
  printf "%s\n" --http-login--
  curl -ksS -o /tmp/misp-login.html -w "status=%{http_code}\tcontent_type=%{content_type}\tsize=%{size_download}\n" https://localhost/users/login || true
  printf "%s\n" --http-api-restsearch--
  curl -ksS -o /tmp/misp-restsearch.json \
    -H "Authorization: $ADMIN_KEY" \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -d "{\"returnFormat\":\"json\",\"limit\":1}" \
    -w "status=%{http_code}\tcontent_type=%{content_type}\tsize=%{size_download}\n" \
    https://localhost/events/restSearch || true
  if [ -s /tmp/misp-restsearch.json ]; then
    jq "{response_type: (type), keys: (if type == \"object\" then keys else [] end), length: (if type == \"array\" then length else null end)}" /tmp/misp-restsearch.json 2>/dev/null || sed -n "1,20p" /tmp/misp-restsearch.json
  fi
' | redact_stream > "$OUT/misp-state.txt"

if docker inspect aptl-kali >/dev/null 2>&1; then
  docker exec aptl-kali sh -lc '
    set +e
    printf "%s\n" --dns--
    getent hosts misp misp.techvault.local aptl-misp 2>&1
    printf "%s\n" --ports--
    timeout 5 sh -c "nc -vz 172.20.0.16 443" 2>&1
    timeout 5 sh -c "nc -vz misp.techvault.local 443" 2>&1
    true
  ' | redact_stream > "$OUT/participant-discovery.kali.txt"
else
  record_limit "Kali participant-vantage discovery was skipped because aptl-kali was not present."
  printf 'aptl-kali container unavailable\n' > "$OUT/participant-discovery.kali.txt"
fi

if docker inspect "$SYNC_CONTAINER" >/dev/null 2>&1; then
  docker exec "$SYNC_CONTAINER" sh -lc '
    set +e
    printf "%s\n" --dns--
    getent hosts misp aptl-misp 2>&1
    printf "%s\n" --tcp443--
    timeout 5 bash -lc "cat < /dev/null > /dev/tcp/misp/443" && echo "misp:443 reachable" || echo "misp:443 unreachable"
    printf "%s\n" --tcp80--
    timeout 5 bash -lc "cat < /dev/null > /dev/tcp/misp/80" && echo "misp:80 reachable" || echo "misp:80 unreachable"
    printf "%s\n" --tls--
    timeout 8 sh -c "openssl s_client -connect misp:443 -servername misp -brief -CAfile /etc/lab-ca/lab-ca.pem < /dev/null" 2>&1
    true
  ' | redact_stream > "$OUT/participant-discovery.misp-suricata-sync.txt"
else
  record_limit "misp-suricata-sync participant-vantage discovery was skipped because $SYNC_CONTAINER was not present."
  printf '%s container unavailable\n' "$SYNC_CONTAINER" > "$OUT/participant-discovery.misp-suricata-sync.txt"
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
  "containerized osquery sharing aptl-misp PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-misp network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-misp";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%misp-core%";' \
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
  find docs/aces/inventory/misp/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
