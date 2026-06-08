#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
OUT="$ROOT/docs/aces/inventory/webapp/evidence"
CONTAINER="${CONTAINER:-aptl-webapp}"
IMAGE="${IMAGE:-aptl-webapp:latest}"

# Tool images are digest-pinned so a later maintainer can rerun the same
# scanner binaries even when floating tags move.
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6}"
OSQUERY_IMAGE="${OSQUERY_IMAGE:-osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd}"

mkdir -p "$OUT"

redact_env_jq='
  def redact_env:
    if test("^(APTL_FLAG_KEY|DB_PASSWORD|JWT_SECRET|SECRET_KEY)=") then
      capture("^(?<name>[^=]+)=") as $m
      | "\($m.name)=<REDACTED-\($m.name | gsub("_"; "-"))>"
    else
      .
    end;
'

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

COMPOSE_PROFILES=enterprise,wazuh,soc docker compose -f "$ROOT/docker-compose.yml" config --format json \
  | jq '
      .services.webapp
      | .environment |= with_entries(
          if (.key | test("^(APTL_FLAG_KEY|DB_PASSWORD|JWT_SECRET|SECRET_KEY)$"))
          then .value = ("<REDACTED-" + (.key | gsub("_"; "-")) + ">")
          else .
          end
        )
    ' > "$OUT/compose-service.webapp.json"

docker inspect "$CONTAINER" \
  | jq "$redact_env_jq .[].Config.Env |= map(redact_env)" \
  > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" | jq . > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" > "$OUT/docker-history.image.txt"
docker network inspect aptl_aptl-dmz | jq . > "$OUT/docker-network.aptl-dmz.json"
docker network inspect aptl_aptl-internal | jq . > "$OUT/docker-network.aptl-internal.json"
docker volume inspect aptl_webapp_logs | jq . > "$OUT/docker-volume.webapp-logs.json"
docker top "$CONTAINER" > "$OUT/docker-top.txt"

sha256sum \
  "$ROOT/containers/webapp/Dockerfile" \
  "$ROOT/containers/webapp/entrypoint.sh" \
  "$ROOT/containers/webapp/supervisord.conf" \
  "$ROOT/containers/webapp/requirements.txt" \
  "$ROOT/containers/webapp/app/app.py" \
  "$ROOT/containers/webapp/app/static/style.css" \
  "$ROOT/containers/webapp/app/templates/admin.html" \
  "$ROOT/containers/webapp/app/templates/base.html" \
  "$ROOT/containers/webapp/app/templates/dashboard.html" \
  "$ROOT/containers/webapp/app/templates/login.html" \
  "$ROOT/containers/webapp/app/templates/search.html" \
  "$ROOT/containers/webapp/app/templates/tools.html" \
  "$ROOT/containers/webapp/app/templates/upload.html" \
  "$ROOT/containers/_wazuh-agent/install.sh" \
  "$ROOT/containers/_wazuh-agent/wazuh-agent.sh" \
  "$ROOT/containers/_wazuh-agent/ossec.conf.template" \
  "$ROOT/containers/_wazuh-agent/aptl-firewall-drop.sh" \
  "$ROOT/config/wazuh_cluster/etc/lists/active-response-whitelist" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"

docker exec "$CONTAINER" sh -lc '
  dpkg-query -W -f="\${binary:Package}\t\${Version}\t\${Architecture}\n" | sort
' > "$OUT/os-packages.txt"

{
  echo "--pip-freeze--"
  docker exec "$CONTAINER" sh -lc "python -m pip freeze | sort"
  echo "--requirements--"
  docker exec "$CONTAINER" cat /app/requirements.txt
} > "$OUT/language-manifests.txt"

docker exec "$CONTAINER" sh -lc '
  for path in \
    /var/ossec/etc/ossec.conf \
    /app/templates/admin.html \
    /app/templates/dashboard.html \
    /app/app.py \
    /app/templates/base.html \
    /etc/rsyslog.d/80-gunicorn.conf \
    /app/user.txt \
    /etc/rsyslog.d/90-forward.conf \
    /app/static/style.css \
    /app/templates/upload.html \
    /app/templates/tools.html \
    /app/requirements.txt \
    /app/templates/search.html \
    /app/templates/login.html \
    /etc/supervisor/conf.d/webapp.conf \
    /opt/aptl/wazuh/ossec.conf.template \
    /entrypoint.sh \
    /opt/aptl/wazuh/wazuh-agent.sh \
    /app \
    /app/static \
    /app/templates \
    /etc/rsyslog.d \
    /etc/supervisor/conf.d \
    /opt/aptl/wazuh
  do
    stat -c "%A %U %G %s %n" "$path"
  done
' > "$OUT/filesystem-tree.txt"

docker exec "$CONTAINER" sh -lc '
  sha256sum \
    /app/app.py \
    /app/requirements.txt \
    /app/static/style.css \
    /app/templates/admin.html \
    /app/templates/base.html \
    /app/templates/dashboard.html \
    /app/templates/login.html \
    /app/templates/search.html \
    /app/templates/tools.html \
    /app/templates/upload.html \
    /app/user.txt \
    /entrypoint.sh \
    /etc/rsyslog.d/80-gunicorn.conf \
    /etc/rsyslog.d/90-forward.conf \
    /etc/supervisor/conf.d/webapp.conf \
    /opt/aptl/wazuh/ossec.conf.template \
    /opt/aptl/wazuh/wazuh-agent.sh \
    /var/ossec/etc/ossec.conf
' > "$OUT/filesystem-checksums.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  redact_env() {
    sed -E "s/^(APTL_FLAG_KEY|DB_PASSWORD|JWT_SECRET|SECRET_KEY)=.*/\1=<REDACTED-\1>/" \
      | sed "s/<REDACTED-APTL_FLAG_KEY>/<REDACTED-APTL-FLAG-KEY>/;s/<REDACTED-DB_PASSWORD>/<REDACTED-DB-PASSWORD>/;s/<REDACTED-JWT_SECRET>/<REDACTED-JWT-SECRET>/;s/<REDACTED-SECRET_KEY>/<REDACTED-SECRET-KEY>/"
  }
  echo --os-release--
  cat /etc/os-release
  echo --id--
  id
  echo --pwd--
  pwd
  echo --uname--
  uname -a
  echo --capabilities-pid1--
  grep "^Cap" /proc/1/status || true
  echo --environment--
  env | sort | redact_env
  echo --listeners--
  (ss -lntup || netstat -lntup || true) 2>&1
  echo --mounts--
  mount | sed -n "1,120p"
  echo --users--
  getent passwd | sed -n "1,160p"
  echo --groups--
  getent group | sed -n "1,120p"
  echo --supervisor--
  supervisorctl status || true
  echo --process-tree--
  ps -eo pid,ppid,user,args || true
' > "$OUT/runtime-baseline.txt"
sed -i 's/[[:space:]]\+$//' "$OUT/runtime-baseline.txt" "$OUT/docker-top.txt"

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" --version \
  > "$OUT/trivy-version.txt"

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" \
  image --format cyclonedx "$IMAGE" \
  | jq -c . > "$OUT/trivy-sbom.cyclonedx.json"

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
  | jq -c '
      walk(
        if type == "object" and has("properties") then
          .properties |= map(select((.name | startswith("syft:location:")) | not))
          | if .properties == [] then del(.properties) else . end
        else
          .
        end
      )
    ' > "$OUT/syft-sbom.cyclonedx.json"

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
  "containerized osquery sharing aptl-webapp PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-webapp network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-webapp";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%aptl-webapp%";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-apt-sources.json" apt_sources \
  'select * from apt_sources order by name;' \
  "containerized osquery host-side view; target rootfs apt source parsing is not supported by this capture" docker

write_unavailable_osquery_json "$OUT/osquery-installed-applications.json" installed_applications \
  'select * from installed_applications;'

write_unavailable_osquery_json "$OUT/osquery-programs.json" programs \
  'select * from programs;'

(
  cd "$ROOT"
  find docs/aces/inventory/webapp/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
