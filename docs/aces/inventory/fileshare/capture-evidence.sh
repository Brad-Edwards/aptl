#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
ASSET_DIR="$ROOT/docs/aces/inventory/fileshare"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-fileshare}"
IMAGE="${IMAGE:-aptl-fileshare:latest}"

# Tool images are digest-pinned so a later maintainer can rerun the same
# scanner binaries even when floating tags move.
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6}"
OSQUERY_IMAGE="${OSQUERY_IMAGE:-osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd}"
SYFT_NORMALIZER="$ASSET_DIR/normalize-syft-cyclonedx.jq"

mkdir -p "$OUT"
: > "$OUT/capture-limits.txt"

record_limit() {
  printf -- '- %s\n' "$*" >> "$OUT/capture-limits.txt"
}

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

yq -o=json '.services.fileshare' "$ROOT/docker-compose.yml" | jq . > "$OUT/compose-service.fileshare.json"

docker inspect "$CONTAINER" | jq . > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" | jq . > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" > "$OUT/docker-history.image.txt"
docker history --no-trunc --format '{{json .}}' "$IMAGE" > "$OUT/docker-history.image.jsonl"
docker network inspect aptl_aptl-internal | jq . > "$OUT/docker-network.aptl-internal.json"
docker volume inspect aptl_fileshare_data | jq . > "$OUT/docker-volume.fileshare-data.json"
docker volume inspect aptl_fileshare_logs | jq . > "$OUT/docker-volume.fileshare-logs.json"
docker top "$CONTAINER" > "$OUT/docker-top.txt"

sha256sum \
  "$ROOT/containers/fileshare/Dockerfile" \
  "$ROOT/containers/fileshare/setup-shares.sh" \
  "$ROOT/containers/fileshare/smb.conf" \
  "$ROOT/containers/fileshare/supervisord.conf" \
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
  echo "--dpkg-query--"
  docker exec "$CONTAINER" sh -lc "dpkg-query -W -f='\${binary:Package}\t\${Version}\t\${Architecture}\n' | sort"
  echo "--samba-version--"
  docker exec "$CONTAINER" sh -lc "smbd --version || true"
  echo "--supervisor-version--"
  docker exec "$CONTAINER" sh -lc "supervisord --version || true"
  echo "--python-packages--"
  docker exec "$CONTAINER" sh -lc "python3 -m pip freeze 2>/dev/null | sort || true"
} > "$OUT/language-manifests.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  for path in \
    /opt/setup-shares.sh \
    /etc/samba/smb.conf \
    /etc/supervisor/conf.d/fileshare.conf \
    /etc/rsyslog.d/90-forward.conf \
    /opt/aptl/wazuh/ossec.conf.template \
    /opt/aptl/wazuh/wazuh-agent.sh \
    /var/ossec/etc/ossec.conf \
    /var/ossec/etc/client.keys \
    /srv/shares \
    /srv/shares/public \
    /srv/shares/public/welcome.txt \
    /srv/shares/engineering \
    /srv/shares/engineering/deployments \
    /srv/shares/engineering/deployments/deploy.sh \
    /srv/shares/engineering/deployments/README.md \
    /srv/shares/finance \
    /srv/shares/finance/reports \
    /srv/shares/finance/reports/q3-revenue.csv \
    /srv/shares/hr \
    /srv/shares/hr/employees \
    /srv/shares/hr/employees/directory.csv \
    /srv/shares/it-backups \
    /srv/shares/it-backups/keys \
    /srv/shares/it-backups/keys/README \
    /srv/shares/it-backups/keys/deploy_key \
    /srv/shares/it-backups/keys/deploy_key.pub \
    /srv/shares/it-backups/db_backup_20240115.sql \
    /srv/shares/shared \
    /srv/shares/shared/wifi-passwords.txt \
    /srv/shares/shared/meeting-notes-q3.txt \
    /srv/shares/shared/user-flag.txt \
    /root/root.txt \
    /var/log/samba
  do
    if [ -e "$path" ]; then
      stat -c "%A %U %G %u %g %s %n" "$path"
    else
      printf "MISSING %s\n" "$path"
    fi
  done
' > "$OUT/filesystem-tree.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  for path in \
    /opt/setup-shares.sh \
    /etc/samba/smb.conf \
    /etc/supervisor/conf.d/fileshare.conf \
    /etc/rsyslog.d/90-forward.conf \
    /opt/aptl/wazuh/ossec.conf.template \
    /opt/aptl/wazuh/wazuh-agent.sh \
    /var/ossec/etc/ossec.conf \
    /var/ossec/etc/client.keys \
    /srv/shares/public/welcome.txt \
    /srv/shares/engineering/deployments/deploy.sh \
    /srv/shares/engineering/deployments/README.md \
    /srv/shares/finance/reports/q3-revenue.csv \
    /srv/shares/hr/employees/directory.csv \
    /srv/shares/it-backups/keys/README \
    /srv/shares/it-backups/keys/deploy_key \
    /srv/shares/it-backups/keys/deploy_key.pub \
    /srv/shares/it-backups/db_backup_20240115.sql \
    /srv/shares/shared/wifi-passwords.txt \
    /srv/shares/shared/meeting-notes-q3.txt \
    /srv/shares/shared/user-flag.txt \
    /root/root.txt
  do
    if [ -f "$path" ]; then
      sha256sum "$path"
    else
      printf "MISSING  %s\n" "$path"
    fi
  done
' > "$OUT/filesystem-checksums.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
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
  env | sort
  echo --listeners--
  (ss -lntup || netstat -lntup || true) 2>&1
  echo --mounts--
  mount | sed -n "1,160p"
  echo --users--
  getent passwd | sed -n "1,220p"
  echo --groups--
  getent group | sed -n "1,220p"
  echo --samba-shares--
  smbclient -L localhost -N || true
  echo --samba-config-shares--
  testparm -s 2>/dev/null | sed -n "/^\\[/,\$p" || true
  echo --samba-users--
  pdbedit -L -v 2>/dev/null || true
  echo --supervisor--
  supervisorctl status || true
  echo --process-tree--
  ps -eo pid,ppid,user,args || true
' > "$OUT/runtime-baseline.txt"
sed -i 's/[[:space:]]\+$//' "$OUT/runtime-baseline.txt" "$OUT/docker-top.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  for path in \
    /srv/shares/engineering/deployments/deploy.sh \
    /srv/shares/finance/reports/q3-revenue.csv \
    /srv/shares/hr/employees/directory.csv \
    /srv/shares/it-backups/keys/deploy_key \
    /srv/shares/it-backups/keys/deploy_key.pub \
    /srv/shares/it-backups/db_backup_20240115.sql \
    /srv/shares/shared/wifi-passwords.txt \
    /srv/shares/shared/user-flag.txt \
    /root/root.txt \
    /var/ossec/etc/client.keys
  do
    printf -- "--path:%s--\n" "$path"
    if [ -f "$path" ]; then
      cat "$path"
      printf "\n"
    else
      printf "MISSING\n"
    fi
  done
' > "$OUT/filesystem-sensitive-paths.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  echo --all-share-paths--
  find /srv/shares -xdev -printf "%M %u %g %U %G %s %p\n" | sort
  echo --all-samba-log-paths--
  find /var/log/samba -xdev -maxdepth 1 -printf "%M %u %g %U %G %s %p\n" | sort
' > "$OUT/share-tree.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  find /srv/shares -xdev -type f -print0 | sort -z | xargs -0 sha256sum
' > "$OUT/share-checksums.txt"

docker exec "$CONTAINER" sh -lc '
  set -eu
  echo --public-anonymous-listing--
  smbclient //localhost/Public -N -c "ls" || true
  echo --shared-anonymous-listing--
  smbclient //localhost/Shared -N -c "ls" || true
  echo --engineering-anonymous-listing--
  smbclient //localhost/Engineering -N -c "ls" || true
  echo --finance-anonymous-listing--
  smbclient //localhost/Finance -N -c "ls" || true
  echo --hr-anonymous-listing--
  smbclient //localhost/HR -N -c "ls" || true
  echo --it-backups-anonymous-listing--
  smbclient //localhost/IT-Backups -N -c "ls" || true
' > "$OUT/smbclient-anonymous-probes.txt" 2>&1

docker exec "$CONTAINER" sh -lc '
  set -eu
  echo --svc-fileshare-share-list--
  smbclient -L localhost -U "svc-fileshare%FileShare2024!" || true
  echo --svc-fileshare-public-listing--
  smbclient //localhost/Public -U "svc-fileshare%FileShare2024!" -c "ls" || true
  echo --svc-fileshare-shared-listing--
  smbclient //localhost/Shared -U "svc-fileshare%FileShare2024!" -c "ls" || true
  echo --svc-fileshare-engineering-listing--
  smbclient //localhost/Engineering -U "svc-fileshare%FileShare2024!" -c "ls" || true
' > "$OUT/smbclient-svc-fileshare-probes.txt" 2>&1
record_limit "smbclient-svc-fileshare-probes.txt uses the participant-visible fixture credential svc-fileshare/FileShare2024! to prove auth behavior; the value is already authored in containers/fileshare/setup-shares.sh."

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
  | jq -c -f "$SYFT_NORMALIZER" > "$OUT/syft-sbom.cyclonedx.json"
record_limit "Syft CycloneDX output was deterministically normalized by stripping syft:location:* properties; filesystem provenance is captured in filesystem-tree.txt, filesystem-checksums.txt, share-tree.txt, and share-checksums.txt."

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
  "containerized osquery sharing aptl-fileshare PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-fileshare network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-fileshare";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%aptl-fileshare%";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-apt-sources.json" apt_sources \
  'select * from apt_sources order by name;' \
  "containerized osquery host-side view; target rootfs apt source parsing is not supported by this capture" docker

write_unavailable_osquery_json "$OUT/osquery-installed-applications.json" installed_applications \
  'select * from installed_applications;'

write_unavailable_osquery_json "$OUT/osquery-programs.json" programs \
  'select * from programs;'
record_limit "osquery installed_applications and programs tables were unavailable in the Linux osquery 4.9.0 scanner image."

record_limit "Capture used the already-running aptl-fileshare container created on 2026-05-23, not a destructive fresh aptl lab stop -v && aptl lab start reset."

(
  cd "$ROOT"
  find docs/aces/inventory/fileshare/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
