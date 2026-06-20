#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
ASSET_ID="workstation"
ASSET_DIR="$ROOT/docs/aces/inventory/$ASSET_ID"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-workstation}"
IMAGE="${IMAGE:-aptl-workstation:latest}"
COMPOSE_FILE="$ROOT/docker-compose.yml"
COMPOSE_SERVICE="workstation"
COMPOSE_PROFILES="${COMPOSE_PROFILES:-enterprise,wazuh,soc}"

TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6}"
OSQUERY_IMAGE="${OSQUERY_IMAGE:-osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd}"
SYFT_NORMALIZER="$ASSET_DIR/normalize-syft-cyclonedx.jq"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'required command missing: %s\n' "$1" >&2
    exit 2
  }
}

record_limit() {
  printf -- '- %s\n' "$*" >> "$OUT/capture-limits.txt"
}

require docker
require jq
require sha256sum

mkdir -p "$OUT"
: > "$OUT/capture-limits.txt"
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

record_limit "This capture used the already-running local lab and did not run aptl lab stop -v && aptl lab start; it is a frozen steady-state observation, not a clean-lab rebuild proof."
record_limit "Credential fixture contents, generated flags, scenario private-key material (host SSH keys and the planted /home/dev-user/.ssh/id_rsa), and Wazuh agent key material are captured verbatim where present in filesystem-sensitive-paths.txt and checksummed in filesystem-checksums.txt. Per the SEC #417 key split, the target /keys holds only public key material — aptl_lab_key.pub (operator/control-plane pubkey) and kali_pivot_key.pub (scenario pivot pubkey); no private key is mounted into the target."

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

COMPOSE_PROFILES="$COMPOSE_PROFILES" docker compose -f "$COMPOSE_FILE" config --format json \
  | jq --arg service "$COMPOSE_SERVICE" '.services[$service]' \
  > "$OUT/compose-service.workstation.json"

docker inspect "$CONTAINER" | jq . > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" | jq . > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" > "$OUT/docker-history.image.txt"
docker history --no-trunc --format '{{json .}}' "$IMAGE" \
  > "$OUT/docker-history.image.jsonl"
docker network inspect aptl_aptl-internal | jq . > "$OUT/docker-network.aptl-internal.json"
docker volume inspect aptl_workstation_logs | jq . > "$OUT/docker-volume.workstation-logs.json"

home_volume="$(
  jq -r '.[0].Mounts[] | select(.Destination == "/home" and .Type == "volume") | .Name' \
    "$OUT/docker-inspect.container.json"
)"
if [[ -n "$home_volume" ]]; then
  docker volume inspect "$home_volume" | jq . > "$OUT/docker-volume.workstation-home.json"
else
  record_limit "The anonymous /home volume was not found in Docker inspect output."
fi

docker top "$CONTAINER" > "$OUT/docker-top.txt"

sha256sum \
  "$ROOT/containers/workstation/Dockerfile" \
  "$ROOT/containers/workstation/entrypoint.sh" \
  "$ROOT/containers/workstation/install-all.sh" \
  "$ROOT/containers/workstation/install-falco.sh" \
  "$ROOT/containers/workstation/install-wazuh.sh" \
  "$ROOT/containers/workstation/lab-install.service" \
  "$ROOT/containers/workstation/setup-workstation.sh" \
  "$ROOT/containers/base/scripts/entrypoint-base.sh" \
  "$ROOT/containers/base/scripts/ossec.conf.template" \
  "$ROOT/containers/base/falco_custom.yaml" \
  "$ROOT/keys/aptl_lab_key.pub" \
  "$ROOT/config/lab-ssh/kali_pivot_key.pub" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"

docker exec "$CONTAINER" bash -lc '
  rpm -qa --qf "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n" | sort
' > "$OUT/os-packages.txt"

docker exec "$CONTAINER" bash -lc '
  set +e
  echo --dnf-repolist--
  dnf -q repolist --all 2>&1
  echo --yum-repos--
  for repo in /etc/yum.repos.d/*.repo; do
    echo "[$repo]"
    sed -n "1,220p" "$repo"
  done
  echo --dnf-config--
  sed -n "1,220p" /etc/dnf/dnf.conf 2>/dev/null
  echo --dnf-vars--
  for var in /etc/dnf/vars/*; do
    echo "[$var]"
    cat "$var"
  done
' > "$OUT/rpm-repositories.txt"

docker exec "$CONTAINER" bash -lc '
  set +e
  echo --python--
  python3 --version 2>&1
  echo --pip-freeze--
  python3 -m pip freeze 2>&1 | sort
  echo --node--
  node --version 2>&1
  echo --npm--
  npm --version 2>&1
  echo --psql--
  psql --version 2>&1
  echo --git--
  git --version 2>&1
  echo --falco--
  falco --version 2>&1
  echo --wazuh--
  /var/ossec/bin/wazuh-control info 2>&1
' > "$OUT/language-manifests.txt"

docker exec "$CONTAINER" bash -lc '
  set +e
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
  if command -v capsh >/dev/null 2>&1; then
    capsh --decode="$(awk "/^CapEff:/ {print \$2}" /proc/1/status)" || true
  fi
  echo --environment--
  env | sort
  echo --listeners--
  (ss -lntup || netstat -lntup || true) 2>&1
  echo --sshd-effective-config--
  sshd -T 2>/dev/null | sort | sed -n "/^acceptenv /p;/^allowusers /p;/^authorizedkeysfile /p;/^passwordauthentication /p;/^permitrootlogin /p;/^permittty /p;/^port /p;/^pubkeyauthentication /p;/^usepam /p"
  echo --network-addresses--
  ip addr show
  echo --routes--
  ip route show table all
  echo --dns--
  cat /etc/resolv.conf
  echo --hosts--
  cat /etc/hosts
  echo --hostname--
  cat /etc/hostname
  echo --mounts--
  mount | sed -n "1,220p"
  echo --users--
  getent passwd | sed -n "1,220p"
  echo --groups--
  getent group | sed -n "1,220p"
  echo --sudo-rules--
  find /etc/sudoers.d -maxdepth 1 -type f -print -exec sed -n "1,80p" {} \;
  echo --systemd-services--
  systemctl --no-pager --type=service --state=running,exited,failed || true
  echo --process-tree--
  ps -eo pid,ppid,user,args || true
' > "$OUT/runtime-baseline.txt"
sed -i 's/[[:space:]]\+$//' "$OUT/runtime-baseline.txt" "$OUT/docker-top.txt"

docker exec "$CONTAINER" bash -lc '
  set +e
  systemctl --no-pager list-unit-files --type=service
  echo --service-status--
  systemctl --no-pager status \
    lab-install.service \
    rsyslog.service \
    sshd.service \
    systemd-journald.service \
    systemd-tmpfiles-clean.service \
    systemd-tmpfiles-setup.service \
    systemd-user-sessions.service \
    wazuh-agent.service \
    falco-modern-bpf.service \
    falco-bpf.service \
    falco-kmod.service \
    falco-custom.service || true
' > "$OUT/systemd-units.txt"

docker exec "$CONTAINER" bash -lc '
  set -euo pipefail
  find \
    /home \
    /root \
    /keys \
    /usr/local/bin \
    /etc/environment.wazuh \
    /etc/dnf \
    /etc/yum.repos.d \
    /etc/pki/rpm-gpg \
    /opt/purple-team/scripts \
    /etc/systemd/system \
    /etc/ssh \
    /etc/sudoers.d \
    /etc/rsyslog.d \
    /etc/falco \
    /var/ossec/etc \
    /var/log \
    -xdev \
    -maxdepth 6 \
    -printf "%M %u %g %s %p\n" 2>/dev/null \
    | sort
' > "$OUT/filesystem-tree.txt"

docker exec "$CONTAINER" bash -lc '
  set -euo pipefail
  find \
    /home \
    /root \
    /keys \
    /usr/local/bin \
    /etc/environment.wazuh \
    /etc/dnf \
    /etc/yum.repos.d \
    /etc/pki/rpm-gpg \
    /opt/purple-team/scripts \
    /etc/systemd/system \
    /etc/ssh \
    /etc/sudoers.d \
    /etc/rsyslog.d \
    /etc/falco \
    /var/ossec/etc \
    /var/log \
    -xdev \
    -maxdepth 6 \
    -type f \
    -print0 2>/dev/null \
    | sort -z \
    | xargs -0 sha256sum
' > "$OUT/filesystem-checksums.txt"

docker exec "$CONTAINER" sh -c '
  for f in \
    /home/dev-user/.bash_history \
    /home/dev-user/.pgpass \
    /home/dev-user/.config/credentials.json \
    /home/dev-user/projects/techvault-portal/.env \
    /home/dev-user/projects/techvault-portal/deploy.sh \
    /home/dev-user/Documents/onboarding-notes.txt \
    /home/dev-user/user.txt \
    /home/dev-user/.ssh/id_rsa \
    /home/dev-user/.ssh/id_rsa.pub \
    /home/dev-user/.ssh/known_hosts \
    /root/root.txt \
    /keys/aptl_lab_key.pub \
    /keys/kali_pivot_key.pub \
    /etc/ssh/ssh_host_dsa_key \
    /etc/ssh/ssh_host_dsa_key.pub \
    /etc/ssh/ssh_host_ecdsa_key \
    /etc/ssh/ssh_host_ecdsa_key.pub \
    /etc/ssh/ssh_host_ed25519_key \
    /etc/ssh/ssh_host_ed25519_key.pub \
    /etc/ssh/ssh_host_rsa_key \
    /etc/ssh/ssh_host_rsa_key.pub \
    /var/ossec/etc/client.keys; do
      [ -e "$f" ] || continue
      printf "%s\n" "--path:$f--"
      cat "$f"
      printf "\n"
  done
' > "$OUT/filesystem-sensitive-paths.txt"

# Drop the trailing blank separator emitted after the last captured file so the
# committed evidence ends with a single newline; otherwise the pre-commit
# end-of-file-fixer rewrites it and stales evidence-sha256sums.txt.
printf '%s\n' "$(cat "$OUT/filesystem-sensitive-paths.txt")" \
  > "$OUT/filesystem-sensitive-paths.txt.tmp"
mv "$OUT/filesystem-sensitive-paths.txt.tmp" "$OUT/filesystem-sensitive-paths.txt"

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" --version \
  > "$OUT/trivy-version.txt"

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" \
  image --format cyclonedx "$IMAGE" \
  | jq -c . \
  | gzip -n > "$OUT/trivy-sbom.cyclonedx.json.gz"

trivy_json="$(mktemp)"
trap 'rm -f "$trivy_json"' EXIT
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
jq 'group_by(.severity) | map({severity: .[0].severity, count: length})' \
  "$OUT/trivy-vulnerability-list.json" > "$OUT/trivy-vulnerability-counts.json"

docker run --rm "$SYFT_IMAGE" version -o json | jq . > "$OUT/syft-version.json"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$SYFT_IMAGE" \
  "docker:$IMAGE" \
  --output cyclonedx-json \
  --select-catalogers "-file-content-cataloger,-file-digest-cataloger,-file-executable-cataloger,-file-metadata-cataloger" \
  | jq -c -f "$SYFT_NORMALIZER" \
  | gzip -n > "$OUT/syft-sbom.cyclonedx.json.gz"
record_limit "Syft CycloneDX output was deterministically normalized by stripping syft:location:* properties; component identity remains and filesystem provenance is captured separately."
record_limit "Trivy and Syft CycloneDX SBOM evidence is committed as deterministic gzip-compressed minified JSON to satisfy the repository's added-file size gate; compression is lossless."

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

write_osquery_unavailable_json() {
  local output="$1"
  local table="$2"
  local query="$3"
  local status="$4"
  local reason="$5"
  jq -n \
    --arg table "$table" \
    --arg query "$query" \
    --arg tool "$OSQUERY_TOOL" \
    --arg status "$status" \
    --arg reason "$reason" \
    '{table: $table, query: $query, tool: $tool, vantage: "containerized osquery Linux image", status: $status, reason: $reason, rows: []}' \
    > "$output"
}

write_osquery_json "$OUT/osquery-processes.json" processes \
  'select pid, name, path, cmdline, uid, gid, start_time from processes where name != "osqueryi" order by pid;' \
  "containerized osquery sharing aptl-workstation PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-workstation network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-workstation";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%aptl-workstation%";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_unavailable_json "$OUT/osquery-apt-sources.json" apt_sources \
  'select * from apt_sources order by name;' \
  "not_applicable" \
  "apt_sources is Debian/Ubuntu-specific and does not describe the Rocky Linux workstation target; RPM repository state is captured by os-packages.txt and filesystem evidence under /etc/yum.repos.d through the image/SBOM surfaces."
record_limit "osquery apt_sources was not applicable for the Rocky Linux workstation target."

write_osquery_unavailable_json "$OUT/osquery-installed-applications.json" installed_applications \
  'select * from installed_applications;' \
  "unavailable" \
  "osquery table installed_applications is not present in the Linux osquery registry for the digest-pinned osquery 4.9.0 scanner image"
record_limit "osquery installed_applications was unavailable in the digest-pinned Linux osquery scanner image."

write_osquery_unavailable_json "$OUT/osquery-programs.json" programs \
  'select * from programs;' \
  "unavailable" \
  "osquery table programs is not present in the Linux osquery registry for the digest-pinned osquery 4.9.0 scanner image"
record_limit "osquery programs was unavailable in the digest-pinned Linux osquery scanner image."

(
  cd "$ROOT"
  find docs/aces/inventory/workstation/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
