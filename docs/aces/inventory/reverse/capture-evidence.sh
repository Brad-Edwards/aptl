#!/usr/bin/env bash
set -euo pipefail

# SCN-010 / issue #338 — reverse steady-state asset inventory capture.
#
# The reverse asset is the lab's reverse-engineering workbench: a custom
# Ubuntu 22.04 systemd container (profile "reverse", built from
# containers/reverse/Dockerfile on the shared ubuntu base layer) running
# sshd (published to the host as 2027->22), rsyslog forwarding to the Wazuh
# manager, a Wazuh agent, Falco (modern eBPF), and a first-boot-installed
# reverse-engineering toolchain (radare2 from source, YARA, binutils/LLVM,
# UPX, osslsigncode, OpenJDK 17, pipx-installed flare-floss + flare-capa).
#
# The image is a local custom build, not a registry artifact, so build
# provenance is the repo Dockerfile + build-context inputs (source-checksums.txt),
# not a registry manifest digest. docker buildx imagetools inspect is attempted
# but expected to fail for the local-only tag; that is recorded as a limit.

ROOT="$(git rev-parse --show-toplevel)"
ASSET_ID="reverse"
ASSET_DIR="$ROOT/docs/aces/inventory/$ASSET_ID"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-reverse}"
MANAGER_CONTAINER="${MANAGER_CONTAINER:-aptl-wazuh-manager}"
IMAGE="${IMAGE:-aptl-reverse:latest}"
COMPOSE_FILE="$ROOT/docker-compose.yml"
COMPOSE_SERVICE="reverse"

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
require gzip
require jq
require sha256sum

mkdir -p "$OUT"
: > "$OUT/capture-limits.txt"
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

record_limit "This capture used the already-running local lab and did not run aptl lab stop -v && aptl lab start; it is a frozen steady-state observation, not a clean-lab rebuild proof."
record_limit "The reverse profile container was started for this inventory after fixing three pre-existing service-definition bugs on the same branch (missing cgroup: host, missing /run/lock tmpfs for Ubuntu systemd under AppArmor docker-default, and a 512m memory limit that OOM-killed the first-boot radare2 source build, raised to 2g). The first OOM-killed boot registered Wazuh agent id 008 (reverse-host, now Disconnected) before the container was recreated; the active registration is agent id 009 with a runtime-generated collision-suffixed name. Both rows are visible in observer-discovery.wazuh-manager.txt; the stale 008 row is local lab-state debris, not part of the asset spec."
record_limit "Scenario target secret files under /etc/ssh (host keys) and /var/ossec/etc/client.keys are captured verbatim in filesystem-sensitive-paths.txt and checksummed in filesystem-checksums.txt.xz. Per the SEC #417 key split, the target /keys holds only public key material — aptl_lab_key.pub (operator/control-plane pubkey) and kali_pivot_key.pub (scenario pivot pubkey); no private key is mounted into the target."
record_limit "The reverse-engineering Python tools are pipx-installed for labadmin from the Mandiant/FLARE PyPI distributions flare-floss==3.1.1 and flare-capa==9.4.0 (the correct names; the bare 'floss'/'capa' PyPI names are unrelated projects). This was corrected in SCN-010 #338: the initial capture found the bare 'floss' package (an unrelated spectrum-based fault-localization tool, analyzed as non-malicious) installed by an unpinned setup-reverse-tools.sh; the script was fixed to install the pinned flare- distributions and the box re-captured."

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

COMPOSE_PROFILES=reverse docker compose -f "$COMPOSE_FILE" config --format json \
  | jq --arg service "$COMPOSE_SERVICE" '.services[$service]' \
  > "$OUT/compose-service.reverse.json"

docker inspect "$CONTAINER" | jq . > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" | jq . > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" > "$OUT/docker-history.image.txt"
docker history --no-trunc --format '{{json .}}' "$IMAGE" \
  > "$OUT/docker-history.image.jsonl"

if docker buildx imagetools inspect "$IMAGE" > "$OUT/docker-buildx-imagetools.image.txt" 2>"$OUT/docker-buildx-imagetools.image.err"; then
  docker buildx imagetools inspect "$IMAGE" --raw | jq . > "$OUT/docker-buildx-imagetools.image.raw.json"
  rm -f "$OUT/docker-buildx-imagetools.image.err"
else
  rm -f "$OUT/docker-buildx-imagetools.image.txt"
  record_limit "Docker Buildx imagetools inspection failed for $IMAGE because it is a locally built tag with no registry manifest; see docker-buildx-imagetools.image.err. Image identity is the local config ID in docker-inspect.image.json plus the build recipe in source-checksums.txt."
fi

docker network inspect aptl_aptl-security | jq . > "$OUT/docker-network.aptl-security.json"
docker volume inspect aptl_reverse_logs | jq . > "$OUT/docker-volume.reverse_logs.json"
home_volume="$(
  docker inspect "$CONTAINER" \
    | jq -r '.[0].Mounts[] | select(.Destination == "/home" and .Type == "volume") | .Name'
)"
if [[ -n "$home_volume" ]]; then
  docker volume inspect "$home_volume" | jq . > "$OUT/docker-volume.reverse-home.json"
else
  record_limit "The anonymous /home volume was not found in Docker inspect output."
fi
docker top "$CONTAINER" > "$OUT/docker-top.txt"
docker logs "$CONTAINER" --tail 500 > "$OUT/docker-logs.reverse.txt" 2>&1

sha256sum \
  "$ROOT/docker-compose.yml" \
  "$ROOT/containers/reverse/Dockerfile" \
  "$ROOT/containers/reverse/entrypoint.sh" \
  "$ROOT/containers/reverse/install-all.sh" \
  "$ROOT/containers/reverse/install-falco.sh" \
  "$ROOT/containers/reverse/install-wazuh.sh" \
  "$ROOT/containers/reverse/setup-reverse-tools.sh" \
  "$ROOT/containers/reverse/reverse-tools-install.service" \
  "$ROOT/containers/base/scripts/entrypoint-base.sh" \
  "$ROOT/containers/base/scripts/ossec.conf.template" \
  "$ROOT/containers/base/falco_custom.yaml" \
  "$ROOT/keys/aptl_lab_key.pub" \
  "$ROOT/config/lab-ssh/kali_pivot_key.pub" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"

docker exec "$CONTAINER" bash -c "dpkg-query -W -f='\${binary:Package}\t\${Version}\t\${Architecture}\n' | sort" \
  > "$OUT/os-packages.txt"

docker exec "$CONTAINER" bash -c '
  set +e
  echo --apt-sources--
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do
    [ -f "$f" ] || continue
    echo "[$f]"
    sed -n "1,60p" "$f"
  done
  echo --apt-keyrings--
  ls -la /usr/share/keyrings/ /etc/apt/trusted.gpg.d/ 2>/dev/null
' > "$OUT/apt-repositories.txt"

docker exec "$CONTAINER" bash -c '
  set +e
  echo --python--
  python3 --version 2>&1
  echo --pipx-list--
  su - labadmin -c "pipx list" 2>&1
  echo --java--
  java -version 2>&1
  echo --radare2--
  r2 -v 2>&1
  echo --yara--
  yara --version 2>&1
  echo --upx--
  upx --version 2>&1 | head -1
  echo --osslsigncode--
  osslsigncode --version 2>&1 | head -2
  echo --binutils--
  objdump --version 2>&1 | head -1
  echo --llvm--
  llvm-objdump --version 2>&1 | head -3
  echo --capa--
  su - labadmin -c "command -v capa && capa --version" 2>&1 || echo "capa not on PATH"
  echo --falco--
  falco --version 2>&1
  echo --wazuh--
  /var/ossec/bin/wazuh-control info 2>&1
' > "$OUT/language-manifests.txt"

docker exec "$CONTAINER" bash -c '
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

docker exec "$CONTAINER" bash -c '
  set +e
  systemctl --no-pager list-unit-files --type=service
  echo --service-status--
  systemctl --no-pager status \
    reverse-tools-install.service \
    rsyslog.service \
    ssh.service \
    systemd-journald.service \
    systemd-user-sessions.service \
    wazuh-agent.service \
    falco-modern-bpf.service \
    falcoctl-artifact-follow.service || true
' > "$OUT/systemd-units.txt"

# RE-toolchain state: the asset's purpose is the analysis workbench. Record
# the installed tool surface and the labadmin workspace skeleton.
docker exec "$CONTAINER" bash -c '
  set +e
  echo --analysis-tools-on-path--
  for t in r2 radare2 rabin2 radiff2 rafind2 r2pm yara yarac upx osslsigncode objdump nm readelf strings llvm-objdump java analyze; do
    p="$(command -v "$t" 2>/dev/null)"
    [ -n "$p" ] && echo "$t -> $p"
  done
  echo --labadmin-local-bin--
  ls -la /home/labadmin/.local/bin 2>/dev/null
  echo --pipx-venvs--
  ls /home/labadmin/.local/share/pipx/venvs 2>/dev/null || ls /home/labadmin/.local/pipx/venvs 2>/dev/null
  echo --workspace--
  find /home/labadmin/reverse-workspace -maxdepth 2 2>/dev/null | head -40
  echo --analyze-helper--
  for c in /usr/local/bin/analyze /home/labadmin/.local/bin/analyze; do
    [ -f "$c" ] && { echo "[$c]"; sed -n "1,60p" "$c"; }
  done
  echo --radare2-install--
  ls /usr/local/lib/radare2 2>/dev/null | head -5
  r2pm -l 2>/dev/null | head -10
  echo --marker--
  ls -la /opt/lab/.reverse_tools_installed 2>&1
' > "$OUT/reverse-tools-state.txt"

# Wazuh agent state (same surface as the sidecar bundles).
docker exec "$CONTAINER" bash -c '
  set +e
  echo --wazuh-control-info--
  /var/ossec/bin/wazuh-control info 2>&1
  echo --wazuh-control-status--
  /var/ossec/bin/wazuh-control status 2>&1
  echo --ossec-conf--
  cat /var/ossec/etc/ossec.conf 2>&1
  echo --agentd-state--
  cat /var/ossec/var/run/wazuh-agentd.state 2>&1
  echo --client-keys-presence--
  if [ -s /var/ossec/etc/client.keys ]; then
    printf "client.keys present: %s line(s), %s bytes\n" "$(wc -l < /var/ossec/etc/client.keys)" "$(wc -c < /var/ossec/etc/client.keys)"
    cat /var/ossec/etc/client.keys 2>/dev/null
  else
    printf "client.keys absent or empty\n"
  fi
  echo --rsyslog-forwarding--
  cat /etc/rsyslog.d/*.conf 2>/dev/null
' > "$OUT/wazuh-agent-state.txt"

# Observer vantage: manager-side registration rows (includes the stale 008
# row from the OOM-killed first boot; see capture-limits.txt).
if docker inspect "$MANAGER_CONTAINER" >/dev/null 2>&1; then
  docker exec "$MANAGER_CONTAINER" sh -lc '
    set +e
    printf "%s\n" --agent-list--
    /var/ossec/bin/agent_control -l 2>&1 | grep -iE "reverse|Total|Wazuh"
    printf "%s\n" --agent-detail--
    id="$(/var/ossec/bin/agent_control -l 2>/dev/null | sed -n "s/^[[:space:]]*ID: \([0-9]*\),.*reverse.*Active.*/\1/p" | head -1)"
    if [ -n "$id" ]; then /var/ossec/bin/agent_control -i "$id" 2>&1; else echo "active reverse agent id not resolved"; fi
    true
  ' > "$OUT/observer-discovery.wazuh-manager.txt"
else
  record_limit "Wazuh manager observer-vantage discovery was skipped because $MANAGER_CONTAINER was not present."
  printf '%s container unavailable\n' "$MANAGER_CONTAINER" > "$OUT/observer-discovery.wazuh-manager.txt"
fi

# Attacker vantage: kali. The reverse box is on security-net (kali cannot
# route there) but publishes host port 2027->22.
if docker inspect aptl-kali >/dev/null 2>&1; then
  docker exec aptl-kali sh -lc '
    set +e
    printf "%s\n" --dns--
    getent hosts reverse aptl-reverse reverse-host 172.20.0.27 2>&1
    printf "%s\n" --route-to-security-net--
    ip route get 172.20.0.27 2>&1
    printf "%s\n" --tcp-probe--
    timeout 8 sh -c "nc -vz -w 3 172.20.0.27 22 2>&1" 2>&1
    printf "%s\n" --ping--
    ping -c 1 -W 2 172.20.0.27 2>&1 | sed -n "1,4p"
    true
  ' > "$OUT/participant-discovery.kali.txt"
else
  record_limit "Kali participant-vantage discovery was skipped because aptl-kali was not present."
  printf 'aptl-kali container unavailable\n' > "$OUT/participant-discovery.kali.txt"
fi

# Filesystem manifest: bootstrap scripts, systemd units, ssh/sudo/rsyslog/
# falco/wazuh config, apt trust, the labadmin home skeleton, /opt/lab marker,
# and the RE toolchain entry points. The radare2 source/build tree and the
# full /usr/local/lib payload are summarized by the package/SBOM surfaces.
docker exec "$CONTAINER" bash -c '
  set -euo pipefail
  find \
    /home \
    /root \
    /keys \
    /usr/local/bin \
    /opt/purple-team/scripts \
    /opt/lab \
    /etc/environment.wazuh \
    /etc/apt \
    /usr/share/keyrings \
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
    | grep -Ev "/home/labadmin/(radare2|\.cache|\.local/share/pipx/venvs/[^/]+/lib)(/|$)" \
    | sort
' | gzip -n > "$OUT/filesystem-tree.txt.gz"
record_limit "The filesystem manifest excludes the radare2 source/build tree, pipx venv lib payloads, and ~/.cache under /home/labadmin (toolchain payload evidenced by the package/SBOM surfaces and language-manifests.txt); /var/log content rows are runtime logs on the reverse_logs volume."

docker exec "$CONTAINER" bash -c '
  set -euo pipefail
  find \
    /keys \
    /opt/purple-team/scripts \
    /opt/lab \
    /etc/environment.wazuh \
    /etc/systemd/system \
    /etc/ssh \
    /etc/sudoers.d \
    /etc/rsyslog.d \
    /etc/falco \
    /var/ossec/etc \
    /usr/local/bin \
    -xdev \
    -maxdepth 4 \
    -type f \
    -print0 2>/dev/null \
    | sort -z \
    | xargs -0 sha256sum
' | xz -9 -c > "$OUT/filesystem-checksums.txt.xz"

docker exec "$CONTAINER" sh -c '
  for f in \
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
jq 'group_by(.severity) | map({severity: .[0].severity, count: length})' \
  "$OUT/trivy-vulnerability-list.json" > "$OUT/trivy-vulnerability-counts.json"
record_limit "Trivy scans the committed image layers (aptl-reverse:latest); the first-boot-installed toolchain (radare2 build, wazuh-agent, falco, pipx venvs) lives in the container's writable layer and is NOT covered by the image scan — runtime package state is captured by os-packages.txt and language-manifests.txt instead."

docker run --rm "$SYFT_IMAGE" version -o json | jq . > "$OUT/syft-version.json"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$SYFT_IMAGE" \
  "docker:$IMAGE" \
  --output cyclonedx-json \
  --select-catalogers "-file-content-cataloger,-file-digest-cataloger,-file-executable-cataloger,-file-metadata-cataloger" \
  | jq -c -f "$SYFT_NORMALIZER" \
  | gzip -n > "$OUT/syft-sbom.cyclonedx.json.gz"
record_limit "Syft CycloneDX output was deterministically normalized by stripping syft:location:* properties; component identity remains and filesystem provenance is captured separately. Like Trivy, Syft sees only the committed image layers, not the first-boot writable-layer installs."

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
  "containerized osquery sharing aptl-reverse PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-reverse network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-reverse";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%aptl-reverse%";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-apt-sources.json" apt_sources \
  'select * from apt_sources order by name;' \
  "containerized osquery host-side view; target rootfs apt source parsing is not supported by this capture" docker
record_limit "osquery apt_sources reflects the host-side scanner vantage; the target rootfs apt sources are captured directly in apt-repositories.txt."

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

# Normalize to match the repo pre-commit hooks: trim per-line trailing
# whitespace, then strip trailing blank lines so each file ends with exactly
# one newline (end-of-file-fixer parity). This keeps the committed evidence and
# its sha256 manifest stable across captures.
for f in "$OUT"/*.txt; do
  [ -f "$f" ] || continue
  sed -i 's/[[:space:]]\+$//' "$f"
  sed -i -e :a -e '/^\n*$/{$d;N;ba}' "$f"
done

(
  cd "$ROOT"
  find docs/aces/inventory/reverse/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
