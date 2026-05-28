#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
ASSET_ID="victim"
ASSET_DIR="$ROOT/docs/aces/inventory/$ASSET_ID"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-victim}"
IMAGE="${IMAGE:-aptl-victim:latest}"
COMPOSE_FILE="$ROOT/docker-compose.yml"
COMPOSE_SERVICE="victim"
COMPOSE_PROFILES="${COMPOSE_PROFILES:-victim,wazuh}"

TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6}"
OSQUERY_IMAGE="${OSQUERY_IMAGE:-osquery/osquery@sha256:f8ec3300048158292df2d4bb0d1d7804af358f530005828c3387553f23c796cd}"
SYFT_NORMALIZER="$ASSET_DIR/normalize-syft-cyclonedx.jq"

SECRET_NAME_REGEX="(token|secret|password|credential|cookie|session|private_key|api_key|jwt|flag_key|access_key)"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'required command missing: %s\n' "$1" >&2
    exit 2
  }
}

record_limit() {
  printf -- '- %s\n' "$*" >> "$OUT/capture-limits.txt"
}

redact_fixture_stream() {
  sed -E \
    -e 's/Summer2024/<REDACTED-SCENARIO-FIXTURE>/g' \
    -e 's/LabAdmin2024!/<REDACTED-SCENARIO-FIXTURE>/g' \
    -e 's/Welcome1!/<REDACTED-SCENARIO-FIXTURE>/g' \
    -e 's/Admin123!/<REDACTED-SCENARIO-FIXTURE>/g' \
    -e 's/admin123/<REDACTED-SCENARIO-FIXTURE>/g' \
    -e 's/techvault_db_pass/<REDACTED-SCENARIO-FIXTURE>/g' \
    -e 's/techvault-jwt-weak/<REDACTED-SCENARIO-FIXTURE>/g' \
    -e 's/tvault-api-key-2024-admin/<REDACTED-SCENARIO-FIXTURE>/g' \
    -e 's/techvault-secret-key-2024/<REDACTED-SCENARIO-FIXTURE>/g' \
    -e 's/AKIAIOSFODNN7EXAMPLE/<REDACTED-SCENARIO-FIXTURE>/g' \
    -e 's#wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY#<REDACTED-SCENARIO-FIXTURE>#g' \
    -e 's/APTL\{[^}]+\}/<REDACTED-SCENARIO-FLAG>/g'
}

redact_text_stream() {
  awk -v secret_re="$SECRET_NAME_REGEX" '
    {
      for (i = 1; i <= NF; i++) {
        token = $i
        lowered = tolower(token)
        if (lowered == "passwordauthentication") {
          $i = token
        } else if (lowered ~ secret_re) {
          if (token ~ /=/) {
            sub(/=.*/, "=<REDACTED>", token)
          } else if (token ~ /:/) {
            sub(/:.*/, ":<REDACTED>", token)
          } else {
            token = "<REDACTED>"
            if (i < NF) {
              $(i + 1) = "<REDACTED>"
            }
          }
          $i = token
        }
      }
      print
    }
  ' | redact_fixture_stream
}

redact_env_jq='
  def redact_env($secret_re):
    if contains("=") then
      capture("^(?<name>[^=]+)=(?<value>.*)$") as $m
      | if ($m.name | test($secret_re; "i")) then
          "\($m.name)=<REDACTED-\($m.name | gsub("_"; "-"))>"
        else
          .
        end
    else
      .
    end;

  def redact_sensitive_keys($secret_re):
    walk(
      if type == "object" then
        with_entries(
          if (.key | test($secret_re; "i")) then
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

require docker
require gzip
require jq
require sha256sum

mkdir -p "$OUT"
: > "$OUT/capture-limits.txt"
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/captured-at-utc.txt"

record_limit "This capture used the already-running local lab and did not run aptl lab stop -v && aptl lab start; it is a frozen steady-state observation, not a clean-lab rebuild proof."
record_limit "Raw generated flag contents, SSH private keys, and Wazuh agent key material are intentionally absent from committed evidence; sensitive paths are catalogued by metadata and checksums only where permitted."
record_limit "The host-mounted operator private key /keys/aptl_lab_key is catalogued by path metadata only; its content checksum is omitted as an operator-secret boundary."

docker version --format json | jq . > "$OUT/docker-version.json"
docker compose version --format json | jq . > "$OUT/docker-compose-version.json"

COMPOSE_PROFILES="$COMPOSE_PROFILES" docker compose -f "$COMPOSE_FILE" config --format json \
  | jq \
    --arg service "$COMPOSE_SERVICE" \
    --arg secret_re "$SECRET_NAME_REGEX" '
      .services[$service]
      | .environment = (
          (.environment // {})
          | with_entries(
              if (.key | test($secret_re; "i")) then
                .value = ("<REDACTED-" + (.key | gsub("_"; "-")) + ">")
              else
                .
              end
            )
        )
    ' > "$OUT/compose-service.victim.json"

docker inspect "$CONTAINER" \
  | jq --arg secret_re "$SECRET_NAME_REGEX" \
      "$redact_env_jq
      .[].Config.Env |= ((. // []) | map(redact_env(\$secret_re)))
      | redact_sensitive_keys(\$secret_re)" \
  > "$OUT/docker-inspect.container.json"

docker image inspect "$IMAGE" \
  | jq --arg secret_re "$SECRET_NAME_REGEX" "$redact_env_jq redact_sensitive_keys(\$secret_re)" \
  > "$OUT/docker-inspect.image.json"
docker history --no-trunc "$IMAGE" | redact_fixture_stream > "$OUT/docker-history.image.txt"
docker history --no-trunc --format '{{json .}}' "$IMAGE" \
  | redact_fixture_stream > "$OUT/docker-history.image.jsonl"
docker network inspect aptl_aptl-internal | jq . > "$OUT/docker-network.aptl-internal.json"
docker volume inspect aptl_victim_logs | jq . > "$OUT/docker-volume.victim-logs.json"

home_volume="$(
  jq -r '.[0].Mounts[] | select(.Destination == "/home" and .Type == "volume") | .Name' \
    "$OUT/docker-inspect.container.json"
)"
if [[ -n "$home_volume" ]]; then
  docker volume inspect "$home_volume" | jq . > "$OUT/docker-volume.victim-home.json"
else
  record_limit "The anonymous /home volume was not found in Docker inspect output."
fi

docker top "$CONTAINER" | redact_fixture_stream > "$OUT/docker-top.txt"

sha256sum \
  "$ROOT/containers/victim/Dockerfile" \
  "$ROOT/containers/victim/entrypoint.sh" \
  "$ROOT/containers/victim/install-all.sh" \
  "$ROOT/containers/victim/install-falco.sh" \
  "$ROOT/containers/victim/install-wazuh.sh" \
  "$ROOT/containers/victim/lab-install.service" \
  "$ROOT/containers/base/scripts/entrypoint-base.sh" \
  "$ROOT/containers/base/scripts/ossec.conf.template" \
  "$ROOT/containers/base/falco_custom.yaml" \
  "$ROOT/keys/aptl_lab_key.pub" \
  "$ROOT/keys/authorized_keys" \
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
' | redact_fixture_stream > "$OUT/rpm-repositories.txt"

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
  echo --git--
  git --version 2>&1
  echo --falco--
  falco --version 2>&1
  echo --wazuh--
  /var/ossec/bin/wazuh-control info 2>&1
' | redact_fixture_stream > "$OUT/language-manifests.txt"

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
' | redact_fixture_stream > "$OUT/runtime-baseline.txt"
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
' | redact_fixture_stream > "$OUT/systemd-units.txt"

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
' | redact_fixture_stream > "$OUT/filesystem-tree.txt"

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
    ! -path /keys/aptl_lab_key \
    ! -path "/etc/ssh/ssh_host_*_key" \
    ! -path /var/ossec/etc/client.keys \
    ! -path /root/root.txt \
    -print0 2>/dev/null \
    | sort -z \
    | xargs -0 sha256sum
' > "$OUT/filesystem-checksums.txt"

cat > "$OUT/filesystem-sensitive-paths.txt" <<'EOF'
/home/labadmin/user.txt	generated_flag	checksum-only
/keys/aptl_lab_key	operator_private_key	metadata-only
/keys/aptl_lab_key.pub	public_lab_key	checksum-only
/keys/authorized_keys	public_lab_key	checksum-only
/root/root.txt	generated_flag	metadata-only
/etc/ssh/ssh_host_dsa_key	host_private_key	metadata-only
/etc/ssh/ssh_host_ecdsa_key	host_private_key	metadata-only
/etc/ssh/ssh_host_ed25519_key	host_private_key	metadata-only
/etc/ssh/ssh_host_rsa_key	host_private_key	metadata-only
/var/ossec/etc/client.keys	wazuh_agent_secret	metadata-only
EOF

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
  "containerized osquery sharing aptl-victim PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-victim network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-victim";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%aptl-victim%";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_unavailable_json "$OUT/osquery-apt-sources.json" apt_sources \
  'select * from apt_sources order by name;' \
  "not_applicable" \
  "apt_sources is Debian/Ubuntu-specific and does not describe the Rocky Linux victim target; RPM repository state is captured by os-packages.txt and filesystem evidence under /etc/yum.repos.d through the image/SBOM surfaces."
record_limit "osquery apt_sources was not applicable for the Rocky Linux victim target."

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
  find docs/aces/inventory/victim/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"
