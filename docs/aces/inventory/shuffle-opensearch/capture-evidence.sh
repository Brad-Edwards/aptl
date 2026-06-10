#!/usr/bin/env bash
set -euo pipefail

# SCN-010 / issue #356 — shuffle-opensearch steady-state asset inventory capture.
#
# The shuffle-opensearch asset is the OpenSearch 2.14.0 datastore backing
# Shuffle (opensearchproject/opensearch:2.14.0, upstream registry image)
# running as aptl-shuffle-opensearch on aptl-security (DHCP address). It runs
# single-node (discovery.type=single-node) with the OpenSearch security plugin
# ENABLED (HTTPS + self-signed TLS, basic auth admin:<fixture>). It persists
# index data in the shuffle_opensearch_data volume at
# /usr/share/opensearch/data and exposes 9200 (REST), 9300 (transport), and
# 9600 (performance analyzer) to the security network only (no host-published
# ports).
#
# Secret handling: OPENSEARCH_INITIAL_ADMIN_PASSWORD=StrongPassword123! is a
# COMMITTED SCENARIO FIXTURE present in docker-compose.yml. It is a
# secret_fixture: its value is PRESERVED in the authored compose extraction
# (compose-service.shuffle-opensearch.json) and is used to authenticate the
# in-container REST probes, but it is REDACTED from every other evidence file
# (docker-inspect env redaction, runtime-baseline env, and the redact_stream
# backstop on all *-state files). Non-destructive: observes the running lab.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ASSET_DIR="$ROOT/docs/aces/inventory/shuffle-opensearch"
OUT="$ASSET_DIR/evidence"
CONTAINER="${CONTAINER:-aptl-shuffle-opensearch}"
IMAGE="${IMAGE:-opensearchproject/opensearch:2.14.0}"

export PATH="$HOME/.local/bin:$PATH"

# The OpenSearch admin password is the committed compose scenario fixture. It is
# read from the authored compose file (not hardcoded here) so the probe stays
# in sync with the scenario, passed to docker exec via -e, and NEVER written to
# evidence; redact_stream redacts the literal value as a defense-in-depth
# backstop.
OS_ADMIN_USER="${OS_ADMIN_USER:-admin}"
OS_ADMIN_PASS="$(yq -r '.services."shuffle-opensearch".environment[] | select(test("^OPENSEARCH_INITIAL_ADMIN_PASSWORD=")) | sub("^OPENSEARCH_INITIAL_ADMIN_PASSWORD=";"")' "$ROOT/docker-compose.yml")"

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

# redact_stream redacts NAME=value secret env, JSON "key":"value" secrets, PEM
# private-key envelopes, AND the literal scenario-fixture password value so it
# can never leak into a *-state or runtime file.
redact_stream() {
  local pass_re
  pass_re="$(printf '%s' "$OS_ADMIN_PASS" | sed -E 's/[][(){}.^$*+?|\\\/]/\\&/g')"
  sed -E \
    -e 's/(PASSWORD|PASS|SECRET|TOKEN|APIKEY|API_KEY|KEY|COOKIE|SESSION|PRIVATE_KEY|JWT)=([^[:space:]]+)/\1=<REDACTED>/Ig' \
    -e 's/("?(password|pass|secret|token|apikey|api_key|session_key|private_key|jwt|cookie)"?[[:space:]]*[:=][[:space:]]*")[^"]*(")/\1<REDACTED>\3/Ig' \
    -e 's/-----BEGIN [A-Z ]*PRIVATE KEY-----/<REDACTED-PRIVATE-KEY-BEGIN>/g' \
    -e 's/-----END [A-Z ]*PRIVATE KEY-----/<REDACTED-PRIVATE-KEY-END>/g' \
    -e "s/${pass_re}/<REDACTED-SCENARIO-FIXTURE>/g"
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

# The shuffle-opensearch compose block is extracted directly from
# docker-compose.yml with yq. A profile-filtered docker compose config cannot
# be used because soc-profile services depend_on wazuh.manager and profile
# filtering invalidates the project. The env redaction rule is applied
# uniformly EXCEPT it intentionally preserves OPENSEARCH_INITIAL_ADMIN_PASSWORD:
# that committed value is a secret_fixture (scenario reproduction input), not a
# real operator secret, so it stays in the authored compose extraction.
yq -o=json '.services."shuffle-opensearch"' "$ROOT/docker-compose.yml" \
  | jq '
      if (has("environment") and (.environment | type == "array")) then
        .environment |= map(
          if test("^(?<name>[^=]+)=") then
            capture("^(?<name>[^=]+)=(?<value>.*)$") as $m
            | if ($m.name == "OPENSEARCH_INITIAL_ADMIN_PASSWORD") then .
              elif ($m.name | test("(PASSWORD|PASS|SECRET|TOKEN|APIKEY|API_KEY|KEY|COOKIE|SESSION|PRIVATE_KEY|JWT)$"; "i"))
              then "\($m.name)=<REDACTED-\($m.name | gsub("_"; "-"))>"
              else .
              end
          else
            .
          end
        )
      else . end
    ' > "$OUT/compose-service.shuffle-opensearch.json"
record_limit "compose-service.shuffle-opensearch.json is the authored docker-compose.yml service block (yq-extracted); a profile-filtered docker compose config could not be used because soc-profile services depend_on wazuh.manager and profile filtering invalidates the project."
record_limit "OPENSEARCH_INITIAL_ADMIN_PASSWORD=StrongPassword123! is a COMMITTED SCENARIO FIXTURE (secret_fixture), not a real operator secret. Its value is intentionally PRESERVED in compose-service.shuffle-opensearch.json (the authored compose extraction) as a scenario reproduction input, and is REDACTED everywhere else (docker-inspect.container.json env, runtime-baseline.txt env, and all *-state files via redact_stream). This matches the committed docker-compose.yml."

# The env array is redacted by redact_env (covers OPENSEARCH_INITIAL_ADMIN_PASSWORD).
# The committed scenario-fixture password ALSO appears inside the compose
# healthcheck Test command that Docker embeds in the container config
# (curl -u admin:<fixture>); it is redacted structurally inside jq via a LITERAL
# (non-regex) split/join replacement over every string so the JSON stays
# well-formed (a line-based sed would mangle the JSON quoting). The fixture
# value is preserved ONLY in the authored compose-service extraction.
docker inspect "$CONTAINER" \
  | jq --arg fixture "$OS_ADMIN_PASS" --arg redacted "<REDACTED-SCENARIO-FIXTURE>" "$redact_env_jq
      .[].Config.Env |= ((. // []) | map(redact_env))
      | redact_sensitive_keys
      | walk(if (type == \"string\" and (\$fixture | length) > 0) then (split(\$fixture) | join(\$redacted)) else . end)" \
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
  rm -f "$OUT/docker-buildx-imagetools.image.txt"
  record_limit "Docker Buildx imagetools inspection failed for $IMAGE; see docker-buildx-imagetools.image.err for non-secret tool stderr. Image identity falls back to the registry RepoDigest in docker-inspect.container.json and the local config ID in docker-inspect.image.json."
fi

docker network inspect aptl_aptl-security | jq . > "$OUT/docker-network.aptl-security.json"
docker volume inspect aptl_shuffle_opensearch_data | jq . > "$OUT/docker-volume.shuffle_opensearch_data.json"
docker top "$CONTAINER" | redact_stream > "$OUT/docker-top.txt"
docker logs "$CONTAINER" --tail 500 2>&1 | redact_stream > "$OUT/docker-logs.shuffle-opensearch.txt"

record_limit "Capture used the already-running aptl project (soc profile up) per operator direction and did not run aptl lab stop -v && aptl lab start; this bundle is a steady-state observation of that local lab, not a clean-reset rebuild proof."
record_limit "shuffle-opensearch joins aptl-security with a DHCP address (the compose service declares no static ipv4_address) and publishes NO host ports; its current network identity is recorded in docker-inspect.container.json and docker-network.aptl-security.json."
record_limit "The shuffle_opensearch_data volume contents (/usr/share/opensearch/data) are runtime index state and out of manifest scope; only top-level directory rows are recorded in filesystem-tree.txt. Index-level state (indices, counts, mappings) is captured via the OpenSearch REST API in opensearch-state.txt and shuffle-opensearch-index-mappings.json instead."

# Build provenance: no repo-authored bind files exist for this service; the
# compose file is the only authored input (config is upstream-image defaults
# plus compose environment, TLS material is entrypoint/image-shipped).
sha256sum \
  "$ROOT/docker-compose.yml" \
  | sed "s#  $ROOT/#  #" > "$OUT/source-checksums.txt"
record_limit "source-checksums.txt covers only docker-compose.yml; the shuffle-opensearch service has no repo-authored bind files (configuration is upstream-image defaults plus compose environment)."

# --- OS packages (Amazon Linux 2023 rpm) ------------------------------------
docker exec "$CONTAINER" bash -lc '
  rpm -qa --qf "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n" | sort
' > "$OUT/os-packages.txt"

# --- Language / runtime manifest (Java / OpenSearch) ------------------------
{
  printf "%s\n" "--opensearch-version--"
  docker exec "$CONTAINER" sh -lc '/usr/share/opensearch/bin/opensearch --version 2>&1' || true
  printf "%s\n" "--bundled-jdk-java-version--"
  docker exec "$CONTAINER" sh -lc '/usr/share/opensearch/jdk/bin/java --version 2>&1' || true
  printf "%s\n" "--bundled-jdk-release--"
  docker exec "$CONTAINER" sh -lc 'cat /usr/share/opensearch/jdk/release 2>/dev/null' || true
  printf "%s\n" "--lib-opensearch-core-jar--"
  docker exec "$CONTAINER" sh -lc 'ls /usr/share/opensearch/lib/opensearch-[0-9]*.jar 2>/dev/null' || true
  printf "%s\n" "--runtime-presence--"
  docker exec "$CONTAINER" sh -lc 'for t in java python3 pip node npm; do if command -v "$t" >/dev/null 2>&1; then printf "%s present: %s\n" "$t" "$(command -v "$t")"; else printf "%s absent\n" "$t"; fi; done' 2>&1 || true
} > "$OUT/language-manifests.txt"

# --- Filesystem manifest + checksums (config + bin + modules/plugins list) --
# Excludes the data volume content. TLS private keys under config
# (esnode-key.pem, kirk-key.pem and any *-key.pem) are operator_secret: recorded
# path/metadata only with sensitivity=operator_secret and excluded from
# checksums.
#
# The Amazon Linux 2023 OpenSearch image does NOT ship find(1) or xargs(1); it
# does ship python3, stat, and sha256sum. The path list is therefore enumerated
# with a python3 os.walk (full tree for config/bin/os-release; one level deep
# for modules/plugins; top-level dir rows only for the data volume), then the
# container's native stat/sha256sum are driven per-path via a read loop so the
# emitted columns match the precedents byte-for-byte.
PY_TREE_ROOTS='/usr/share/opensearch/config:full /usr/share/opensearch/bin:full /etc/os-release:full /usr/share/opensearch/modules:depth1 /usr/share/opensearch/plugins:depth1 /usr/share/opensearch/data:dataroot'

docker exec -e "PY_TREE_ROOTS=$PY_TREE_ROOTS" "$CONTAINER" bash -lc '
  set -eu
  python3 - <<"PY" | sort -u | while IFS= read -r path; do
import os, sys
specs = os.environ["PY_TREE_ROOTS"].split()
out = set()
for spec in specs:
    root, mode = spec.rsplit(":", 1)
    if not os.path.lexists(root):
        continue
    if mode == "full":
        if os.path.isfile(root) or (os.path.islink(root) and not os.path.isdir(root)):
            out.add(root); continue
        for dp, dns, fns in os.walk(root):
            out.add(dp)
            for n in dns + fns:
                out.add(os.path.join(dp, n))
    elif mode == "depth1":
        out.add(root)
        try:
            for n in os.listdir(root):
                out.add(os.path.join(root, n))
        except OSError:
            pass
    elif mode == "dataroot":
        # top-level directory/symlink rows only; never descend into index data
        out.add(root)
        try:
            for n in os.listdir(root):
                p = os.path.join(root, n)
                if os.path.isdir(p) or os.path.islink(p):
                    out.add(p)
        except OSError:
            pass
for p in sorted(out):
    print(p)
PY
        stability=stable
        sensitivity=plain
        case "$path" in
          /usr/share/opensearch/data*) stability=runtime_created ;;
          *-key.pem|/usr/share/opensearch/config/*.key) sensitivity=operator_secret ;;
          /usr/share/opensearch/config/opensearch.keystore) stability=runtime_created; sensitivity=operator_secret ;;
        esac
        stat -c "%F\t%A\t%a\t%u\t%U\t%g\t%G\t%s\t%Y\t${stability}\t${sensitivity}\t%n" "$path"
      done
' | awk '{gsub(/\\t/,"\t"); print}' | gzip -n > "$OUT/filesystem-tree.txt.gz"
record_limit "filesystem-tree.txt.gz scopes the manifest to the application surfaces (/usr/share/opensearch config, bin, and modules/plugins listings, /etc/os-release) plus top-level directory rows for the volume-backed data tree. TLS private keys under config (esnode-key.pem, kirk-key.pem) and the generated opensearch.keystore are recorded as path/metadata rows with sensitivity=operator_secret and excluded from filesystem-checksums.txt."
record_limit "The Amazon Linux 2023 OpenSearch image ships no find(1) or xargs(1); the filesystem manifest and checksums are enumerated with the in-container python3 os.walk and computed with the in-container stat/sha256sum, producing the same column format as the precedents."

# Stable-content checksums over config + bin trees; TLS private keys and the
# generated keystore are excluded (metadata rows only above). modules/plugins
# are listing-level evidence per the dedicated limit. Enumerated with python3
# (no find/xargs in image), checksummed with the native sha256sum per path.
docker exec "$CONTAINER" bash -lc '
  set -eu
  python3 - <<"PY" | sort -u | while IFS= read -r path; do
import os
roots = ["/usr/share/opensearch/config", "/usr/share/opensearch/bin"]
out = set()
for root in roots:
    if not os.path.isdir(root):
        continue
    for dp, dns, fns in os.walk(root):
        for n in fns:
            p = os.path.join(dp, n)
            if not os.path.isfile(p):
                continue
            base = os.path.basename(p)
            if base.endswith("-key.pem") or base.endswith(".key") or base == "opensearch.keystore":
                continue
            out.add(p)
for p in sorted(out):
    print(p)
PY
        sha256sum "$path"
      done
' | xz -9 -c > "$OUT/filesystem-checksums.txt.xz"
record_limit "filesystem-checksums.txt.xz covers the OpenSearch config and bin trees only; modules and plugins are recorded as manifest listing rows in filesystem-tree.txt.gz (no per-file checksums) and their integrity is evidenced by the registry image digest and the SBOMs. TLS private keys (esnode-key.pem, kirk-key.pem) and the generated opensearch.keystore are excluded from checksums (operator_secret)."

# --- Runtime baseline --------------------------------------------------------
# The OpenSearch image (Amazon Linux 2023) does not include ss or netstat;
# listener/connection evidence falls back to raw /proc/net tables.
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
  printf "%s\n" --process-tree--
  (ps -eo pid,ppid,user,args 2>/dev/null || for p in /proc/[0-9]*; do printf "%s %s\n" "${p#/proc/}" "$(tr "\0" " " < "$p/cmdline" 2>/dev/null)"; done) 2>&1
  true
' | redact_stream > "$OUT/runtime-baseline.txt"
record_limit "The OpenSearch (Amazon Linux 2023) image does not include ss or netstat; listener and outbound-connection evidence in runtime-baseline.txt falls back to raw /proc/net/tcp,tcp6,udp,udp6 tables, complemented by docker top and osquery namespace-sharing evidence. The REST/transport/perf-analyzer listeners are confirmed via the OpenSearch API in opensearch-state.txt."

# --- Service-specific state: OpenSearch REST API (authenticated, HTTPS) ------
# Security is ENABLED; HTTPS with a self-signed cert (hence -k). Auth uses the
# committed scenario-fixture credentials, passed via -e and redacted on output.
# A readiness poll guards against a momentary REST/security-plugin
# unavailability (e.g. a GC pause or a security-plugin reinitialization, which
# transiently returns "OpenSearch Security not initialized") producing empty or
# partial state evidence; the data store is already running. Readiness requires
# the authenticated root endpoint to return a proper cluster_uuid AND the
# cluster health to be at least yellow.
docker exec -e "OS_USER=$OS_ADMIN_USER" -e "OS_PASS=$OS_ADMIN_PASS" "$CONTAINER" bash -lc '
  cred="${OS_USER}:${OS_PASS}"
  for _ in $(seq 1 60); do
    root="$(curl -ks -u "$cred" "https://localhost:9200/" 2>/dev/null)"
    status="$(curl -ks -u "$cred" "https://localhost:9200/_cluster/health" 2>/dev/null)"
    case "$root" in *cluster_uuid*) ;; *) sleep 2; continue;; esac
    case "$status" in *\"status\":\"yellow\"*|*\"status\":\"green\"*) break;; *) sleep 2; continue;; esac
  done
  true
'
docker exec -e "OS_USER=$OS_ADMIN_USER" -e "OS_PASS=$OS_ADMIN_PASS" "$CONTAINER" bash -lc '
  set +e
  cred="${OS_USER}:${OS_PASS}"
  echo --root--
  curl -ks -u "$cred" https://localhost:9200/ 2>&1
  echo --cluster-health--
  curl -ks -u "$cred" "https://localhost:9200/_cluster/health?pretty" 2>&1
  echo --cat-indices--
  curl -ks -u "$cred" "https://localhost:9200/_cat/indices?v&s=index" 2>&1
  echo --cat-nodes--
  curl -ks -u "$cred" "https://localhost:9200/_cat/nodes?v" 2>&1
  echo --nodes-plugins-names-only--
  curl -ks -u "$cred" "https://localhost:9200/_nodes/_local/plugins" 2>/dev/null \
    | python3 -c "import json,sys
try:
  d=json.load(sys.stdin)
  out={\"cluster_name\": d.get(\"cluster_name\"), \"nodes\": {k:{\"name\":v.get(\"name\"),\"version\":v.get(\"version\"),\"plugins\":sorted([p[\"name\"] for p in v.get(\"plugins\",[])]),\"modules\":sorted([m[\"name\"] for m in v.get(\"modules\",[])])} for k,v in d.get(\"nodes\",{}).items()}}
  print(json.dumps(out, indent=2))
except Exception as e:
  print(\"plugins parse error:\", e)" 2>&1
  echo --transport-and-http-listeners--
  curl -ks -u "$cred" "https://localhost:9200/_nodes/_local/http,transport?filter_path=nodes.*.http.publish_address,nodes.*.http.bound_address,nodes.*.transport.publish_address,nodes.*.transport.bound_address&pretty" 2>&1
  true
' | redact_stream > "$OUT/opensearch-state.txt"

# --- Per-index mappings ------------------------------------------------------
# For each non-system index, capture /<index>/_mapping. For system-reserved
# indices whose _mapping returns a reserved-access error, fall back to the
# operator _cluster/state/metadata/<index> vantage (which exposes reserved
# mappings). All indices from _cat/indices are covered.
docker exec -e "OS_USER=$OS_ADMIN_USER" -e "OS_PASS=$OS_ADMIN_PASS" "$CONTAINER" bash -lc '
  set +e
  cred="${OS_USER}:${OS_PASS}"
  indices="$(curl -ks -u "$cred" "https://localhost:9200/_cat/indices?h=index&s=index" | sed "s/[[:space:]]*$//" | grep -v "^$")"
  echo "{"
  first=1
  for idx in $indices; do
    body="$(curl -ks -u "$cred" "https://localhost:9200/$idx/_mapping" 2>/dev/null)"
    vantage="_mapping"
    case "$body" in
      *security_exception*|*reserved*|*"is forbidden"*|*"no permissions"*|"")
        body="$(curl -ks -u "$cred" "https://localhost:9200/_cluster/state/metadata/$idx" 2>/dev/null)"
        vantage="_cluster/state/metadata"
        ;;
    esac
    [ $first -eq 1 ] || echo ","
    first=0
    printf "%s: " "$(printf "%s" "$idx" | python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))")"
    printf "{\"vantage\": %s, \"body\": %s}" \
      "$(printf "%s" "$vantage" | python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))")" \
      "$(printf "%s" "$body" | python3 -c "import json,sys
try:
  print(json.dumps(json.load(sys.stdin)))
except Exception:
  print(json.dumps({\"raw\": sys.stdin.read() if False else None}))" 2>/dev/null || echo "null")"
  done
  echo "}"
  true
' | redact_stream | jq -S . > "$OUT/shuffle-opensearch-index-mappings.json"
record_limit "shuffle-opensearch-index-mappings.json captures per-index _mapping bodies for every index returned by _cat/indices, tagging each with the vantage used (_mapping for accessible indices; the operator _cluster/state/metadata vantage as a fallback for any reserved/system index whose _mapping returns a security_exception). ACES mappings/templates surfaces are name-only list[str] and cannot encode these structured field schemas (blocked surface)."

# --- Participant-vantage discovery: kali ------------------------------------
# OpenSearch is on security-net only (DHCP) and publishes no host ports; the IP
# is read from docker inspect at capture time. Record what an in-range attacker
# can resolve/reach on 9200/9300/9600.
OS_IP="$(docker inspect "$CONTAINER" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo "")"
if docker inspect aptl-kali >/dev/null 2>&1; then
  docker exec -e "OS_IP=$OS_IP" aptl-kali sh -lc '
    set +e
    printf "%s\n" --opensearch-dhcp-ip-at-capture--
    printf "%s\n" "$OS_IP"
    printf "%s\n" --dns--
    getent hosts shuffle-opensearch aptl-shuffle-opensearch 2>&1
    printf "%s\n" --route-to-security-net--
    [ -n "$OS_IP" ] && ip route get "$OS_IP" 2>&1
    printf "%s\n" --tcp-probe-9200--
    [ -n "$OS_IP" ] && timeout 8 sh -c "nc -vz -w 3 $OS_IP 9200 2>&1" 2>&1
    printf "%s\n" --tcp-probe-9300--
    [ -n "$OS_IP" ] && timeout 8 sh -c "nc -vz -w 3 $OS_IP 9300 2>&1" 2>&1
    printf "%s\n" --tcp-probe-9600--
    [ -n "$OS_IP" ] && timeout 8 sh -c "nc -vz -w 3 $OS_IP 9600 2>&1" 2>&1
    printf "%s\n" --ping--
    [ -n "$OS_IP" ] && ping -c 1 -W 2 "$OS_IP" 2>&1 | sed -n "1,4p"
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
record_limit "Syft CycloneDX output was deterministically normalized by stripping syft:location:* properties; component identity remains and filesystem provenance is captured in filesystem-tree.txt.gz and filesystem-checksums.txt.xz."
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
  "containerized osquery sharing aptl-shuffle-opensearch PID namespace" container

write_osquery_json "$OUT/osquery-listening-ports.json" listening_ports \
  'select port, protocol, address, pid, socket, path from listening_ports order by port, protocol, pid;' \
  "containerized osquery sharing aptl-shuffle-opensearch network namespace" container

write_osquery_json "$OUT/osquery-docker-containers.json" docker_containers \
  'select id, name, image, image_id, command, created, state, status, pid, path, config_entrypoint, started_at, finished_at, privileged, security_options, readonly_rootfs, cgroup_namespace, ipc_namespace, mnt_namespace, net_namespace, pid_namespace, user_namespace, uts_namespace from docker_containers where name="/aptl-shuffle-opensearch";' \
  "containerized osquery host-side Docker socket view" docker

write_osquery_json "$OUT/osquery-docker-images.json" docker_images \
  'select id, tags, created, size_bytes from docker_images where tags like "%opensearch%";' \
  "containerized osquery host-side Docker socket view" docker

write_unavailable_osquery_json "$OUT/osquery-apt-sources.json" apt_sources \
  'select * from apt_sources order by name;'

write_unavailable_osquery_json "$OUT/osquery-installed-applications.json" installed_applications \
  'select * from installed_applications;'

write_unavailable_osquery_json "$OUT/osquery-programs.json" programs \
  'select * from programs;'

{
  echo "- osquery apt_sources is Debian/Ubuntu-specific and does not describe the Amazon Linux 2023 OpenSearch target; RPM package state is captured in os-packages.txt and the SBOMs. Recorded as unavailable."
  echo "- osquery installed_applications table unavailable in the digest-pinned Linux scanner image."
  echo "- osquery programs table unavailable in the digest-pinned Linux scanner image."
} >> "$OUT/capture-limits.txt"

# --- EOF normalization (strip trailing whitespace AND trailing blank lines) --
for f in "$OUT"/*.txt; do
  sed -i 's/[[:space:]]\+$//' "$f"
  sed -i -e :a -e '/^\n*$/{$d;N;ba}' "$f"
done

(
  cd "$ROOT"
  find docs/aces/inventory/shuffle-opensearch/evidence -maxdepth 1 -type f \
    ! -name evidence-sha256sums.txt \
    -print | sort | xargs sha256sum
) > "$OUT/evidence-sha256sums.txt"

echo "capture complete: $OUT"
