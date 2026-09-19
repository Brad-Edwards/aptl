#!/usr/bin/env bash
set -euo pipefail

: "${RELEASE_TAG:?release tag is required}"
: "${GITHUB_REPOSITORY:?GitHub repository is required}"
: "${REPOSITORY_OWNER:?repository owner is required}"
: "${APTL_RELEASE_PUBLIC_KEY_PEM:?configured release trust anchor is required}"
: "${APTL_QUALIFICATION_PUBLIC_KEY_PEM:?configured qualification trust anchor is required}"

for client in claude codex; do
    if ! command -v "$client" >/dev/null 2>&1; then
        echo "public acceptance runner is missing the authenticated $client CLI" >&2
        exit 2
    fi
done

owner=${REPOSITORY_OWNER,,}
namespace="ghcr.io/${owner}/aptl"
release_id="aptl-${RELEASE_TAG}-x86_64"
root=$PWD/build/appliance-public-acceptance
test ! -e "$root"
install -d -m 0700 "$root" "$root/release/artifacts" "$root/cache" \
    "$root/client" "$root/seat"
cleanup() {
    if test -x "$root/venv/bin/aptl"; then
        "$root/venv/bin/aptl" seat stop --seat-root "$root/seat" \
            >/dev/null 2>&1 || true
    fi
    rm -f "$root/client-key" "$root/client-key.pub"
}
trap cleanup EXIT INT TERM

docker logout ghcr.io >/dev/null 2>&1 || true
unset GH_TOKEN GITHUB_TOKEN CR_PAT
images=(
    generic-samba-ad-base
    generic-systemd-base
    generic-systemd-base-debian
    generic-samba-ad-wazuh-agent-base
    generic-systemd-wazuh-agent-base
    generic-systemd-wazuh-agent-base-debian
    generic-systemd-node22-base
    generic-wazuh-agent-base-debian
    suricata-wazuh-agent
    kali-capture
    network-boundary-helper
    appliance-egress-proxy
    operator-access-proxy
    misp-suricata-sync
    reverse
    web
    web-api
)
for image in "${images[@]}"; do
    docker pull "${namespace}/${image}:${RELEASE_TAG}"
done

base="https://github.com/${GITHUB_REPOSITORY}/releases/download/${RELEASE_TAG}"
fetch() {
    local name=$1
    curl --fail --location --proto '=https' --tlsv1.2 \
        --retry 5 --retry-all-errors --output "$root/$name" "$base/$name"
}
fetch "${release_id}.metadata.tar"
fetch appliance-release-public.pem
fetch appliance-qualification-public.pem
fetch THIRD-PARTY-NOTICES.md
printf '%s' "$APTL_RELEASE_PUBLIC_KEY_PEM" >"$root/trusted-release-public.pem"
printf '%s' "$APTL_QUALIFICATION_PUBLIC_KEY_PEM" \
    >"$root/trusted-qualification-public.pem"
for name in release qualification; do
    openssl pkey -pubin -in "$root/appliance-${name}-public.pem" -outform DER \
        >"$root/downloaded-${name}.der"
    openssl pkey -pubin -in "$root/trusted-${name}-public.pem" -outform DER \
        >"$root/trusted-${name}.der"
    cmp "$root/downloaded-${name}.der" "$root/trusted-${name}.der"
done
python3 - "$root/${release_id}.metadata.tar" "$root/release" <<'PYTHON'
import pathlib
import sys
import tarfile

with tarfile.open(pathlib.Path(sys.argv[1]), "r:") as archive:
    archive.extractall(pathlib.Path(sys.argv[2]), filter="data")
PYTHON

python3 -m venv "$root/venv"
"$root/venv/bin/pip" install --require-hashes -r requirements/ci.txt
"$root/venv/bin/pip" install --no-deps .
"$root/venv/bin/aptl" appliance verify-redistribution-review \
    --release-dir "$root/release" \
    --notices-output "$root/reconstructed-THIRD-PARTY-NOTICES.md"
cmp "$root/THIRD-PARTY-NOTICES.md" \
    "$root/reconstructed-THIRD-PARTY-NOTICES.md"
for artifact in aptl-golden.qcow2 offline-payload.tar; do
    "$root/venv/bin/aptl" appliance fetch-distribution \
        --repository "$GITHUB_REPOSITORY" --tag "$RELEASE_TAG" \
        --release-id "$release_id" --artifact-name "$artifact" \
        --public-key "$root/trusted-release-public.pem" \
        --cache-dir "$root/cache" --output "$root/release/artifacts/$artifact"
done
"$root/venv/bin/aptl" appliance verify \
    --release-dir "$root/release" \
    --public-key "$root/trusted-release-public.pem" \
    --qualification-public-key "$root/trusted-qualification-public.pem"

ssh-keygen -q -t ed25519 -N '' -f "$root/client-key"
"$root/venv/bin/aptl" seat start \
    --seat-root "$root/seat" --seat-id public-acceptance \
    --release-dir "$root/release" \
    --release-public-key "$root/trusted-release-public.pem" \
    --qualification-public-key "$root/trusted-qualification-public.pem" \
    --mapping participant,tcp,127.0.0.1,23001,127.0.0.1,3000 \
    --mapping recovery,tcp,127.0.0.1,24001,127.0.0.1,8400 \
    --mapping host-mcp,tcp,127.0.0.1,25001,127.0.0.1,2222 \
    --access-owner public-acceptance \
    --access-public-key "$root/client-key.pub" \
    --access-identity-file "$root/client-key" \
    --access-project-dir "$root/client" \
    --access-profile red --access-client claude --access-client codex

manifest_digest=$("$root/venv/bin/python" -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["manifest_digest"])' \
    "$root/release/manifest.sig.json")
golden_digest=$("$root/venv/bin/python" -c \
    'import json,sys; m=json.load(open(sys.argv[1])); print(next(a["sha256"] for a in m["artifacts"] if a["kind"] == "golden-disk"))' \
    "$root/release/manifest.json")
for client in claude codex; do
    if test "$client" = claude; then
        config="$root/client/.mcp.json"
    else
        config="$root/client/.codex/config.toml"
    fi
    "$root/venv/bin/python" scripts/appliance/probe-native-client.py \
        --mode active --client "$client" --config "$config" \
        --state "$root/$client.active.json" --candidate-id "$release_id" \
        --candidate-manifest-digest "$manifest_digest" \
        --golden-image-digest "$golden_digest" \
        --seat-id public-acceptance --generation 1
done
"$root/venv/bin/aptl" seat stop --seat-root "$root/seat"
for client in claude codex; do
    if test "$client" = claude; then
        config="$root/client/.mcp.json"
    else
        config="$root/client/.codex/config.toml"
    fi
    "$root/venv/bin/python" scripts/appliance/probe-native-client.py \
        --mode revoked --client "$client" --config "$config" \
        --state "$root/$client.active.json" --receipt "$root/$client.json" \
        --candidate-id "$release_id" --candidate-manifest-digest "$manifest_digest" \
        --golden-image-digest "$golden_digest" \
        --seat-id public-acceptance --generation 1
done
"$root/venv/bin/aptl" seat reset \
    --seat-root "$root/seat" --seat-id public-acceptance \
    --release-dir "$root/release" \
    --release-public-key "$root/trusted-release-public.pem" \
    --qualification-public-key "$root/trusted-qualification-public.pem"
cleanup
trap - EXIT INT TERM
