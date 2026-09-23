#!/usr/bin/env bash
# Push one baked seat image to GHCR as an OCI artifact.
#
# The disk is a single blob and the config blob is the image's own
# self-description, which is exactly what `aptl seat start` resolves: it reads
# the small config, then fetches the disk by digest. Publication is proven by
# pulling the result anonymously rather than by trusting a visibility flag.
set -euo pipefail

: "${RELEASE_TAG:?release tag is required}"
: "${REPOSITORY_OWNER:?repository owner is required}"
: "${GHCR_TOKEN:?registry token is required}"

out=${1:?baked image directory is required}
disk=$out/seat-disk.qcow2
config=$out/seat-image-config.json
test -f "$disk"
test -f "$config"
size=$(stat -c %s "$disk")
if test "$size" -ge 10000000000; then
  echo 'seat disk exceeds the GHCR 10 GB layer limit' >&2
  exit 1
fi

# A source-only key cannot identify this artifact while Compose contains
# mutable third-party tags. The two published blobs determine its key.
key=$(sha256sum "$disk" "$config" | awk '{print $1}' | sha256sum | cut -d' ' -f1)

owner=${REPOSITORY_OWNER,,}
repository="${owner}/aptl-seat"
namespace="ghcr.io/${repository}"

DISK_MEDIA_TYPE='application/vnd.aptl.seat.disk.v1+qcow2'
CONFIG_MEDIA_TYPE='application/vnd.aptl.seat.config.v1+json'

command -v oras >/dev/null || {
  echo 'publishing a seat image requires oras' >&2
  exit 2
}

printf '%s' "$GHCR_TOKEN" | oras login ghcr.io --username "${GITHUB_ACTOR}" \
  --password-stdin
trap 'oras logout ghcr.io >/dev/null 2>&1 || true' EXIT

# The content key is the immutable tag. :latest is a moving pointer at it, and
# a seat that has already selected a digest is unaffected by moving it.
key_tag="key-${key}"

if oras resolve "${namespace}:${key_tag}" >/dev/null 2>&1; then
  echo "seat image ${key_tag} is already published; retagging latest" >&2
else
  # Annotations are metadata only; the disk layer and config blob are what the
  # launcher reads, both by digest.
  oras push "${namespace}:${key_tag}" \
    --config "${config}:${CONFIG_MEDIA_TYPE}" \
    --annotation "org.opencontainers.image.source=https://github.com/${owner}/aptl" \
    --annotation "org.opencontainers.image.version=${RELEASE_TAG}" \
    --annotation "org.opencontainers.image.revision=$(git rev-parse HEAD)" \
    "${disk}:${DISK_MEDIA_TYPE}"
fi

key_digest=$(oras resolve "${namespace}:${key_tag}")
release_digest=$(oras resolve "${namespace}:${RELEASE_TAG}" 2>/dev/null || true)
if test -n "$release_digest" && test "$release_digest" != "$key_digest"; then
  echo "release tag ${RELEASE_TAG} already identifies another seat image" >&2
  exit 1
fi

# Verify the immutable candidate before moving latest. GHCR creates new
# packages private by default; a failed visibility check must leave an
# existing working latest tag alone.
accept='application/vnd.oci.image.manifest.v1+json'
accept+=',application/vnd.oci.image.index.v1+json'
token=$(curl --silent --location --max-time 60 \
  "https://ghcr.io/token?service=ghcr.io&scope=repository:${repository}:pull" |
  jq -r '.token // empty')
test -n "$token" || {
  echo "seat image has no anonymous pull token: ${namespace}" >&2
  exit 1
}
verify_anonymous_manifest() {
  local target=$1 status=000 attempt
  for attempt in $(seq 1 20); do
    status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
      --max-time 60 --header "Authorization: Bearer ${token}" \
      --header "Accept: ${accept}" \
      "https://ghcr.io/v2/${repository}/manifests/${target}")
    if test "$status" = 200; then
      return 0
    fi
    if test "$attempt" -lt 20; then
      sleep 15
    fi
  done
  echo "seat image ${target} is not anonymously pullable (HTTP ${status})" >&2
  return 1
}

verify_anonymous_manifest "$key_tag"
oras tag "${namespace}:${key_tag}" "$RELEASE_TAG" latest
verify_anonymous_manifest latest

oras logout ghcr.io
trap - EXIT
unset GHCR_TOKEN

echo "${namespace}:latest"
