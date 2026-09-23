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
: "${APTL_SEAT_IMAGE_KEY:?seat image content key is required}"
: "${GHCR_TOKEN:?registry token is required}"

out=${1:?baked image directory is required}
disk=$out/seat-disk.qcow2
config=$out/seat-image-config.json
test -f "$disk"
test -f "$config"

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

# The content key is the immutable tag. :latest is a moving pointer at it, and
# a seat that has already selected a digest is unaffected by moving it.
key_tag="key-${APTL_SEAT_IMAGE_KEY}"

if oras manifest fetch "${namespace}:${key_tag}" >/dev/null 2>&1; then
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

oras tag "${namespace}:${key_tag}" "$RELEASE_TAG" latest

oras logout ghcr.io
unset GHCR_TOKEN

# Prove the published tag is anonymously pullable, the same property the
# launcher depends on. A package that is not readable without credentials is a
# failed publication, not a published image nobody can use.
accept='application/vnd.oci.image.manifest.v1+json'
accept+=',application/vnd.oci.image.index.v1+json'
token=$(curl --silent --location --max-time 60 \
  "https://ghcr.io/token?service=ghcr.io&scope=repository:${repository}:pull" |
  jq -r '.token // empty')
test -n "$token" || {
  echo "seat image has no anonymous pull token: ${namespace}" >&2
  exit 1
}
status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --max-time 60 --header "Authorization: Bearer ${token}" \
  --header "Accept: ${accept}" \
  "https://ghcr.io/v2/${repository}/manifests/latest")
test "$status" = 200 || {
  echo "seat image is not anonymously pullable (HTTP ${status})" >&2
  exit 1
}

echo "${namespace}:latest"
