#!/usr/bin/env bash
# Push one baked seat image to GHCR as an OCI artifact.
#
# The disk is a single blob and the config blob is the image's own
# self-description, which is exactly what `aptl seat start` resolves: it reads
# the small config, then fetches the disk by digest. Publication is proven by
# pulling the result anonymously rather than by trusting a visibility flag.
set -euo pipefail

: "${REPOSITORY_OWNER:?repository owner is required}"
: "${GHCR_TOKEN:?registry token is required}"
: "${APTL_SEAT_SIGNING_KEY:?Cosign signing key is required}"

image_tag=${APTL_SEAT_IMAGE_TAG:-}
publish_latest=${APTL_SEAT_PUBLISH_LATEST:-0}
public_key=${APTL_SEAT_PUBLIC_KEY:-$PWD/src/aptl/appliance/seat/aptl-seat.pub}
if test -n "$image_tag" && ! [[ "$image_tag" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$ ]]; then
  echo 'invalid image tag' >&2
  exit 2
fi
if test "$publish_latest" != 0 && test "$publish_latest" != 1; then
  echo 'APTL_SEAT_PUBLISH_LATEST must be 0 or 1' >&2
  exit 2
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
out=$(realpath "${1:?baked image directory is required}")
public_key=$(realpath "$public_key")
for tool in oras cosign curl jq python3; do
  command -v "$tool" >/dev/null || { echo "publication requires $tool" >&2; exit 2; }
done
disk=$out/seat-disk.qcow2
config=$out/seat-image-config.json
test -f "$disk"
test -f "$config"
source_commit=$(python3 "$script_dir/seat-build-record.py" verify "$out")
size=$(wc -c < "$disk" | tr -d '[:space:]')
if test "$size" -ge 10000000000; then
  echo 'seat disk exceeds the GHCR 10 GB layer limit' >&2
  exit 1
fi

# A source-only key cannot identify this artifact while Compose contains
# mutable third-party tags. The two published blobs determine its key.
key=$(sha256sum "$disk" "$config" | awk '{print $1}' | sha256sum | cut -d' ' -f1)

owner=$(printf '%s' "$REPOSITORY_OWNER" | tr '[:upper:]' '[:lower:]')
repository="${owner}/aptl-seat"
namespace="ghcr.io/${repository}"

DISK_MEDIA_TYPE='application/vnd.aptl.seat.disk.v1+qcow2'
CONFIG_MEDIA_TYPE='application/vnd.aptl.seat.config.v1+json'

command -v oras >/dev/null || {
  echo 'publishing a seat image requires oras' >&2
  exit 2
}

registry_dir=$(mktemp -d)
trap 'rm -rf -- "$registry_dir"' EXIT
export DOCKER_CONFIG="$registry_dir"
oras() {
  command oras "$@" --registry-config "$registry_dir/config.json"
}
printf '%s' "$GHCR_TOKEN" | oras login ghcr.io --username "${GITHUB_ACTOR:-$REPOSITORY_OWNER}" \
  --password-stdin

# The content key is the immutable tag. :latest is a moving pointer at it, and
# a seat that has already selected a digest is unaffected by moving it.
key_tag="key-${key}"

if oras resolve "${namespace}:${key_tag}" >/dev/null 2>&1; then
  echo "seat image ${key_tag} is already published" >&2
else
  # Annotations are metadata only; the disk layer and config blob are what the
  # launcher reads, both by digest.
  (cd "$out" && oras push "${namespace}:${key_tag}" \
    --config "seat-image-config.json:${CONFIG_MEDIA_TYPE}" \
    --annotation "org.opencontainers.image.source=https://github.com/${owner}/aptl" \
    --annotation "org.opencontainers.image.version=${image_tag:-$key_tag}" \
    --annotation "org.opencontainers.image.revision=${source_commit}" \
    "seat-disk.qcow2:${DISK_MEDIA_TYPE}")
fi

key_digest=$(oras resolve "${namespace}:${key_tag}")
oras manifest fetch "${namespace}@${key_digest}" --output "$registry_dir/candidate.json"
python3 "$script_dir/seat-build-record.py" verify-manifest "$out" \
  --manifest "$registry_dir/candidate.json" --manifest-digest "$key_digest"
if test -n "$image_tag"; then
  previous_digest=$(oras resolve "${namespace}:${image_tag}" 2>/dev/null || true)
  if test -n "$previous_digest" && test "$previous_digest" != "$key_digest"; then
    echo "image tag ${image_tag} already identifies another seat image" >&2
    exit 1
  fi
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
  for ((attempt = 1; attempt <= 3; attempt++)); do
    status=$(curl --silent --output "$registry_dir/anonymous-manifest.json" --write-out '%{http_code}' \
      --max-time 30 --header "Authorization: Bearer ${token}" \
      --header "Accept: ${accept}" \
      "https://ghcr.io/v2/${repository}/manifests/${target}")
    if test "$status" = 200; then
      received="sha256:$(sha256sum "$registry_dir/anonymous-manifest.json" | cut -d' ' -f1)"
      if test "$received" = "$key_digest"; then
        return 0
      fi
      echo 'anonymous seat manifest digest differs from the published candidate' >&2
      return 1
    fi
    if test "$status" = 401 || test "$status" = 403; then
      break
    fi
    if test "$attempt" -lt 3; then
      sleep 5
    fi
  done
  echo "seat image ${target} is not anonymously pullable (HTTP ${status})" >&2
  return 1
}

verify_anonymous_manifest "$key_digest"

command -v cosign >/dev/null || {
  echo 'publishing a seat image requires Cosign' >&2
  exit 2
}
cosign sign --yes --key "$APTL_SEAT_SIGNING_KEY" \
  --bundle "$out/seat-image.sigstore.json" "${namespace}@${key_digest}"
install -d -m 0700 "$registry_dir/anonymous"
DOCKER_CONFIG="$registry_dir/anonymous" cosign verify --key "$public_key" \
  "${namespace}@${key_digest}" >/dev/null
if test -n "$image_tag"; then
  oras tag "${namespace}@${key_digest}" "$image_tag"
fi
if test "$publish_latest" = 1; then
  oras tag "${namespace}@${key_digest}" latest
  verify_anonymous_manifest latest
fi

rm -rf -- "$registry_dir"
trap - EXIT
unset GHCR_TOKEN

echo "${namespace}@${key_digest}"
