#!/usr/bin/env bash
set -euo pipefail

: "${RELEASE_TAG:?release tag is required}"
: "${REPOSITORY_OWNER:?repository owner is required}"
: "${GH_TOKEN:?GitHub package token is required}"

owner=${REPOSITORY_OWNER,,}
namespace="ghcr.io/${owner}/aptl"
candidate_namespace="ghcr.io/${owner}/aptl-candidate"
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
)

printf '%s' "$GH_TOKEN" | docker login ghcr.io --username "${GITHUB_ACTOR}" --password-stdin
for image in "${images[@]}"; do
  source="${candidate_namespace}/${image}:${RELEASE_TAG}"
  target="${namespace}/${image}:${RELEASE_TAG}"
  if docker manifest inspect "$target" >/dev/null 2>&1; then
    echo "refusing to replace existing public GHCR tag: ${image}:${RELEASE_TAG}" >&2
    exit 1
  fi
  docker pull "$source"
  source_digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$source")
  source_digest=${source_digest##*@}
  if [[ ! "$source_digest" =~ ^sha256:[a-f0-9]{64}$ ]]; then
    echo "candidate image has no registry digest: ${image}" >&2
    exit 1
  fi
  docker tag "$source" "$target"
  docker push "$target"
  docker pull "$target"
  target_digests=$(docker image inspect --format '{{json .RepoDigests}}' "$target")
  if [[ "$target_digests" != *"${namespace}/${image}@${source_digest}"* ]]; then
    echo "public image digest differs from qualified candidate: ${image}" >&2
    exit 1
  fi
done

# Both namespaces inherit this public repository's visibility at creation and
# GitHub exposes no endpoint that changes it, so publication is proven by an
# unauthenticated pull of every promoted tag rather than by setting a flag.
docker logout ghcr.io
unset GH_TOKEN
for image in "${images[@]}"; do
  docker pull "${namespace}/${image}:${RELEASE_TAG}"
done
