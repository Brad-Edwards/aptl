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
account_type=$(gh api "/users/${owner}" --jq .type)
for image in "${images[@]}"; do
  candidate_package=$(printf 'aptl-candidate/%s' "$image" | jq -sRr @uri)
  package=$(printf 'aptl/%s' "$image" | jq -sRr @uri)
  if [[ "$account_type" == Organization ]]; then
    candidate_endpoint="/orgs/${owner}/packages/container/${candidate_package}"
    endpoint="/orgs/${owner}/packages/container/${package}"
  else
    candidate_endpoint="/user/packages/container/${candidate_package}"
    endpoint="/user/packages/container/${package}"
  fi
  if [[ $(gh api "$candidate_endpoint" --jq .visibility) != private ]]; then
    echo "candidate package is not private: ${image}" >&2
    exit 1
  fi
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
  gh api --method PATCH "$endpoint" -f visibility=public >/dev/null
done

docker logout ghcr.io
unset GH_TOKEN
for image in "${images[@]}"; do
  docker pull "${namespace}/${image}:${RELEASE_TAG}"
done
