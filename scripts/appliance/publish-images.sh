#!/usr/bin/env bash
set -euo pipefail

: "${RELEASE_TAG:?release tag is required}"
: "${REPOSITORY_OWNER:?repository owner is required}"

owner=${REPOSITORY_OWNER,,}
namespace="ghcr.io/${owner}/aptl-candidate"

account_type=$(gh api "/users/${owner}" --jq .type)

package_endpoint() {
  local name=$1
  local package
  package=$(printf 'aptl-candidate/%s' "$name" | jq -sRr @uri)
  if [[ "$account_type" == Organization ]]; then
    printf '/orgs/%s/packages/container/%s' "$owner" "$package"
  else
    printf '/user/packages/container/%s' "$package"
  fi
}

require_private_or_missing() {
  local name=$1
  local endpoint
  endpoint=$(package_endpoint "$name")
  local visibility
  if visibility=$(gh api "$endpoint" --jq .visibility 2>/dev/null); then
    if [[ "$visibility" != private ]]; then
      echo "candidate package is not private: ${name}" >&2
      exit 1
    fi
  fi
}

require_private() {
  local name=$1
  local endpoint
  endpoint=$(package_endpoint "$name")
  if [[ $(gh api "$endpoint" --jq .visibility) != private ]]; then
    echo "candidate package was not private after push: ${name}" >&2
    exit 1
  fi
}

build_image() {
  local name=$1
  local canonical=$2
  local context=$3
  local dockerfile=$4
  local base_mode=${5:-remote}
  local build=(docker build --provenance=false)
  if test "$base_mode" = remote; then
    build+=(--pull)
  elif test "$base_mode" != local; then
    echo 'invalid container base mode' >&2
    exit 2
  fi
  require_private_or_missing "$name"
  if docker manifest inspect "${namespace}/${name}:${RELEASE_TAG}" >/dev/null 2>&1; then
    echo "refusing to replace existing GHCR tag: ${name}:${RELEASE_TAG}" >&2
    exit 1
  fi
  "${build[@]}" --file "$dockerfile" --tag "$canonical" "$context"
  docker tag "$canonical" "${namespace}/${name}:${RELEASE_TAG}"
  docker push "${namespace}/${name}:${RELEASE_TAG}"
  require_private "$name"
}

# Parent images remain locally tagged while their children build. Every image
# is also pushed into a private staging package under the immutable source tag
# used by the appliance job. Qualification promotes the same registry digest
# into the public package; candidates are never placed in a public package.
build_image generic-samba-ad-base aptl/generic-samba-ad-base:latest \
  containers/generic-samba-ad-base containers/generic-samba-ad-base/Dockerfile
build_image generic-systemd-base aptl/generic-systemd-base:latest \
  containers/generic-systemd-base containers/generic-systemd-base/Dockerfile
build_image generic-systemd-base-debian aptl/generic-systemd-base-debian:latest \
  containers/generic-systemd-base-debian containers/generic-systemd-base-debian/Dockerfile

build_image generic-samba-ad-wazuh-agent-base \
  aptl/generic-samba-ad-wazuh-agent-base:latest . \
  containers/generic-samba-ad-wazuh-agent-base/Dockerfile local
build_image generic-systemd-wazuh-agent-base \
  aptl/generic-systemd-wazuh-agent-base:latest . \
  containers/generic-systemd-wazuh-agent-base/Dockerfile local
build_image generic-systemd-wazuh-agent-base-debian \
  aptl/generic-systemd-wazuh-agent-base-debian:latest . \
  containers/generic-systemd-wazuh-agent-base-debian/Dockerfile local
build_image generic-systemd-node22-base aptl/generic-systemd-node22-base:latest \
  containers/generic-systemd-node22-base containers/generic-systemd-node22-base/Dockerfile
build_image generic-wazuh-agent-base-debian aptl/generic-wazuh-agent-base-debian:latest \
  . containers/generic-wazuh-agent-base-debian/Dockerfile
build_image suricata-wazuh-agent aptl/suricata-wazuh-agent:latest \
  . containers/suricata-wazuh-agent/Dockerfile
build_image kali-capture aptl-kali-capture:latest . containers/kali-capture/Dockerfile
build_image network-boundary-helper aptl-network-boundary-helper:5 \
  . containers/network-boundary-helper/Dockerfile
build_image appliance-egress-proxy aptl-appliance-egress-proxy:1 \
  . containers/appliance-egress-proxy/Dockerfile
build_image operator-access-proxy aptl-operator-access-proxy:latest \
  . containers/operator-access-proxy/Dockerfile
