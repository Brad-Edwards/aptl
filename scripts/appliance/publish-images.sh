#!/usr/bin/env bash
set -euo pipefail

: "${RELEASE_TAG:?release tag is required}"
: "${REPOSITORY_OWNER:?repository owner is required}"

owner=${REPOSITORY_OWNER,,}
namespace="ghcr.io/${owner}/aptl-candidate"

accept='application/vnd.oci.image.index.v1+json'
accept+=',application/vnd.docker.distribution.manifest.list.v2+json'
accept+=',application/vnd.oci.image.manifest.v1+json'
accept+=',application/vnd.docker.distribution.manifest.v2+json'

anonymous_manifest_status() {
  local repository=$1
  local token
  token=$(curl --silent --location --max-time 30 \
    "https://ghcr.io/token?service=ghcr.io&scope=repository:${repository}:pull" |
    jq -r '.token // empty')
  if test -z "$token"; then
    printf 'no-token'
    return 0
  fi
  curl --silent --output /dev/null --write-out '%{http_code}' --max-time 60 \
    --header "Authorization: Bearer ${token}" --header "Accept: ${accept}" \
    "https://ghcr.io/v2/${repository}/manifests/${RELEASE_TAG}"
}

# Prove the pushed tag is anonymously pullable. This reads the registry rather
# than the packages API: package visibility has no REST read that the workflow
# token can reach for a user-owned package, and an anonymous pull is the
# property the appliance job and public consumers actually depend on. The
# retry bound is deliberately generous because registry read-after-write
# visibility for an anonymous client is not a measured quantity here; a public
# tag answers on the first attempt and only a genuinely unreadable package
# spends the full window.
require_anonymous_pull() {
  local name=$1
  local repository="${namespace#ghcr.io/}/${name}"
  local status
  local attempt
  for attempt in $(seq 1 20); do
    status=$(anonymous_manifest_status "$repository")
    if test "$status" = 200; then
      return 0
    fi
    if test "$attempt" -lt 20; then
      sleep 15
    fi
  done
  echo "candidate package is not anonymously pullable after push:" \
    "${name}:${RELEASE_TAG} (last status ${status})" >&2
  exit 1
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
  if docker manifest inspect "${namespace}/${name}:${RELEASE_TAG}" >/dev/null 2>&1; then
    echo "refusing to replace existing GHCR tag: ${name}:${RELEASE_TAG}" >&2
    exit 1
  fi
  "${build[@]}" --file "$dockerfile" --tag "$canonical" "$context"
  docker tag "$canonical" "${namespace}/${name}:${RELEASE_TAG}"
  docker push "${namespace}/${name}:${RELEASE_TAG}"
  require_anonymous_pull "$name"
}

# Parent images remain locally tagged while their children build. Every image
# is also pushed into a public staging package under the immutable source tag
# used by the appliance job. Qualification promotes that same registry digest
# into the public release package; staging never replaces an existing tag, so
# an immutable candidate reference cannot be rewritten after it is recorded.
# Staging packages inherit this public repository's visibility at creation, and
# GitHub exposes no API to change package visibility, so the push is verified
# rather than adjusted: an unreadable staging package fails the release here
# instead of stranding the appliance job on an image it cannot pull.
build_image generic-samba-ad-base aptl/generic-samba-ad-base:latest \
  containers/generic-samba-ad-base containers/generic-samba-ad-base/Dockerfile
build_image generic-systemd-base aptl/generic-systemd-base:latest \
  containers/generic-systemd-base containers/generic-systemd-base/Dockerfile
build_image generic-systemd-base-debian aptl/generic-systemd-base-debian:latest \
  . containers/generic-systemd-base-debian/Dockerfile

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
  . containers/generic-systemd-node22-base/Dockerfile
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
