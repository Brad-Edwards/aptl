#!/usr/bin/env bash
set -euo pipefail

local_image_ref() {
  local canonical=$1
  if test -n "${APTL_LOCAL_IMAGE_TAG_SUFFIX:-}"; then
    printf '%s:local-%s' "${canonical%:*}" "$APTL_LOCAL_IMAGE_TAG_SUFFIX"
  else
    printf '%s' "$canonical"
  fi
}

build_image() {
  local canonical=$1
  local context=$2
  local dockerfile=$3
  local base_mode=${4:-remote}
  local parent_image=${5:-}
  local output_ref
  output_ref=$(local_image_ref "$canonical")
  local build=(docker build --provenance=false)
  if test "$base_mode" = remote; then
    build+=(--pull)
  elif test "$base_mode" != local; then
    echo 'invalid container base mode' >&2
    exit 2
  fi
  if test -n "$parent_image"; then
    build+=(--build-arg "APTL_PARENT_IMAGE=$parent_image")
  fi
  "${build[@]}" --file "$dockerfile" --tag "$output_ref" "$context"
  if test -n "${APTL_LOCAL_IMAGE_LOCK_FILE:-}"; then
    local image_id
    image_id=$(docker image inspect --format '{{.Id}}' "$output_ref")
    printf '%s %s %s\n' "$canonical" "$output_ref" "$image_id" \
      >> "$APTL_LOCAL_IMAGE_LOCK_FILE"
  fi
}

if test -n "${APTL_LOCAL_IMAGE_LOCK_FILE:-}"; then
  : "${APTL_LOCAL_IMAGE_TAG_SUFFIX:?unique local image suffix is required}"
  test ! -e "$APTL_LOCAL_IMAGE_LOCK_FILE"
  install -m 0600 /dev/null "$APTL_LOCAL_IMAGE_LOCK_FILE"
fi

# Build the same exact-source project-owned closure as the release workflow,
# but keep it in the local Docker daemon for development candidate assembly.
build_image aptl/generic-samba-ad-base:latest \
  containers/generic-samba-ad-base containers/generic-samba-ad-base/Dockerfile
build_image aptl/generic-systemd-base:latest \
  containers/generic-systemd-base containers/generic-systemd-base/Dockerfile
build_image aptl/generic-systemd-base-debian:latest \
  . containers/generic-systemd-base-debian/Dockerfile

build_image aptl/generic-samba-ad-wazuh-agent-base:latest . \
  containers/generic-samba-ad-wazuh-agent-base/Dockerfile local \
  "$(local_image_ref aptl/generic-samba-ad-base:latest)"
build_image aptl/generic-systemd-wazuh-agent-base:latest . \
  containers/generic-systemd-wazuh-agent-base/Dockerfile local \
  "$(local_image_ref aptl/generic-systemd-base:latest)"
build_image aptl/generic-systemd-wazuh-agent-base-debian:latest . \
  containers/generic-systemd-wazuh-agent-base-debian/Dockerfile local \
  "$(local_image_ref aptl/generic-systemd-base-debian:latest)"
build_image aptl/generic-systemd-node22-base:latest \
  . containers/generic-systemd-node22-base/Dockerfile
build_image aptl/generic-wazuh-agent-base-debian:latest . \
  containers/generic-wazuh-agent-base-debian/Dockerfile
build_image aptl/suricata-wazuh-agent:latest . \
  containers/suricata-wazuh-agent/Dockerfile
build_image aptl-kali-capture:latest . containers/kali-capture/Dockerfile
build_image aptl-network-boundary-helper:5 . \
  containers/network-boundary-helper/Dockerfile
build_image aptl-appliance-egress-proxy:1 . \
  containers/appliance-egress-proxy/Dockerfile
build_image aptl/operator-access-proxy:latest . \
  containers/operator-access-proxy/Dockerfile
