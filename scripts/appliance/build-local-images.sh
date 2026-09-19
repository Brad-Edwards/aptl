#!/usr/bin/env bash
set -euo pipefail

build_image() {
  local canonical=$1
  local context=$2
  local dockerfile=$3
  local base_mode=${4:-remote}
  local build=(docker build --provenance=false)
  if test "$base_mode" = remote; then
    build+=(--pull)
  elif test "$base_mode" != local; then
    echo 'invalid container base mode' >&2
    exit 2
  fi
  "${build[@]}" --file "$dockerfile" --tag "$canonical" "$context"
}

# Build the same exact-source project-owned closure as the release workflow,
# but keep it in the local Docker daemon for development candidate assembly.
build_image aptl/generic-samba-ad-base:latest \
  containers/generic-samba-ad-base containers/generic-samba-ad-base/Dockerfile
build_image aptl/generic-systemd-base:latest \
  containers/generic-systemd-base containers/generic-systemd-base/Dockerfile
build_image aptl/generic-systemd-base-debian:latest \
  . containers/generic-systemd-base-debian/Dockerfile

build_image aptl/generic-samba-ad-wazuh-agent-base:latest . \
  containers/generic-samba-ad-wazuh-agent-base/Dockerfile local
build_image aptl/generic-systemd-wazuh-agent-base:latest . \
  containers/generic-systemd-wazuh-agent-base/Dockerfile local
build_image aptl/generic-systemd-wazuh-agent-base-debian:latest . \
  containers/generic-systemd-wazuh-agent-base-debian/Dockerfile local
build_image aptl/generic-systemd-node22-base:latest \
  containers/generic-systemd-node22-base containers/generic-systemd-node22-base/Dockerfile
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
