#!/usr/bin/env bash
set -euo pipefail

if test -n "$(git status --porcelain --untracked-files=no)"; then
  echo 'local candidate builds require a clean exact source commit' >&2
  exit 2
fi

export APTL_CANDIDATE_MODE=local
export APTL_BASE_IMAGE_URL=${APTL_BASE_IMAGE_URL:-https://cloud-images.ubuntu.com/releases/resolute/release-20260823/ubuntu-26.04-server-cloudimg-amd64.img}
export APTL_BASE_IMAGE_SHA256=${APTL_BASE_IMAGE_SHA256:-sha256:8196be9d7958059cb56c6c75c80fdf6cee8a8885bc149ea791d7db1c7ef93035}
export APTL_BASE_IMAGE_SIZE_BYTES=${APTL_BASE_IMAGE_SIZE_BYTES:-863306240}
export APTL_GUEST_PYTHON_VERSION=${APTL_GUEST_PYTHON_VERSION:-3.14}

scripts/appliance/build-local-images.sh
scripts/appliance/build-candidate.sh
