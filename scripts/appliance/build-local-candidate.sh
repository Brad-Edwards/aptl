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

install -d -m 0700 build
local_image_lock_dir=$(mktemp -d -p "$PWD/build" aptl-local-images.XXXXXXXX)
cleanup_local_image_lock() {
  if test -f "$local_image_lock_dir/images.txt"; then
    unlink "$local_image_lock_dir/images.txt"
  fi
  rmdir "$local_image_lock_dir"
}
trap cleanup_local_image_lock EXIT
export APTL_LOCAL_IMAGE_LOCK_FILE="$local_image_lock_dir/images.txt"
export APTL_LOCAL_IMAGE_TAG_SUFFIX="$(git rev-parse --short=12 HEAD)-$$"

scripts/appliance/build-local-images.sh
scripts/appliance/build-candidate.sh
