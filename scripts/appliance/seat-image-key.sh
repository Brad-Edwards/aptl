#!/usr/bin/env bash
# Print the content key for the seat image this commit would produce.
#
# The key is a digest over everything that changes the baked image: the guest
# provisioning assets, the container definitions whose images are preloaded
# into it, the locked Python closure, the participant profile, and the pinned
# base image. A commit that touches none of them produces the same key, so the
# release workflow reuses the image already published under it instead of
# baking an identical one.
set -euo pipefail

: "${APTL_BASE_IMAGE_SHA256:?base image digest is required}"
: "${APTL_GUEST_PYTHON_VERSION:?guest Python target is required}"

# Directories and files whose contents decide what ends up inside the image.
inputs=(
  appliance/guest
  containers
  mcp
  web
  requirements/runtime.txt
  requirements/web.txt
  participant-profiles
  src/aptl/appliance/policy.py
  scripts/appliance/build-seat-image.sh
  scripts/appliance/build-local-images.sh
)

# git hash-object over tracked content keeps this independent of mtimes,
# checkout order and untracked build residue.
{
  printf 'base=%s\n' "$APTL_BASE_IMAGE_SHA256"
  printf 'python=%s\n' "$APTL_GUEST_PYTHON_VERSION"
  git ls-files -z -- "${inputs[@]}" |
    sort -z |
    while IFS= read -r -d '' path; do
      printf '%s %s\n' "$(git hash-object -- "$path")" "$path"
    done
} | sha256sum | cut -d' ' -f1
