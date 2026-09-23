#!/usr/bin/env bash
# Bake one seat VM image: Ubuntu, Docker, and the TechVault images, ready to go.
#
# The guest provisioning this drives is `appliance/guest/provision-offline.sh`,
# the same script that built the seats run in the field. It installs Docker
# from digest-locked .deb files staged here rather than from a repository the
# guest cannot reach, installs the APTL runtime from a hash-locked wheelhouse,
# and places the container image archive on disk. First boot loads that archive
# once per overlay, so a participant's seat resolves nothing and pulls nothing.
#
# The output is a standalone read-only qcow2 plus the config blob describing
# it; `aptl seat start` pulls both from a registry and overlays the disk.
set -euo pipefail

: "${APTL_BASE_IMAGE_URL:?base image URL is required}"
: "${APTL_BASE_IMAGE_SHA256:?base image digest is required}"
: "${APTL_GUEST_PYTHON_VERSION:?guest Python target is required}"

source_root=$PWD
build_root=${APTL_SEAT_BUILD_ROOT:-$PWD/build/seat-image}
disk_gib=${APTL_SEAT_DISK_GIB:-250}

test ! -e "$build_root"
install -d -m 0700 "$build_root" "$build_root/input" "$build_root/cache" \
  "$build_root/out"

for tool in qemu-img virt-customize virt-sysprep docker python3; do
  command -v "$tool" >/dev/null || {
    echo "seat image build requires $tool" >&2
    exit 2
  }
done

# --- pinned base image -------------------------------------------------
base=$build_root/cache/base.qcow2
expected=${APTL_BASE_IMAGE_SHA256#sha256:}
curl --fail --silent --show-error --location --max-time 1800 \
  --output "$base" "$APTL_BASE_IMAGE_URL"
actual=$(sha256sum "$base" | cut -d' ' -f1)
test "$actual" = "$expected" || {
  echo 'base image digest does not match the pin' >&2
  exit 1
}

# --- container images --------------------------------------------------
# This project's images are built from the exact source and exported, so the
# guest holds the same bytes this commit produces. The third-party set comes
# from the Compose definition, which is the only statement of what the lab
# actually starts.
payload=$build_root/input/payload
install -d -m 0700 "$payload"

lock_dir=$(mktemp -d -p "$build_root" images.XXXXXXXX)
export APTL_LOCAL_IMAGE_LOCK_FILE="$lock_dir/images.txt"
commit=$(git rev-parse --short=12 HEAD)
export APTL_LOCAL_IMAGE_TAG_SUFFIX="seat-${commit}-$$"
"$source_root/scripts/appliance/build-local-images.sh"

canonical_refs=()
while read -r canonical built _id; do
  docker tag "$built" "$canonical"
  canonical_refs+=("$canonical")
done <"$APTL_LOCAL_IMAGE_LOCK_FILE"

readarray -t third_party < <(
  python3 "$source_root/scripts/appliance/seat-image-third-party.py"
)
for reference in "${third_party[@]}"; do
  docker pull --quiet "$reference"
done

docker save --output "$payload/oci-images.tar" \
  "${canonical_refs[@]}" "${third_party[@]}"

# --- guest system packages ---------------------------------------------
# Docker and its companions arrive as digest-locked .deb files, downloaded
# here where there is a network and unpacked offline in the guest.
"$source_root/scripts/appliance/acquire-guest-system-packages.sh" \
  "$payload/system-packages"
cp "$source_root/appliance/guest/system-packages.sha256" "$payload/"

# --- guest runtime -----------------------------------------------------
target_python=$(command -v "python${APTL_GUEST_PYTHON_VERSION}" || true)
if test -z "$target_python" && command -v uv >/dev/null 2>&1; then
  target_python=$(uv python find "$APTL_GUEST_PYTHON_VERSION")
fi
test -n "$target_python"

install -d -m 0700 "$payload/wheelhouse"
"$target_python" -m pip download --require-hashes \
  -r "$source_root/requirements/runtime.txt" --dest "$payload/wheelhouse"
cp "$source_root/requirements/runtime.txt" "$payload/requirements.txt"
python3 -m build --wheel --no-isolation --outdir "$payload/wheelhouse" \
  "$source_root"

# The guest's project tree, with runtime identity and credentials excluded.
python3 - "$source_root" "$payload/project.tar" <<'PYTHON'
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(sys.argv[1]) / "src"))
from aptl.utils.mcp_packaging import archive_project, flatten_common_dependencies

root = pathlib.Path(sys.argv[1])
flatten_common_dependencies(root)
archive_project(root, pathlib.Path(sys.argv[2]))
PYTHON

printf 'APTL_SEAT_COMMIT=%s\n' "$commit" >"$payload/appliance-release.env"
cp "$source_root/appliance/guest/aptl-appliance-first-boot" "$payload/"
cp "$source_root/appliance/guest/aptl-appliance-first-boot.service" "$payload/"
cp "$source_root/appliance/guest/aptl-launch.mount" "$payload/"

tar --create --file "$build_root/input/offline-payload.tar" \
  --directory "$payload" .

# --- bake --------------------------------------------------------------
disk=$build_root/out/seat-disk.qcow2
qemu-img create -f qcow2 "$disk" "${disk_gib}G" >/dev/null
virt-resize --expand /dev/sda1 "$base" "$disk"

virt-customize --add "$disk" \
  --run-command 'mkdir -m 0700 -p /opt/aptl-stage' \
  --copy-in "$build_root/input/offline-payload.tar:/opt/aptl-stage" \
  --copy-in "$source_root/appliance/guest/provision-offline.sh:/opt/aptl-stage" \
  --run-command 'chmod 0500 /opt/aptl-stage/provision-offline.sh' \
  --run-command '/opt/aptl-stage/provision-offline.sh'

virt-sysprep --add "$disk" \
  --operations defaults,-ssh-userdir,-ssh-hostkeys

qemu-img convert -O qcow2 -c "$disk" "$disk.compact"
mv "$disk.compact" "$disk"
chmod 0444 "$disk"

# --- self-description --------------------------------------------------
"$source_root/scripts/appliance/write-seat-image-config.py" \
  --output "$build_root/out/seat-image-config.json" \
  --disk "$disk"

unlink "$APTL_LOCAL_IMAGE_LOCK_FILE"
rmdir "$lock_dir"
echo "$build_root/out"
