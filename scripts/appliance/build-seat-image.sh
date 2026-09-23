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

# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/seat-base-image.env"

source_root=$PWD
build_root=${APTL_SEAT_BUILD_ROOT:-$PWD/build/seat-image}
disk_gib=${APTL_SEAT_DISK_GIB:-250}

test ! -e "$build_root" || {
  echo "seat image build root already exists: $build_root" >&2
  exit 1
}
install -d -m 0700 "$build_root" "$build_root/input" "$build_root/cache" \
  "$build_root/out"

for tool in qemu-img virt-customize virt-sysprep virt-sparsify docker python3 npm; do
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
# This project's images are built from the exact source. The realized scenario
# supplies the full service and helper image closure; Compose adds services
# that sit outside that scenario matrix.
payload=$build_root/input/payload
install -d -m 0700 "$payload"

lock_dir=$(mktemp -d -p "$build_root" images.XXXXXXXX)
export APTL_LOCAL_IMAGE_LOCK_FILE="$lock_dir/images.txt"
commit=$(git rev-parse --short=12 HEAD)
export APTL_LOCAL_IMAGE_TAG_SUFFIX="seat-${commit}-$$"
"$source_root/scripts/appliance/build-local-images.sh"

while read -r canonical built _id; do
  docker tag "$built" "$canonical"
done <"$APTL_LOCAL_IMAGE_LOCK_FILE"

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
test -n "$target_python" || {
  echo "no python${APTL_GUEST_PYTHON_VERSION} available for the guest closure" >&2
  exit 1
}

install -d -m 0700 "$payload/wheelhouse"
"$target_python" -m pip download --require-hashes \
  -r "$source_root/requirements/runtime.txt" --dest "$payload/wheelhouse"
cp "$source_root/requirements/runtime.txt" "$payload/requirements.txt"
python3 -m build --wheel --no-isolation --outdir "$payload/wheelhouse" \
  "$source_root"
python3 - "$source_root/pyproject.toml" "$payload/wheelhouse" \
  "$payload/aptl-wheel-requirements.txt" <<'PYTHON'
import hashlib
import pathlib
import sys
import tomllib

project = tomllib.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
version = project["project"]["version"]
wheels = list(pathlib.Path(sys.argv[2]).glob(f"aptl_labs-{version}-*.whl"))
if len(wheels) != 1:
    raise SystemExit("bake must produce exactly one APTL application wheel")
digest = hashlib.sha256(wheels[0].read_bytes()).hexdigest()
pathlib.Path(sys.argv[3]).write_text(
    f"aptl-labs=={version} --hash=sha256:{digest}\n", encoding="utf-8"
)
PYTHON

# Build the shipped client code from the lockfiles. A clean release checkout
# has neither node_modules nor MCP/web build output; copying the source alone
# would leave the guest with nonfunctional MCP entrypoints.
for package in "$source_root/mcp/aptl-mcp-common" "$source_root"/mcp/mcp-*; do
  (cd "$package" && npm ci --no-audit --no-fund && npm run build)
done
(cd "$source_root/web" && npm ci --no-audit --no-fund && npm run build)

# Build a clean project tree first, then write the image-bound participant
# profile into that tree. The checkout itself is never modified by the bake.
python3 - "$source_root" "$build_root/input/source-project.tar" <<'PYTHON'
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(sys.argv[1]) / "src"))
from aptl.utils.mcp_packaging import archive_project

root = pathlib.Path(sys.argv[1])
archive_project(root, pathlib.Path(sys.argv[2]))
PYTHON
install -d -m 0700 "$build_root/input/project"
tar -xf "$build_root/input/source-project.tar" -C "$build_root/input/project"
PYTHONPATH="$source_root/src" python3 \
  "$source_root/scripts/appliance/assemble-seat-inputs.py" \
  --project "$build_root/input/project" --work "$build_root/input" \
  --local-image-lock "$APTL_LOCAL_IMAGE_LOCK_FILE" \
  --roles-output "$build_root/input/image-roles.json" \
  --tags-output "$build_root/input/image-tags.txt" \
  --tag-ids-output "$build_root/input/image-tag-ids.json"
readarray -t image_tags <"$build_root/input/image-tags.txt"
docker save --output "$payload/oci-images.tar" "${image_tags[@]}"
PYTHONPATH="$source_root/src" python3 \
  "$source_root/scripts/appliance/assemble-seat-inputs.py" \
  --project "$build_root/input/project" --work "$build_root/input" \
  --local-image-lock "$APTL_LOCAL_IMAGE_LOCK_FILE" \
  --roles-output "$build_root/input/image-roles.json" \
  --tags-output "$build_root/input/image-tags.txt" \
  --tag-ids-output "$build_root/input/image-tag-ids.json" \
  --verify-archive "$payload/oci-images.tar"
python3 - "$source_root" "$build_root/input/project" "$payload/project.tar" <<'PYTHON'
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(sys.argv[1]) / "src"))
from aptl.utils.mcp_packaging import archive_project

archive_project(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
PYTHON

printf 'APTL_SEAT_COMMIT=%s\n' "$commit" >"$payload/appliance-release.env"
cp "$source_root/appliance/guest/aptl-appliance-first-boot" "$payload/"
cp "$source_root/appliance/guest/aptl-appliance-first-boot.service" "$payload/"
cp "$source_root/appliance/guest/aptl-launch.mount" "$payload/"

(
  cd "$payload"
  find . -mindepth 1 -printf '%P\0' |
    tar --null --no-recursion --create \
      --file "$build_root/input/offline-payload.tar" --files-from -
)

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

virt-sysprep --add "$disk" --operations defaults
# Provisioning temporarily copied and extracted the offline payload inside the
# guest. Discard those now-free ext4 blocks before qcow2 compression, otherwise
# the registry layer still carries the deleted multi-gigabyte staging data.
virt-sparsify --in-place "$disk"

# Inspect the actual finalized guest. This catches missing Docker, Python
# entrypoints, an unexpanded root filesystem, and leaked build state before
# anything can be published.
virt-customize --add "$disk" \
  --copy-in "$source_root/appliance/guest/scan-golden.sh:/tmp" \
  --run-command 'chmod 0500 /tmp/scan-golden.sh && /tmp/scan-golden.sh && rm /tmp/scan-golden.sh && truncate -s 0 /etc/machine-id'

test "$(virt-cat -a "$disk" /etc/machine-id | wc -c)" -eq 0 || {
  echo 'final seat disk still contains a machine identity' >&2
  exit 1
}

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
