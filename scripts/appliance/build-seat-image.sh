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

# Refuse an accidental multi-hour software-emulated bake.
export LIBGUESTFS_BACKEND=${LIBGUESTFS_BACKEND:-direct}
export LIBGUESTFS_BACKEND_SETTINGS=force_kvm
guestfs_command=(env)
if test "${APTL_SEAT_LIBGUESTFS_SUDO:-0}" = 1; then
  guestfs_command=(sudo env "LIBGUESTFS_BACKEND=$LIBGUESTFS_BACKEND"
    "LIBGUESTFS_BACKEND_SETTINGS=$LIBGUESTFS_BACKEND_SETTINGS")
fi

# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/seat-base-image.env"

source_root=$PWD
host_python=${APTL_SEAT_HOST_PYTHON:-$source_root/.venv/bin/python}
if ! test -x "$host_python"; then
  echo "seat image build requires an installed project Python environment: $host_python" >&2
  exit 2
fi
source_commit=$(git rev-parse HEAD)
source_dirty=0
if test -n "$(git status --porcelain --untracked-files=normal)"; then
  source_dirty=1
  echo 'diagnostic build from dirty source; publication will be refused' >&2
fi
build_root=${APTL_SEAT_BUILD_ROOT:-$PWD/build/seat-image}
disk_gib=${APTL_SEAT_DISK_GIB:-128}
if ! [[ "$disk_gib" =~ ^[1-9][0-9]{1,3}$ ]] || ((disk_gib < 64 || disk_gib > 4096)); then
  echo 'APTL_SEAT_DISK_GIB must be between 64 and 4096' >&2
  exit 2
fi
if ! test -r /dev/kvm || ! test -w /dev/kvm; then
  echo 'seat image build requires access to /dev/kvm (join the kvm group)' >&2
  exit 2
fi

test ! -e "$build_root" || {
  echo "seat image build root already exists: $build_root" >&2
  exit 1
}
install -d -m 0700 "$build_root" "$build_root/input" "$build_root/cache" \
  "$build_root/out"

for tool in qemu-img virt-customize virt-sysprep virt-sparsify docker python3 npm uv; do
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
export APTL_SEAT_BAKE_SKIP_WEB=1
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
uv build --wheel --out-dir "$payload/wheelhouse" "$source_root"
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

install -d -m 0700 "$build_root/input/claude"
cp "$source_root/appliance/guest/claude/package.json" \
  "$source_root/appliance/guest/claude/package-lock.json" \
  "$build_root/input/claude/"
npm ci --prefix "$build_root/input/claude" --omit=dev --no-audit --no-fund
tar -cf "$payload/claude-runtime.tar" -C "$build_root/input/claude" \
  package.json package-lock.json node_modules

# The desktop gateway is part of the signed offline closure. Pull exact
# upstream digests, then give the guest stable local tags that survive
# docker save/load without a registry or the host Docker daemon.
desktop_images=(
  'guacamole/guacamole:1.6.0@sha256:f344085e618bb05e22b964b0208dbd06d3468275bac70206f93805245e067b40 aptl-seat-guacamole:1.6.0'
  'guacamole/guacd:1.6.0@sha256:8974eaa9ba32f713daf311e7cc8cd7e4cdfba1edea39eed75524e78ef4b08f4f aptl-seat-guacd:1.6.0'
  'postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea aptl-seat-postgres:16'
  'nginx:stable-alpine@sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94 aptl-seat-nginx:stable'
)
desktop_tags=()
for entry in "${desktop_images[@]}"; do
  read -r pinned local_tag <<<"$entry"
  docker pull "$pinned"
  docker tag "$pinned" "$local_tag"
  desktop_tags+=("$local_tag")
done
docker run --rm aptl-seat-guacamole:1.6.0 \
  /opt/guacamole/bin/initdb.sh --postgresql |
  sed '/^-- Create default user "guacadmin"/,$d' >"$payload/guac-schema.sql"
test -s "$payload/guac-schema.sql"
for filename in desktop-compose.yml desktop-nginx.conf seat-desktop.py seat-privileges.py desktop-handoff.py desktop-mcp-smoke.py desktop-session.sh; do
  cp "$source_root/appliance/guest/$filename" "$payload/"
done

# Build a clean project tree first, then write the image-bound participant
# profile into that tree. The checkout itself is never modified by the bake.
"$host_python" - "$source_root" "$build_root/input/source-project.tar" <<'PYTHON'
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(sys.argv[1]) / "src"))
from aptl.utils.mcp_packaging import archive_project

root = pathlib.Path(sys.argv[1])
archive_project(root, pathlib.Path(sys.argv[2]))
PYTHON
install -d -m 0700 "$build_root/input/project"
tar -xf "$build_root/input/source-project.tar" -C "$build_root/input/project"
PYTHONPATH="$source_root/src" "$host_python" \
  "$source_root/scripts/appliance/assemble-seat-inputs.py" \
  --project "$build_root/input/project" --work "$build_root/input" \
  --local-image-lock "$APTL_LOCAL_IMAGE_LOCK_FILE" \
  --roles-output "$build_root/input/image-roles.json" \
  --tags-output "$build_root/input/image-tags.txt" \
  --tag-ids-output "$build_root/input/image-tag-ids.json"
readarray -t image_tags <"$build_root/input/image-tags.txt"
docker save --output "$payload/oci-images.tar" "${image_tags[@]}" "${desktop_tags[@]}"
extra_image_args=()
for tag in "${desktop_tags[@]}"; do
  extra_image_args+=(--extra-image-tag "$tag")
done
PYTHONPATH="$source_root/src" "$host_python" \
  "$source_root/scripts/appliance/assemble-seat-inputs.py" \
  --project "$build_root/input/project" --work "$build_root/input" \
  --local-image-lock "$APTL_LOCAL_IMAGE_LOCK_FILE" \
  --roles-output "$build_root/input/image-roles.json" \
  --tags-output "$build_root/input/image-tags.txt" \
  --tag-ids-output "$build_root/input/image-tag-ids.json" \
  --verify-archive "$payload/oci-images.tar" \
  "${extra_image_args[@]}"
# The built MCP entrypoints need runtime packages, but the TypeScript and
# vitest trees used to compile them would otherwise add gigabytes to the disk.
# Package "prepare" hooks rebuild file dependencies during npm prune even
# with --ignore-scripts. Remove those hooks only in the archived guest copy.
python3 - "$build_root/input/project/mcp" <<'PYTHON'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
for package in (root / "aptl-mcp-common", *sorted(root.glob("mcp-*"))):
    path = package / "package.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document.get("scripts", {}).pop("prepare", None)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
PYTHON
for package in "$build_root/input/project/mcp/aptl-mcp-common" \
  "$build_root"/input/project/mcp/mcp-*; do
  (cd "$package" && npm prune --omit=dev --ignore-scripts --no-audit --no-fund)
done
"$host_python" - "$source_root" "$build_root/input/project" "$payload/project.tar" <<'PYTHON'
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
"${guestfs_command[@]}" virt-resize --expand /dev/sda1 "$base" "$disk"

"${guestfs_command[@]}" virt-customize --add "$disk" \
  --run-command 'mkdir -m 0700 -p /opt/aptl-stage' \
  --copy-in "$build_root/input/offline-payload.tar:/opt/aptl-stage" \
  --copy-in "$source_root/appliance/guest/provision-offline.sh:/opt/aptl-stage" \
  --run-command 'chmod 0500 /opt/aptl-stage/provision-offline.sh' \
  --run-command '/opt/aptl-stage/provision-offline.sh'

"${guestfs_command[@]}" virt-sysprep --add "$disk" --operations defaults
# Provisioning temporarily copied and extracted the offline payload inside the
# guest. Discard those now-free ext4 blocks before qcow2 compression, otherwise
# the registry layer still carries the deleted multi-gigabyte staging data.
"${guestfs_command[@]}" virt-sparsify --in-place "$disk"

# Inspect the actual finalized guest. This catches missing Docker, Python
# entrypoints, an unexpanded root filesystem, and leaked build state before
# anything can be published.
"${guestfs_command[@]}" virt-customize --add "$disk" \
  --copy-in "$source_root/appliance/guest/scan-golden.sh:/tmp" \
  --run-command "chmod 0500 /tmp/scan-golden.sh && APTL_SEAT_DISK_GIB=$disk_gib /tmp/scan-golden.sh && rm /tmp/scan-golden.sh && truncate -s 0 /etc/machine-id"

test "$("${guestfs_command[@]}" virt-cat -a "$disk" /etc/machine-id | wc -c)" -eq 0 || {
  echo 'final seat disk still contains a machine identity' >&2
  exit 1
}

qemu-img convert -O qcow2 -c "$disk" "$disk.compact"
mv "$disk.compact" "$disk"
chmod 0444 "$disk"

# --- self-description --------------------------------------------------
PYTHONPATH="$source_root/src" "$host_python" \
  "$source_root/scripts/appliance/write-seat-image-config.py" \
  --output "$build_root/out/seat-image-config.json" \
  --disk "$disk"

if test "$(git rev-parse HEAD)" != "${source_commit:-$commit}" || \
  test -n "$(git status --porcelain --untracked-files=normal)"; then
  source_dirty=1
fi
python3 "$source_root/scripts/appliance/seat-build-record.py" write \
  "$build_root/out" --commit "${source_commit:-$(git rev-parse "$commit")}" \
  --dirty "${source_dirty:-1}"

unlink "$APTL_LOCAL_IMAGE_LOCK_FILE"
rmdir "$lock_dir"
echo "$build_root/out"
