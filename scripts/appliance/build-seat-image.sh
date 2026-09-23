#!/usr/bin/env bash
# Bake one seat VM image: Ubuntu + Docker + the TechVault images, ready to run.
#
# The output is a standalone read-only qcow2 plus the config blob describing
# it. `aptl seat start` pulls both from a registry, overlays the disk and
# boots; nothing is built or resolved on a participant's machine.
#
# The guest is provisioned offline from a staged payload so the bake is
# reproducible from pinned inputs: the base image is fetched by digest, the
# container images are exported from an exact local build, and the Python
# closure is hash-locked.
set -euo pipefail

: "${APTL_BASE_IMAGE_URL:?base image URL is required}"
: "${APTL_BASE_IMAGE_SHA256:?base image digest is required}"
: "${APTL_GUEST_PYTHON_VERSION:?guest Python target is required}"

# Docker's own static build. The cloud base ships no Docker and the guest
# reaches no package repository during the bake, so the engine is staged here
# by digest and installed offline. The static tarball carries dockerd,
# containerd, runc and the shim, so nothing is resolved inside the guest.
APTL_DOCKER_VERSION=${APTL_DOCKER_VERSION:-29.8.1}
APTL_DOCKER_SHA256=${APTL_DOCKER_SHA256:-d8db66739d2e28d4933786d73e918d9be643a67fbd835db1bf740d650a259e70}

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
  echo "base image digest does not match the pin" >&2
  exit 1
}

# --- project container images ------------------------------------------
# Built from this exact source, then exported so the guest never pulls them.
lock_dir=$(mktemp -d -p "$build_root" images.XXXXXXXX)
export APTL_LOCAL_IMAGE_LOCK_FILE="$lock_dir/images.txt"
commit=$(git rev-parse --short=12 HEAD)
export APTL_LOCAL_IMAGE_TAG_SUFFIX="seat-${commit}-$$"
"$source_root/scripts/appliance/build-local-images.sh"

# Re-tag each built image to its canonical name inside the archive, so the
# guest loads exactly the names the lab expects.
canonical_refs=()
while read -r canonical built _id; do
  docker tag "$built" "$canonical"
  canonical_refs+=("$canonical")
done <"$APTL_LOCAL_IMAGE_LOCK_FILE"

# The third-party TechVault services are pinned by the scenario's asset lock.
readarray -t third_party < <(
  python3 "$source_root/scripts/appliance/seat-image-third-party.py"
)
for reference in "${third_party[@]}"; do
  docker pull --quiet "$reference"
done

docker save --output "$build_root/input/images.tar" \
  "${canonical_refs[@]}" "${third_party[@]}"

# --- guest image store -------------------------------------------------
# dockerd cannot run inside the libguestfs appliance -- it has no cgroup
# mounts -- so the guest's image store is built here instead, by the same
# pinned static daemon the guest will run, and copied in whole. The guest
# therefore boots with every image already in its local store and loads
# nothing.
payload=$build_root/input/payload
install -d -m 0700 "$payload"

docker_archive=$payload/docker-static.tgz
curl --fail --silent --show-error --location --max-time 900 \
  --output "$docker_archive" \
  "https://download.docker.com/linux/static/stable/x86_64/docker-${APTL_DOCKER_VERSION}.tgz"
docker_actual=$(sha256sum "$docker_archive" | cut -d' ' -f1)
test "$docker_actual" = "$APTL_DOCKER_SHA256" || {
  echo 'staged Docker archive digest does not match the pin' >&2
  exit 1
}
static_root=$build_root/docker-static
install -d -m 0755 "$static_root"
tar --extract --file "$docker_archive" --directory "$static_root" \
  --strip-components=1

guest_store=$build_root/guest-docker
staging_socket=$build_root/staging-docker.sock
install -d -m 0711 "$guest_store"
# The log is owned by this user; sudo would not affect the redirect anyway.
: >"$build_root/staging-docker.log"
sudo "$static_root/dockerd" --data-root "$guest_store" \
  --host "unix://$staging_socket" --pidfile "$build_root/staging-docker.pid" \
  --iptables=false --bridge=none 2>&1 |
  tee -a "$build_root/staging-docker.log" >/dev/null &
staging_attempts=0
until sudo "$static_root/docker" --host "unix://$staging_socket" info >/dev/null 2>&1; do
  staging_attempts=$((staging_attempts + 1))
  if test "$staging_attempts" -gt 120; then
    echo 'staging Docker daemon did not start' >&2
    cat "$build_root/staging-docker.log" >&2
    exit 1
  fi
  sleep 1
done
sudo "$static_root/docker" --host "unix://$staging_socket" load \
  --input "$build_root/input/images.tar"
staged_images=$(sudo "$static_root/docker" --host "unix://$staging_socket" \
  image ls --format '{{.Repository}}:{{.Tag}}' | grep -cv '^<none>')
sudo kill "$(sudo cat "$build_root/staging-docker.pid")"
while test -S "$staging_socket"; do sleep 1; done
test "$staged_images" -ge 25 || {
  echo "guest image store holds only $staged_images images" >&2
  exit 1
}
sudo tar --create --file "$payload/guest-docker.tar" --directory "$guest_store" .
sudo chown "$(id -u):$(id -g)" "$payload/guest-docker.tar"
unlink "$build_root/input/images.tar"

target_python=$(command -v "python${APTL_GUEST_PYTHON_VERSION}" || true)
if test -z "$target_python" && command -v uv >/dev/null 2>&1; then
  target_python=$(uv python find "$APTL_GUEST_PYTHON_VERSION")
fi
test -n "$target_python"

install -d -m 0700 "$payload/wheelhouse"
"$target_python" -m pip download --require-hashes \
  -r "$source_root/requirements/runtime.txt" --dest "$payload/wheelhouse"
python3 -m build --wheel --no-isolation --outdir "$payload/wheelhouse" \
  "$source_root"

cp "$source_root/appliance/guest/docker.service" "$payload/"
cp "$source_root/appliance/guest/aptl-appliance-first-boot" "$payload/"
cp "$source_root/appliance/guest/aptl-appliance-first-boot.service" "$payload/"
cp "$source_root/appliance/guest/aptl-launch.mount" "$payload/"
cp "$source_root/appliance/guest/provision-seat.sh" "$payload/"
chmod 0500 "$payload/provision-seat.sh"

tar --create --file "$build_root/input/payload.tar" --directory "$payload" .

# --- bake --------------------------------------------------------------
disk=$build_root/out/seat-disk.qcow2
qemu-img create -f qcow2 "$disk" "${disk_gib}G" >/dev/null
virt-resize --expand /dev/sda1 "$base" "$disk"

virt-customize --add "$disk" \
  --copy-in "$build_root/input/payload.tar:/opt" \
  --run-command 'mkdir -m 0700 -p /opt/aptl-stage' \
  --run-command 'tar --extract --file /opt/payload.tar --directory /opt/aptl-stage' \
  --run-command 'rm -f /opt/payload.tar' \
  --run-command '/opt/aptl-stage/provision-seat.sh' \
  --run-command 'rm -rf /opt/aptl-stage'

virt-sysprep --add "$disk" \
  --operations defaults,-ssh-userdir,-ssh-hostkeys \
  --firstboot-command 'systemctl enable --now aptl-appliance-first-boot.service'

qemu-img convert -O qcow2 -c "$disk" "$disk.compact"
mv "$disk.compact" "$disk"
chmod 0444 "$disk"

# --- self-description --------------------------------------------------
"$source_root/scripts/appliance/write-seat-image-config.py" \
  --output "$build_root/out/seat-image-config.json" \
  --disk "$disk"

rm -f "$APTL_LOCAL_IMAGE_LOCK_FILE"
rmdir "$lock_dir"
echo "$build_root/out"
