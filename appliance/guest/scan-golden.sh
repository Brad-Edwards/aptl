#!/bin/sh
# Fail if the finalized immutable base contains state owned by an overlay.
set -eu

# virt-customize assigns a temporary machine ID before it runs this scan.
# The bake clears it after the scan and verifies the final disk read-only.
if find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*_key' -print |
    grep -q .
then
    exit 1
fi

# No base-image or build-host login material survives into a participant disk.
if find /root /home -xdev -type f \( \
    -path '*/.ssh/*' -o -name '.bash_history' -o -name '.zsh_history' -o \
    -name '.netrc' -o -name '.npmrc' -o -name '.pypirc' -o \
    -path '*/.aws/credentials' -o -path '*/.config/gh/hosts.yml' \
    \) -print 2>/dev/null | grep -q .
then
    exit 1
fi

# aptl-mcp is the sole intentionally unlocked account: it has no password and
# the generation-bound transport starts its own public-key-only sshd.
if awk -F: '$2 != "" && $2 !~ /^[!*]/ { print $1 }' /etc/shadow | grep -q .
then
    exit 1
fi
test "$(awk -F: '$2 == "" { print $1 }' /etc/shadow)" = aptl-mcp

for executable in docker node python3 systemctl sshd
do
    command -v "$executable" >/dev/null
done
docker buildx version >/dev/null
docker compose version >/dev/null
test -x /opt/aptl/app/bin/aptl
/usr/local/bin/aptl --version >/dev/null
# Exercise the immutable runtime through the identity that the enrolled SSH
# transport actually uses. A root-only scan cannot detect missing traversal or
# read bits introduced by the provisioner's private umask.
su -s /bin/sh -c '
    /usr/local/bin/aptl --version >/dev/null &&
    test -r /opt/aptl/project/mcp/mcp-red/build/index.js
' aptl-mcp
case "$(node --version)" in
    v22.*) ;;
    *) exit 1 ;;
esac
# Allow five percent for EFI/boot partitions and filesystem metadata.
# Compare the root filesystem to the requested virtual size, not a fixed cut.
expected_disk_gib=${APTL_SEAT_DISK_GIB:-250}
case "$expected_disk_gib" in
    ''|*[!0-9]*) echo 'invalid expected disk size' >&2; exit 1 ;;
esac
test "$expected_disk_gib" -ge 64 && test "$expected_disk_gib" -le 4096
minimum_root_bytes=$(( expected_disk_gib * 1024 * 1024 * 1024 * 19 / 20 ))
test "$(df -B1 --output=size / | tail -n 1)" -ge "$minimum_root_bytes"

for clean_path in \
    /var/lib/cloud/instance \
    /var/lib/cloud/instances \
    /var/lib/cloud/seed \
    /opt/aptl-stage \
    /run/secrets \
    /var/run/secrets
do
    if test -e "$clean_path" &&
        find "$clean_path" -mindepth 1 -print -quit 2>/dev/null | grep -q .
    then
        exit 1
    fi
done

for runtime_path in \
    /var/lib/docker \
    /opt/aptl/project/.aptl
do
    if test -d "$runtime_path" &&
        find "$runtime_path" -mindepth 1 -print -quit | grep -q .
    then
        exit 1
    fi
done

# The service account's empty home is immutable account scaffolding, not
# overlay state. No sibling or descendant may exist in the golden image.
test -d /var/lib/aptl/mcp
if find /var/lib/aptl -mindepth 1 -maxdepth 1 ! -name mcp -print -quit |
    grep -q .
then
    exit 1
fi
if find /var/lib/aptl/mcp -mindepth 1 -print -quit | grep -q .
then
    exit 1
fi

test ! -e /opt/aptl/project/.env
test -r /opt/aptl/offline/oci-images.tar
test -r /opt/aptl/project/participant-profiles/techvault-full-v1/profile.json

# Inspect every bundled container layer namespace. Lab target data may contain
# deliberate vulnerable credentials, but host/operator credential locations do
# not belong in any layer.
python3 - /opt/aptl/offline/oci-images.tar <<'PYTHON'
import pathlib
import json
import sys
import tarfile

forbidden = (
    ".aws/credentials",
    ".config/gh/hosts.yml",
    ".docker/config.json",
    ".kube/config",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    "run/secrets/",
    "var/run/secrets/",
)
with tarfile.open(sys.argv[1], "r:") as outer:
    manifest_file = outer.extractfile("manifest.json")
    if manifest_file is None:
        raise SystemExit("image archive has no Docker manifest")
    manifest = json.load(manifest_file)
    layers = sorted({name for image in manifest for name in image["Layers"]})
    if not layers or len(layers) > 10000:
        raise SystemExit("too many image layers")
    for name in layers:
        path = pathlib.PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit("unsafe image layer name")
        layer = outer.getmember(name)
        source = outer.extractfile(layer)
        if source is None or not layer.isfile() or layer.size > 100 * 1024**3:
            raise SystemExit("invalid image layer")
        with tarfile.open(fileobj=source, mode="r|*") as archive:
            for member in archive:
                name = pathlib.PurePosixPath(member.name).as_posix().lstrip("./")
                if any(token in name for token in forbidden):
                    raise SystemExit("operator credential path in image layer")
PYTHON
