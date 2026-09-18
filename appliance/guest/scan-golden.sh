#!/bin/sh
# Fail if the finalized immutable base contains state owned by an overlay.
set -eu

test ! -s /etc/machine-id
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
test -x /opt/aptl/python/bin/aptl
/usr/local/bin/aptl --version >/dev/null
case "$(node --version)" in
    v22.*) ;;
    *) exit 1 ;;
esac
# The planned 250-GiB disk must include an expanded root filesystem; merely
# enlarging the qcow2 container is not sufficient.
test "$(df -B1 --output=size / | tail -n 1)" -ge 214748364800

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
    /var/lib/aptl \
    /opt/aptl/project/.aptl
do
    if test -d "$runtime_path" &&
        find "$runtime_path" -mindepth 1 -print -quit | grep -q .
    then
        exit 1
    fi
done

test ! -e /opt/aptl/project/.env
test -r /opt/aptl/offline/oci-images.tar
test -r /opt/aptl/project/participant-profiles/techvault-full-v1/profile.json

# Inspect every bundled container layer namespace. Lab target data may contain
# deliberate vulnerable credentials, but host/operator credential locations do
# not belong in any layer.
python3 - /opt/aptl/offline/oci-images.tar <<'PYTHON'
import pathlib
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
    layers = [item for item in outer.getmembers() if item.isfile() and item.name.endswith(".tar")]
    if len(layers) > 10000:
        raise SystemExit("too many image layers")
    for layer in layers:
        source = outer.extractfile(layer)
        if source is None or layer.size > 100 * 1024**3:
            raise SystemExit("invalid image layer")
        with tarfile.open(fileobj=source, mode="r|") as archive:
            for member in archive:
                name = pathlib.PurePosixPath(member.name).as_posix().lstrip("./")
                if any(token in name for token in forbidden):
                    raise SystemExit("operator credential path in image layer")
PYTHON
