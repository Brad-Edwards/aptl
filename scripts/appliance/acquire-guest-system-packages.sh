#!/usr/bin/env bash
set -euo pipefail

if test "$#" -ne 1; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi

output=$1
source_root=$(git rev-parse --show-toplevel)
lock="$source_root/appliance/guest/system-packages.sha256"
image='ubuntu:26.04@sha256:da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78'

test ! -e "$output"
install -d -m 0700 "$output"
docker run --rm \
  --volume "$output:/output" \
  "$image" sh -ec '
    apt-get update >/dev/null
    apt-get install --download-only --no-install-recommends -y \
      -o Dir::Cache::archives=/output \
      docker.io=29.1.3-0ubuntu4.1 \
      docker-buildx=0.30.1-0ubuntu1 \
      docker-compose-v2=2.40.3+ds1-0ubuntu1 \
      nodejs=22.22.1+dfsg+~cs22.19.15-1ubuntu1 \
      openssh-server=1:10.2p1-2ubuntu3.6 >/dev/null
    chmod 0644 /output/*.deb
    find /output/partial -depth -delete
    find /output/lock -delete
  '

# Both sides sort under C collation. Locale-dependent ordering silently
# disagrees on names carrying '+' and '~' -- a Debian version separator, so
# every package this stages is a candidate -- and the lock was written on
# whatever locale generated it.
expected=$(sed -n 's/^[0-9a-f]\{64\}  //p' "$lock" | LC_ALL=C sort)
actual=$(find "$output" -maxdepth 1 -type f -name '*.deb' -printf '%f\n' |
  LC_ALL=C sort)
test "$actual" = "$expected"
(cd "$output" && sha256sum --check --strict "$lock")
