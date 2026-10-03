#!/usr/bin/env bash
# Qualify all desktop privilege modes from one immutable signed seat image.
set -euo pipefail
umask 077

source_root=$PWD
image=${1:?signed image digest is required}
public_key=${2:-}
if ! [[ "$image" =~ @sha256:[a-f0-9]{64}$ ]]; then
  echo 'qualify an exact signed image digest, not a mutable tag' >&2
  exit 2
fi
aptl_cli=${APTL_SEAT_CLI:-$source_root/.venv/bin/aptl}
test -x "$aptl_cli" || {
  echo 'installed APTL CLI is required' >&2
  exit 2
}
test -r /dev/kvm && test -w /dev/kvm || {
  echo 'seat privilege qualification requires access to /dev/kvm' >&2
  exit 2
}
for tool in virt-customize virt-cat; do
  command -v "$tool" >/dev/null || {
    echo "seat privilege qualification requires $tool" >&2
    exit 2
  }
done

export LIBGUESTFS_BACKEND=${LIBGUESTFS_BACKEND:-direct}
export LIBGUESTFS_BACKEND_SETTINGS=force_kvm
guestfs_command=(env)
if test "${APTL_SEAT_LIBGUESTFS_SUDO:-0}" = 1; then
  guestfs_command=(sudo env "LIBGUESTFS_BACKEND=$LIBGUESTFS_BACKEND"
    "LIBGUESTFS_BACKEND_SETTINGS=$LIBGUESTFS_BACKEND_SETTINGS")
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/aptl-seat-privileges.XXXXXXXX")
active_root=
cleanup() {
  if test -n "$active_root"; then
    "$aptl_cli" seat stop --seat-root "$active_root" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT

image_args=(--image "$image" --yes)
if test -n "$public_key"; then
  image_args+=(--public-key "$public_key")
fi

for mode in event password passwordless; do
  seat_root=$work/$mode
  active_root=$seat_root
  start_args=(--seat-root "$seat_root" "${image_args[@]}")
  probe_mode=$mode
  if test "$mode" = event; then
    start_args+=(--desktop-mode event)
  else
    start_args+=(--desktop-mode administrative)
    password_file=$work/seat-qualification-password
    if test "$mode" = password; then
      python3 -c 'import secrets,sys;sys.stdout.write(secrets.token_hex(24))' >"$password_file"
    else
      : >"$password_file"
    fi
    chmod 0600 "$password_file"
    start_args+=(--sudo-password-file "$password_file")
  fi
  "$aptl_cli" seat start "${start_args[@]}" >"$work/$mode.start.json"
  "$aptl_cli" seat stop --seat-root "$seat_root" >"$work/$mode.stop.json"
  active_root=

  overlay=$seat_root/instances/seat-01.qcow2
  test -f "$overlay"
  copy_args=(--copy-in "$source_root/appliance/guest/seat-privilege-qualification.py:/root")
  if test "$mode" = password; then
    copy_args+=(--copy-in "$password_file:/root")
  fi
  "${guestfs_command[@]}" virt-customize --add "$overlay" \
    "${copy_args[@]}" \
    --run-command "/usr/bin/python3 /root/seat-privilege-qualification.py $probe_mode"
  result=$work/$mode.result.json
  "${guestfs_command[@]}" virt-cat -a "$overlay" \
    /root/seat-privilege-qualification.json >"$result"
  python3 - "$result" "$mode" <<'PYTHON'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
if report.get("mode") != sys.argv[2] or report.get("passed") is not True:
    raise SystemExit("guest privilege checks failed")
checks = report.get("checks")
if not isinstance(checks, dict) or not checks or not all(value is True for value in checks.values()):
    raise SystemExit("guest privilege checks are incomplete")
PYTHON
  if test "$mode" != event; then
    rm -f -- "$password_file"
  fi
  active_root=$seat_root
  "$aptl_cli" seat start --seat-root "$seat_root" "${image_args[@]}" \
    >"$work/$mode.restart.json"
  "$aptl_cli" seat stop --seat-root "$seat_root" \
    >"$work/$mode.final-stop.json"
  active_root=
  echo "seat privilege mode passed: $mode"
done

echo 'seat privilege qualification passed'
