#!/usr/bin/env bash
# Boot the baked disk in a disposable overlay and prove Docker, the lab and MCP.
set -euo pipefail
export LIBGUESTFS_BACKEND=${LIBGUESTFS_BACKEND:-direct}
export LIBGUESTFS_BACKEND_SETTINGS=force_kvm

source_root=$PWD
disk=${1:?baked seat disk is required}
test -r "$disk"
test -r /dev/kvm && test -w /dev/kvm || {
  echo 'seat qualification requires access to /dev/kvm' >&2
  exit 2
}
for tool in qemu-img qemu-system-x86_64 virt-customize virt-cat; do
  command -v "$tool" >/dev/null || {
    echo "seat qualification requires $tool" >&2
    exit 2
  }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/aptl-seat-qualification.XXXXXXXX")
cleanup() {
  if test "${APTL_SEAT_QUALIFY_KEEP_WORK:-0}" = 1; then
    echo "seat qualification workspace: $work" >&2
  else
    rm -rf -- "$work"
  fi
}
trap cleanup EXIT
overlay=$work/seat.qcow2
qemu-img create -f qcow2 -F qcow2 -b "$(realpath "$disk")" "$overlay" >/dev/null

virt-customize --add "$overlay" \
  --copy-in "$source_root/appliance/guest/seat-qualification-smoke.sh:/usr/local/libexec" \
  --copy-in "$source_root/appliance/guest/seat-qualification-smoke.service:/etc/systemd/system" \
  --run-command 'chmod 0755 /usr/local/libexec/seat-qualification-smoke.sh && systemctl disable aptl-appliance-first-boot.service && systemctl enable seat-qualification-smoke.service'

vm_status=0
timeout --signal=TERM --kill-after=30s 4200 \
  qemu-system-x86_64 \
    -enable-kvm -cpu host -smp 8 -m 32768 -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive "file=$overlay,format=qcow2,if=virtio,cache=none,aio=threads,readonly=off" \
    -netdev user,id=participant,restrict=on,net=10.0.2.0/24,dhcpstart=10.0.2.15 \
    -device virtio-net-pci,netdev=participant \
    -device virtio-rng-pci \
    -serial "file:$work/serial.log" -display none -monitor none \
  || vm_status=$?

result=$work/result
if ! virt-cat -a "$overlay" /var/log/aptl-seat-qualification.result >"$result"; then
  echo 'seat qualification produced no guest result' >&2
  exit 1
fi
cat "$result"
if test "$vm_status" -ne 0 || \
  ! grep -qx 'docker=0 compose=0 load=0 run=0' "$result" || \
  ! grep -qx 'lab=0' "$result" || \
  ! grep -qx 'mcp=0' "$result" || \
  ! grep -qx 'cleanup=0 clean_start=0 clean_stop=0' "$result"; then
  echo "seat qualification failed (VM exit ${vm_status})" >&2
  exit 1
fi
echo 'seat qualification passed'
