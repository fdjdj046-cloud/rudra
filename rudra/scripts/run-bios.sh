#!/usr/bin/env bash
# Запуск rudra в QEMU (BIOS, serial -> stdout).
set -e
cd "$(dirname "$0")/.."
IMG="target/images/rudra-bios.img"
DATA="target/images/data.img"
[ -f "$IMG" ] || ./scripts/build.sh
ARGS=(-drive "format=raw,file=$(pwd -W)/$IMG" -serial stdio -m 256M)
if [ -f "$DATA" ]; then
    # Legacy virtio-blk: BAR0 — порт, а не современный MMIO.
    ARGS+=(-drive "if=none,id=vd0,format=raw,file=$(pwd -W)/$DATA")
    ARGS+=(-device "virtio-blk-pci,drive=vd0,disable-modern=on")
fi
exec "/c/Program Files/qemu/qemu-system-x86_64.exe" "${ARGS[@]}"
