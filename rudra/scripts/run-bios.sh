#!/usr/bin/env bash
# Запуск rudra в QEMU (BIOS, serial -> stdout).
set -e
cd "$(dirname "$0")/.."
REL="target/images/rudra-1.0.0.img"
[ -f "$REL" ] || ./scripts/build.sh
# Один диск: загрузчик в начале, ext2 с 16 МиБ. BIOS грузит его с virtio-blk.
exec "/c/Program Files/qemu/qemu-system-x86_64.exe" \
    -m 256M -serial stdio \
    -drive "if=none,id=vd0,format=raw,file=$(pwd -W)/$REL" \
    -device "virtio-blk-pci,drive=vd0,disable-modern=on,bootindex=0"
