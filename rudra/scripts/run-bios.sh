#!/usr/bin/env bash
# Запуск rudra в QEMU (BIOS, serial -> stdout).
set -e
cd "$(dirname "$0")/.."
IMG="target/images/rudra-bios.img"
[ -f "$IMG" ] || ./scripts/build.sh
exec "/c/Program Files/qemu/qemu-system-x86_64.exe" \
    -drive format=raw,file="$(pwd -W)/$IMG" \
    -serial stdio -m 256M
