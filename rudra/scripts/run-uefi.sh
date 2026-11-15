#!/usr/bin/env bash
# Запуск rudra в QEMU (UEFI/OVMF, serial -> stdout).
set -e
cd "$(dirname "$0")/.."
IMG="target/images/rudra-uefi.img"
[ -f "$IMG" ] || ./scripts/build.sh
OVMF="C:/Program Files/qemu/share/edk2-x86_64-code.fd"
exec "/c/Program Files/qemu/qemu-system-x86_64.exe" \
    -machine q35 -pflash "$OVMF" \
    -drive format=raw,file="$(pwd -W)/$IMG" \
    -serial stdio -m 256M
