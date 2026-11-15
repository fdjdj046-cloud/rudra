#!/usr/bin/env bash
# Сборка ядра + создание boot-образов (BIOS/UEFI).
set -e
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

cargo build --target x86_64-unknown-none
(cd builder && cargo run --release)
echo "images: target/images/rudra-bios.img, target/images/rudra-uefi.img"
