#!/usr/bin/env bash
# Сборка user-программы + ядра + boot-образов (BIOS/UEFI).
set -e
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

echo "== building user program (ring 3, static relocation)"
# Статическая релокация: без PIE/GOT, иначе нужен обход динамических релокаций.
RUSTFLAGS="-C relocation-model=static" cargo build -p user --release --target x86_64-unknown-none

echo "== building kernel"
cargo build -p rudra --target x86_64-unknown-none

echo "== creating disk images"
(cd builder && cargo run --release)
python scripts/mk_ext2.py target/images/data.img
echo "images: target/images/rudra-bios.img, target/images/rudra-uefi.img, target/images/data.img"
