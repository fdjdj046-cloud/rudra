#!/usr/bin/env bash
# Сборка user-программы + ядра + boot-образов (BIOS/UEFI).
set -e
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

echo "== building user program (ring 3, static relocation)"
# Статическая релокация: без PIE/GOT, иначе нужен обход динамических релокаций.
RUSTFLAGS="-C relocation-model=static" cargo build -p user --release --target x86_64-unknown-none

# Свежие user-бинарники должны попасть в embed ядра: cargo на этой машине
# не перезапускает build script по rerun-if-changed вне пакета, а часы скачут,
# так что mtime-оптимизации недёжны. Физически сносим выводы build.rs —
# удалённое cargo восстановить обязано.
rm -rf target/x86_64-unknown-none/release/build/rudra \
       target/x86_64-unknown-none/debug/build/rudra

echo "== building kernel"
# Релиз: builder упаковывает именно release-артефакт (artifact dependency),
# dev-ядро в образ не попадало бы.
cargo build -p rudra --release --target x86_64-unknown-none

echo "== creating disk images"
# env!("CARGO_BIN_FILE_*") зашит во время компиляции builder'а и указывает на
# artifact-зависимость rudra. Пересобираем builder с нуля, иначе он пакует
# ядро, собранное на момент его ПРЕДЫДУЩЕЙ компиляции.
rm -f target/release/builder.exe
(cd builder && cargo run --release)
PY="python3"
if ! command -v python3 >/dev/null 2>&1; then
    PY="python"
fi
"$PY" scripts/mk_ext2.py target/images/rudra-bios.img target/images/rudra-1.0.1.img
echo "images: target/images/rudra-bios.img, target/images/rudra-uefi.img, target/images/rudra-1.0.1.img"
