#!/usr/bin/env bash
# Юнит-тесты ядра в QEMU: cargo test -> ELF -> BIOS-образ -> isa-debug-exit.
# Коды выхода QEMU: 33 = успех, 35 = провал, 124 = зависание/таймаут.
# QEMU: переменная QEMU, иначе qemu-system-x86_64 в PATH, иначе путь Windows.
set -e
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

if [ -n "${QEMU:-}" ]; then
    :
elif command -v qemu-system-x86_64 >/dev/null 2>&1; then
    QEMU="qemu-system-x86_64"
elif [ -x "/c/Program Files/qemu/qemu-system-x86_64.exe" ]; then
    QEMU="/c/Program Files/qemu/qemu-system-x86_64.exe"
elif [ -x "/mnt/c/Program Files/qemu/qemu-system-x86_64.exe" ]; then
    QEMU="/mnt/c/Program Files/qemu/qemu-system-x86_64.exe"
else
    echo "qemu-system-x86_64 not found; set QEMU=" >&2
    exit 1
fi

PY="python3"
if ! command -v python3 >/dev/null 2>&1; then
    PY="python"
fi

echo "== building kernel tests"
cargo test -p rudra --lib --target x86_64-unknown-none --no-run --message-format=json \
    | "$PY" -c "
import sys, json
for line in sys.stdin:
    try: m = json.loads(line)
    except ValueError: continue
    if m.get('profile', {}).get('test') and m.get('executable'):
        print(m['executable'])
" > /tmp/rudra-test-bin.txt
ELF=$(head -1 /tmp/rudra-test-bin.txt)
if [ -z "$ELF" ] || [ ! -f "$ELF" ]; then
    echo "test binary not found" >&2
    exit 1
fi
echo "== test binary: $ELF"

mkdir -p target/images
(cd builder && cargo run --release -q -- "$ELF" ../target/images/rudra-test-bios.img)

IMG="$(pwd)/target/images/rudra-test-bios.img"
if command -v cygpath >/dev/null 2>&1; then
    IMG=$(cygpath -w "$IMG")
fi

echo "== running tests in QEMU ($QEMU)"
set +e
timeout 90 "$QEMU" \
    -drive format=raw,file="$IMG" \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -serial stdio -display none -m 256M -smp 2
CODE=$?
set -e

case $CODE in
    33) echo "== RESULT: PASS" ;;
    35) echo "== RESULT: FAIL (qemu exit 35)"; exit 1 ;;
    124) echo "== RESULT: TIMEOUT (kernel hung)"; exit 1 ;;
    *) echo "== RESULT: UNKNOWN (qemu exit $CODE)"; exit 1 ;;
esac
