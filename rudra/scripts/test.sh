#!/usr/bin/env bash
# Юнит-тесты ядра в QEMU: cargo test -> ELF -> BIOS-образ -> isa-debug-exit.
# Коды выхода QEMU: 33 = успех, 35 = провал, 124 = зависание/таймаут.
set -e
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

echo "== building kernel tests"
cargo test -p rudra --lib --target x86_64-unknown-none --no-run --message-format=json \
    | python -c "
import sys, json
for line in sys.stdin:
    try: m = json.loads(line)
    except ValueError: continue
    if m.get('profile', {}).get('test') and m.get('executable'):
        print(m['executable'])
" > /tmp/rudra-test-bin.txt
ELF=$(cat /tmp/rudra-test-bin.txt | head -1)
if [ -z "$ELF" ] || [ ! -f "$ELF" ]; then
    echo "test binary not found" >&2
    exit 1
fi
echo "== test binary: $ELF"

(cd builder && cargo run --release -q -- "$ELF" ../target/images/rudra-test-bios.img)

echo "== running tests in QEMU"
set +e
timeout 60 "/c/Program Files/qemu/qemu-system-x86_64.exe" \
    -drive format=raw,file="$(pwd -W)/target/images/rudra-test-bios.img" \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -serial stdio -display none -m 256M
CODE=$?
set -e

case $CODE in
    33) echo "== RESULT: PASS" ;;
    35) echo "== RESULT: FAIL (qemu exit 35)"; exit 1 ;;
    124) echo "== RESULT: TIMEOUT (kernel hung)"; exit 1 ;;
    *) echo "== RESULT: UNKNOWN (qemu exit $CODE)"; exit 1 ;;
esac
