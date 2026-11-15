# rudra

Заметки к ядру. Общий обзор, скриншоты и сборка — в [README](../README.md) репозитория.

## v0.6: Linux ABI, SSE, busybox, потоки

Проверено в QEMU на `target/images/rudra-bios.img`:

- `hello.elf` печатает `pid = 2` и выходит с кодом 0
- шелл: `ls /`, `pwd`, `echo`, `cat /motd.txt`, `ps`, `uname` возвращаются к приглашению
- `/bin/busybox`: `ls /`, `cat /motd.txt`, `echo hi`, `wc -c /motd.txt` (291 байт), `true` — код 0
- `/bin/busybox yes` печатает `y`, пока жива ВМ
- `threads.elf`: четыре `clone`, общий счётчик `400000`, строка `OK, race-free`, код 0

Ядро принимает **Linux x86_64 syscall ABI** (`rax` — номер, аргументы `rdi/rsi/rdx/r10/r8/r9`). В `/bin/busybox` лежит статический glibc-бинарь (`ET_EXEC`, без `PT_INTERP`). Внешняя команда шелла — это `execve` busybox с argv `busybox <cmd>`.

Что это держит:

- SSE включает само ядро (`fpu.rs`): bootloader 0.11 его не включает. На смене задачи — `fxsave64` / `fxrstor64`. `CR4.OSXSAVE` не ставится, чтобы glibc не выбирал AVX-ifunc.
- Перед `call` из `syscall_entry` и `timer_entry` стек выравнивается на 16 байт. Иначе `fxsave64` ловит `#GP` с кодом 0.
- `execve` обнуляет регистры общего назначения (ELF_PLAT_INIT). Иначе glibc принимает `rdx` за `rtld_fini` и на выходе прыгает в мусор.
- `write_user` пишет по физическому адресу байта и не прибавляет смещение в странице второй раз. Иначе хвост auxv затирал GOT, и `println!("pid = {}", …)` падал на `rip = 0x7`.
- Стартовый кадр задачи лежит на `T-320`: первое аппаратное прерывание затирает верхние ~160 байт kernel-стека.
- `sys_clone` собирает кадр ребёнка в раскладке `timer_entry`, не `syscall_entry`.
- Мьютекс в `threads.elf` — спинлок. Futex в ядре есть, но на одном CPU с тиком PIT ~55 мс сон на каждую короткую секцию не успевает открутить 400 тысяч итераций.

Ещё возвращают `ENOSYS`, и программы при этом доживают до `exit 0`: `readlinkat` (267), `sendfile` (40), `time` (201). `rseq` (334) — тоже `ENOSYS`, специально.

Каталоги RFS2 — отдельные записи: `mkdir` создаёт узел, файл без родителя не появляется, `rmdir` удаляет только пустой каталог. Имя в таблице по-прежнему полный путь.

Шина PCI 0 читается (`pci.rs`): в QEMU видны мост i440FX, PIIX IDE, VGA и e1000.

## Диск: virtio-blk и ext2 только на чтение

Проверено в QEMU с `-device virtio-blk-pci,drive=vd0,disable-modern=on` и образом `target/images/data.img` (1 МиБ, `scripts/mk_ext2.py`):

```
[pci] 00:04.0 1af4:1001 class 010000
[virtio-blk] io 0xc000 queue 256 capacity 2048 host-features 0x71006ed4 guest-features 0x0 irq 11
[virtio-blk] LBA0: RUDRA-DISK
[block] write/read LBA 200: ok
[ext2] magic ok block 1024 inode-table 5
[ext2] /hello.txt
[ext2] /readme.txt
[ext2] /hello.txt: hello from ext2
```

Дальше приходит приглашение `rudra:/$`.

Корень шелла — по-прежнему RFS2 в памяти. ext2 не смонтирован в шелл: это второй том, ядро читает его один раз при старте. Гостевые features оставлены 0: базовый `VIRTIO_BLK_T_IN` / `T_OUT` от флага не зависит. Очередь одна, запрос один за раз. IRQ virtio (в этом прогоне 11) замаскирован, завершение — опрос used-кольца.

Без второго диска serial пишет `[virtio-blk] no device`. Юнит-тесты ядра на образе без virtio проходят (`isa-debug-exit`, код 33). `scripts/run-bios.sh` подключает `data.img`, только если файл уже собран. SMP ещё впереди.
