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
- Мьютекс в `threads.elf` — спинлок, `futex` он не зовёт. В ядре `FUTEX_WAIT`/`FUTEX_WAKE` уже будят ждущих на том же CPU. Тик BSP — LAPIC около 4 мс. На образе тега 1.0.1 тик всё ещё PIT, а `WAKE` никого не будит.

Ещё возвращают `ENOSYS`, и программы при этом доживают до `exit 0`: `readlinkat` (267), `sendfile` (40), `time` (201). `rseq` (334) — тоже `ENOSYS`, специально.

Каталоги RFS2 — отдельные записи: `mkdir` создаёт узел, файл без родителя не появляется, `rmdir` удаляет только пустой каталог. Имя в таблице по-прежнему полный путь.

Шина PCI 0 читается (`pci.rs`): в QEMU видны мост i440FX, PIIX IDE, VGA и e1000.

## 1.0.1

Текущий образ — `target/images/rudra-1.0.1.img`. Поверх 1.0.0: проверка пользовательских указателей в syscall (`EFAULT`, ядро не паникует), возврат кадров и блоков кучи, `e2fsck -fn` чистый, `scripts/test.sh` и `scripts/smoke.py` без зашитого пути QEMU. `.github/workflows/ci.yml` гоняет тесты ядра и короткий headless smoke (`SMOKE_HELLOS=8`). Локи `TASKS`, кучи, кадров и очереди клавиатуры в syscall берутся с выключенными прерываниями. IRQ-фикс (риск зависания шелла) в опубликованный образ 1.0.1 не вошёл. Теги `v1.0.0` и `v1.0.1` не сдвигаются. Server 1.1 в дереве не закрыт: TSC и RTC есть, у AP свой TSS и тик, задача с affinity исполняется на этом CPU, свободные задачи балансируются (наименее загруженный CPU при рождении, воровство при простое), `/proc/stat` отдаёт `cpuN`-тики. x2APIC нет. Поверх этого — UDP и virtio-net, DHCP запрашивается при загрузке, если карта есть. Перехваченный сигнал с `SA_RESTORER` доставляется на возврате из syscall и с тика в ring 3. Смертельный сигнал забирается без syscall: планировщик убивает задачу до выбора, `deliver_timer` — входящую в ring 3. Сон, futex, pipe, poll и recvfrom возвращают `EINTR`. Чтение консоли нет. `SIGCHLD` приходит, когда завершается дочерний процесс. epoll level- и edge-triggered (`EPOLLET`) по номеру fd; `/sys` содержит `cpu/online` (диапазон поднятых CPU) и `hostname` (`rudra`). UDP на проводе считает сумму и принимает 0. TCP — петля и провод (DHCP, handshake, эхо с хостом; повторов нет). ARP помнит восемь соседей. `PT_INTERP` запускает один интерпретатор; релокации `RELATIVE` и символьные (`64`/`GLOB_DAT`/`JUMP_SLOT`) резолвятся в `.dynsym` своего объекта, живой прогон — `dsym.elf` (`dsym-ok`). Задача рождается root (uid 0); `setuid` без прав даёт `EPERM`. `seccomp` strict пускает только read, write, `rt_sigreturn` и exit. Кэш virtio-blk — 16 слотов чтения по 4 КиБ, запись слот сбрасывает. PID1 — `/bin/init.elf`, он поднимает шелл. `CLONE_FS` делит cwd и umask. umask срезает биты mkdir и нового файла, chmod их пишет, stat читает. Проверки доступа нет. Тег 2.0.0 только для сервера. Десктоп — ветки `desktop-3.x`. Карта: [../ROADMAP.md](../ROADMAP.md).

## 1.0.0: ext2 read-write — это корень

Серверный контур на `main`, тег 2.0.0 ещё не стоит. Не ставьте образ на единственный диск с данными. Контракт, whitelist и `ENOSYS` — в [RELEASE_NOTES.md](../RELEASE_NOTES.md).

Релизный файл — `target/images/rudra-1.0.0.img`, raw, не ISO. 32 МиБ: загрузчик в первых 16 МиБ, ext2 сразу после. QEMU грузит его одним virtio-blk (`disable-modern=on`, `bootindex=0`). Проверено на копии: запись `/keep.txt`, reboot, чтение того же текста; busybox `echo`/`cat`/`ls`/`wc`/`true`/`rmdir` и `hello.elf`/`threads.elf` выходят с кодом 0. Юнит-тесты без диска по-прежнему печатают `[virtio-blk] no device`, `[root] recovery ramdisk` и проходят (код выхода QEMU 33).

Гостевые features virtio оставлены 0. Очередь одна. IRQ virtio маскируется, завершение — опрос used-кольца. Запись сектора проверяется внутри свободного блока ext2, не в LBA загрузчика.
