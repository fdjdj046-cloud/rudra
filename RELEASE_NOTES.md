# rudra 1.0.1

Research OS. Не ставьте образ на единственный диск с данными.

Это первый контракт, не «полная Linux». Скачанный файл — **один raw-образ, не ISO**.

## Артефакт

| | |
|---|---|
| Файл | `rudra-1.0.1.img` |
| Размер | 33554432 байт (32 МиБ) |
| SHA256 | `907d27e179049afef4a7e4ce9f4fbdfb36cdd2802109cb92b36adf343c58d86a` |
| Что внутри | байты `0 .. 16 МиБ` — загрузчик и ядро; с байта `16777216` — ext2 |

Образ, который уже загружался, отличается в свободном блоке: при монтировании ядро пишет проверочный узор в один свободный блок и возвращает бит в bitmap. Контрольная сумма выше — у **незагруженного** файла из Releases. Рядом с образом лежит `rudra-1.0.1.img.sha256` с той же суммой. Тег `v1.0.0` не сдвигался.

## QEMU

Одна строка. Диск и загрузка — один и тот же virtio-blk. Отдельный ISO и второй диск не нужны.

```
qemu-system-x86_64 -m 256M -serial stdio -drive if=none,id=vd0,format=raw,file=rudra-1.0.1.img -device virtio-blk-pci,drive=vd0,disable-modern=on,bootindex=0
```

На этой машине бинарь такой: `C:\Program Files\qemu\qemu-system-x86_64.exe`.

В serial при нормальной загрузке есть PCI `1af4:1001`, строка `[ext2] mounted off 0x1000000` и `[root] ext2 on virtio-blk`, затем приглашение `rudra:/$`. Если virtio нет, ядро пишет `[virtio-blk] no device` и `[root] recovery ramdisk` и всё равно поднимает шелл с ramdisk RFS2. Это запасной корень, не основной.

`uname` печатает `rudra rudra 1.0.1 #1 rudra 1.0.1 x86_64 x86_64`. Поле release — `1.0.1`, как тег.

## Корень

ext2 rev 1, блок 4096, inode 128 байт, одна группа, incompat-флаг только `FILETYPE` (0x2). `ro_compat` пустой: нет `sparse_super`, журнала, extents, `dir_index`, `metadata_csum`, `large_file`.

| Лимит | Значение |
|---|---|
| Файловая система | 16 МиБ, 4096 блоков, 512 inode |
| Файл | 4243456 байт (12 прямых блоков и один косвенный) |
| Каталог | только прямые блоки, не больше 12 |
| Имя и путь | 255 байт |
| Свободно на свежем образе | 3553 блока, 492 inode |

`mkdir`, `rmdir`, `rename`, `unlink` возвращают POSIX-ошибки (`ENOENT`, `EEXIST`, `ENOTDIR`, `EISDIR`, `ENOTEMPTY`, `ENOSPC`, `EINVAL`, `EPERM`). `rmdir /` — `EPERM`. Удаление каталога через `unlink` — `EISDIR`.

Запись файла в шелле — замена целиком при `close`. `echo text > file` не добавляет перевод строки.

Данные переживают reboot. Прогон `scripts/smoke.py` на копии образа: `echo persist-ok > /keep.txt`, `mkdir` / `rm` / `rmdir`, `counter.elf`, `fizzbuzz.elf`, сорок `run /bin/hello.elf`, затем встроенный `reboot`, затем `cat /keep.txt` снова печатает `persist-ok`. Слоты задач после `exit` занимаются заново (их 32). Скрипт ищет QEMU в переменной `QEMU`, в PATH и в стандартном пути Windows. Число hello — `SMOKE_HELLOS` (по умолчанию 40).

Куча отдаёт блоки обратно (первый подходящий, соседи сливаются). Кадры возвращаются в список; курсор выдачи сдвигается только когда списка нет, без прохода `nth`. Страницы пользователя (поддерево L4[0]) и kernel-стек 64 КиБ освобождаются, когда задачу забирает `wait` или слот занимают заново. Тесты ядра: 639 блоков по 64 КиБ, освобождение и повторная выдача; после возврата 64 кадров курсор не двигается; строка `ok` в последних байтах страницы читается, а чтение через границу в несмапленную страницу — нет. На теге 1.0.1 тестов девять. В текущем дереве к ним добавлены шкала TSC, чтение local APIC загрузочного CPU, период его таймера, подъём второго CPU и IPI, календарь RTC, отказ `rseq` без задачи, контрольная сумма IPv4, UDP на `127.0.0.1`, DHCP с ARP шлюза QEMU (адрес `10.0.2.15`) и чтение `/proc/uptime`. `munmap` по-прежнему ничего не отдаёт.

## Проверка с хоста

Суперблок на смещении 1024 внутри файловой системы, таблица групп — блок 1. Срез незагруженного образа проверен `e2fsck 1.44.5 -fn`: пять проходов, код 0, строка `rudra-root: 20/512 files (5.0% non-contiguous), 543/4096 blocks`. Это 3553 свободных блока.

Та же проверка на копии после smoke (`/keep.txt` оставлен, каталог `/demo` создан и удалён, reboot): код 0, `rudra-root: 21/512 files (4.8% non-contiguous), 544/4096 blocks`. Свободных блоков 3552, лишний inode и блок — это файл. Вторая загрузка печатает `free 3552`.

```
dd if=rudra-1.0.1.img of=root.ext2 bs=1048576 skip=16 count=16
e2fsck -fn root.ext2
debugfs -R "ls /" root.ext2
```

Собрать такой же образ из дерева: `./rudra/scripts/build.sh`. Он вызывает `scripts/mk_ext2.py`. Если файловую систему пересоздаёте сами, набор флагов такой:

```
mkfs.ext2 -b 4096 -I 128 -N 512 -L rudra-root -O filetype,^resize_inode,^dir_index,^sparse_super,^large_file,^huge_file,^metadata_csum,^extents
```

Скрипт сборки не вызывает `mkfs`: он пишет ту же геометрию сам и проверяет, что `/bin/busybox` читается обратно.

## Что гарантировано

Шелл после загрузки — первая задача. Встроенные команды: `help`, `ls`, `cat`, `echo`, `pwd`, `cd`, `rm`, `mkdir`, `ps`, `uname`, `clear`, `run`, `reboot`, `exit`.

Внешняя команда: путь, затем `/bin/<cmd>`, затем `/bin/<cmd>.elf`, затем `/bin/busybox` с аргументами `busybox <cmd>`.

На ext2-корне этого коммита дошли до кода 0:

- шелл: `ls`, `cat`, `echo` с перенаправлением, `mkdir`, `rm`, `uname`, `run`, `reboot`
- busybox: `echo`, `cat`, `ls`, `wc -c /motd.txt` (`203 /motd.txt`), `true`, `rmdir`
- свои ELF: `/bin/hello.elf` (сорок запусков в smoke), `/bin/counter.elf`, `/bin/fizzbuzz.elf`, `/bin/threads.elf` (четыре `clone`, счётчик 400000, `OK, race-free` — на образе 1.0.0)

`fork` + `execve` + `wait4` — путь шелла и busybox. Указатель из syscall проверяется до чтения: адрес в диапазоне `0x1000 .. 4 ГиБ`, в таблице страниц задачи стоят present и user, для записи ещё writable. Копирование идёт через physmap, виртуальный адрес задачи не разыменовывается. Иначе `EFAULT`. Строка читается до NUL и не заходит на следующую страницу: argv лежит сразу под несмапленным верхом стека. В PTE бит 7 — это PAT, не huge page; отказ по huge стоит только на PDPTE и PDE. Пользовательский page fault убивает задачу. #PF ядра по адресу ниже 4 ГиБ при живой задаче тоже убивает задачу и пишет в serial `KERNEL PAGE FAULT below 4GiB`: так можно спрятать баг ядра, поэтому строка намеренно громкая. Паника — если fault по адресу ядра.

`syscall_entry` делает `sti`. Пока syscall держит `TASKS`, кучу, кадры или очередь клавиатуры, прерывания выключены: таймер и IRQ клавиатуры берут те же локи, и на одном ядре это был бы вечный спин. IRQ-фикс (риск зависания шелла) в 1.0.1 не вошёл и приедет в 1.0.2. Опубликованный `rudra-1.0.1.img` собран с тега `v1.0.1`; тег не сдвигается.

`sys_clone`, `spawn_path` и разбор адресного пространства целиком идут с выключенным IF: глубокая копия L4 и `free_user_space`. На это время не приходит и тик планировщика. `nanosleep` и `CLOCK_MONOTONIC` считают наносекунды по TSC, откалиброванному каналом 2 PIT. `CLOCK_REALTIME` — CMOS RTC на момент загрузки плюс тот же TSC, без NTP. Планировщик тикает от локального APIC BSP, около 250 Гц; IRQ0 PIT после этого маскируется. Остальные CPU из MADT получают INIT/SIPI, отвечают на IPI и стоят в `hlt`: очереди задач на них нет. `FUTEX_WAIT`/`WAKE` будят ждущих; `REQUEUE` и PI нет. `rseq` регистрируется и на вытеснении из ring 3 переносит rip на abort, если подпись сходится. Legacy virtio-net шлёт и принимает кадры. DHCP в QEMU user-net берёт IPv4, ARP резолвит шлюз (один слот кэша). Сокеты `AF_INET`/`SOCK_DGRAM`: `socket`, `bind`, `connect`, `sendto`, `recvfrom`, петля `127.0.0.0/8`. IPv6, TCP и netlink нет, `SOCK_STREAM` — `EPROTONOSUPPORT`. Сумма UDP не проверяется. На образе тега `v1.0.1` этого нет: там сон и квант кратны ~55 мс, второй CPU не стартует. Дорога к Server 2.0.0 — [ROADMAP.md](ROADMAP.md). Десктоп в `main` не входит, для него ветки `desktop-3.x`.

GitHub Actions после тестов ядра собирает образ и гоняет `scripts/smoke.py` без дисплея (`SMOKE_HELLOS=8`, TCG без KVM, таймаут шага 15 минут). Так 5.3 и 5.4 в CI проверяются слабее, чем локально. Перед следующим тегом на своей машине нужен прогон с `SMOKE_HELLOS=40`. Прогон на 40 hello был на ядре `dbaa7e5` и не покрывает ни тик LAPIC, ни второй CPU. После этой правки локально прогнан короткий smoke на 2 hello с `-smp 2` и virtio-net: загрузка, ext2, MAC карты, reboot, `persist-ok`. Это не прогон на 40 hello.

## Linux x86_64: номера, которые ядро принимает

Номер в `rax`, аргументы `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`. Возврат в `rax`.

| Номера | Поведение |
|---|---|
| 0, 1 | read, write |
| 2, 257, 85 | open, openat, creat |
| 3 | close |
| 4, 6, 5, 262, 332 | stat, lstat, fstat, newfstatat, statx |
| 7, 23 | poll, select |
| 8 | lseek. Успех возвращает **0**, не новую позицию |
| 9 | mmap анонимной памяти. Файл — `ENODEV` |
| 10, 11, 28 | mprotect, munmap, madvise: успех, память не отдаётся |
| 12 | brk |
| 13, 14, 62 | сигналы и kill: успех, доставки нет |
| 16 | ioctl консоли: TCGETS/TCSETS и TIOCGWINSZ |
| 17 | pread64 |
| 18 | pwrite64 пишет с текущего смещения и **игнорирует позицию** |
| 19, 20 | readv, writev |
| 21, 439 | access, faccessat2 |
| 22, 293 | pipe, pipe2 |
| 24 | sched_yield: успех, тик планировщика и так вытесняет |
| 32, 33 | dup, dup2 |
| 35, 230 | nanosleep, clock_nanosleep |
| 39, 110, 186 | getpid, getppid, gettid |
| 56, 57, 58, 59 | clone, fork, vfork, execve |
| 60, 231 | exit, exit_group |
| 61 | wait4 |
| 63 | uname |
| 72 | fcntl |
| 73, 74, 75 | flock, fsync, fdatasync: успех |
| 76, 77 | truncate / ftruncate только до нуля |
| 78, 217 | getdents64 |
| 79, 80 | getcwd, chdir |
| 82, 83, 84, 87 | rename, mkdir, rmdir, unlink |
| 86 | link: **копия байтов**, не жёсткая ссылка |
| 88, 89 | symlink пишет цель как содержимое; readlink его читает |
| 90, 91, 95 | chmod, fchmod: успех; umask хранится |
| 96, 228, 100 | gettimeofday, clock_gettime, times — время работы, не стена |
| 97, 302 | rlimit: без лимита |
| 99 | sysinfo, грубая оценка |
| 102, 104, 107, 108 | uid/gid = 1000 |
| 105, 106 | setuid/setgid: успех |
| 157, 158 | prctl: успех; arch_prctl работает |
| 169 | reboot. Магия `0xfee1dead` / `672274793`. Перезагрузка `0x01234567` и `0xA1B2C3D4`, питание `0x4321FEDC` (порт `0x604`), останов `0xCDEF0123` |
| 202 | futex: WAIT крутит `hlt`, WAKE ничего не будит |
| 203, 204 | affinity: один CPU |
| 218 | set_tid_address |
| 273, 274 | robust_list: успех |
| 318 | getrandom: не криптостойкий xorshift от RDTSC |
| 324 | membarrier: успех |
| 334 | rseq: **ENOSYS** специально |
| 1000 | свой `ps` |

Всё, чего нет в таблице, — `ENOSYS`. Номер пишется в serial один раз. На этом прогоне busybox получил `ENOSYS` и всё равно вышел с кодом 0: `readlinkat` 267, `sendfile` 40, `time` 201.

Не обещано в 1.0: сокеты, настоящие сигналы, ptrace, epoll «как в Linux», динамический линкер, glibc с `PT_INTERP`, IRELATIVE со стороны ядра (их применяет сам busybox), SMP, сеть, GPU, USB, звук, Secure Boot, TPM, произвольный desktop-бинарь Linux.

## Лицензия

MIT или Apache-2.0, на выбор.
