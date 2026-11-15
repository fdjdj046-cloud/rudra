# rudra 1.0.0

Research OS. Не ставьте образ на единственный диск с данными.

Это первый контракт, не «полная Linux». Скачанный файл — **один raw-образ, не ISO**.

## Артефакт

| | |
|---|---|
| Файл | `rudra-1.0.0.img` |
| Размер | 33554432 байт (32 МиБ) |
| SHA256 | `388473cfce65e71c0f1878fc9ab3f7a8b472f2578c49feeda384d8c7cb471f47` |
| Что внутри | байты `0 .. 16 МиБ` — загрузчик и ядро; с байта `16777216` — ext2 |

Образ, который уже загружался, отличается в свободном блоке: при монтировании ядро пишет проверочный узор в один свободный блок и возвращает бит в bitmap. Контрольная сумма выше — у **незагруженного** файла из Releases.

## QEMU

Одна строка. Диск и загрузка — один и тот же virtio-blk. Отдельный ISO и второй диск не нужны.

```
qemu-system-x86_64 -m 256M -serial stdio -drive if=none,id=vd0,format=raw,file=rudra-1.0.0.img -device virtio-blk-pci,drive=vd0,disable-modern=on,bootindex=0
```

На этой машине бинарь такой: `C:\Program Files\qemu\qemu-system-x86_64.exe`.

В serial при нормальной загрузке есть PCI `1af4:1001`, строка `[ext2] mounted off 0x1000000` и `[root] ext2 on virtio-blk`, затем приглашение `rudra:/$`. Если virtio нет, ядро пишет `[virtio-blk] no device` и `[root] recovery ramdisk` и всё равно поднимает шелл с ramdisk RFS2. Это запасной корень, не основной.

`uname` печатает `rudra rudra 1.0.0 #1 rudra 1.0.0 x86_64 x86_64`. Поле release — `1.0.0`, как тег.

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

Данные переживают reboot. Прогон `scripts/smoke.py` на копии образа: `echo persist-ok > /keep.txt`, `mkdir` / `rm` / `rmdir`, восемь `run /bin/hello.elf`, затем встроенный `reboot`, затем `cat /keep.txt` снова печатает `persist-ok`. Слоты задач после `exit` занимаются заново (их 32).

## Проверка с хоста

На машине сборки нет `e2fsck` (WSL без дистрибутива). Образ собран как обычный ext2, суперблок на смещении 1024 внутри файловой системы, таблица групп — блок 1. Проверка среза:

```
dd if=rudra-1.0.0.img of=root.ext2 bs=1048576 skip=16 count=16
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
- свои ELF: `/bin/hello.elf`, `/bin/threads.elf` (четыре `clone`, счётчик 400000, `OK, race-free`)

`/bin/counter.elf` и `/bin/fizzbuzz.elf` лежат на диске и грузятся тем же `execve`. В smoke этого коммита они не запускались.

`fork` + `execve` + `wait4` — путь шелла и busybox. Пользовательский page fault убивает задачу, шелл остаётся. Паника — только если fault в ядре.

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
| 24 | sched_yield: успех, тик PIT и так вытесняет |
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
