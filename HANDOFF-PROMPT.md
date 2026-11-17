
Ты продолжаешь разработку учебной x86-64 ОС **rudra** на Rust (no_std). Репозиторий уже склонирован, код на GitHub: https://github.com/fdjdj046-cloud/rudra (ветка main, последний коммит `3799edc` "rudra v0.6 WIP"). **Первым делом: сделай commit/push всего, что изменишь, в конце сессии — репозиторий должен быть актуален.**

## Цель проекта

«Реально нормальная операционка»: запуск **нативных статических Linux-бинарников** (glibc/musl, уже лежит /bin/busybox из Debian static), **многопоточность** (clone CLONE_VM + futex), чистое современное ядро. Дальше по плану: SMP, ext2/VirtIO, сеть.

## Среда (Windows, Git Bash)

- Rust nightly: `export PATH="$HOME/.cargo/bin:$PATH"` в КАЖДОЙ bash-команде.
- QEMU 11.1: `"/c/Program Files/qemu/qemu-system-x86_64.exe"`.
- Сборка: `cd /c/OS/rudra && ./scripts/build.sh` (должно быть BUILD_EXIT=0, вывод не прятать в /dev/null). Тесты: `./scripts/test.sh` (isa-debug-exit, PASS = exit 33).
- **ВАЖНО: QEMU-зомби.** Перед/после каждого запуска: `taskkill //F //IM qemu-system-x86_64.exe`, проверять `tasklist | grep -c qemu`.
- Интерактив с ВМ: QEMU в background (`run_in_background=true`) с `-serial file:serial.log -m 256M -monitor tcp:127.0.0.1:<порт>,server,nowait -display none`, затем bash: `exec 3<>/dev/tcp/127.0.0.1/<порт>`, печатать команды посимвольно `printf 'sendkey %s\n' <key> >&3` (пробел=spc, /=slash, .=dot, >=shift-dot) с sleep 0.18-0.25, в конце `sendkey ret`. **Одно постоянное соединение на всю сессию** (при переподключениях sendkey ret теряется). Лог читать: `grep -a ... serial.log`.

## Что сделано в v0.6 (коммит 3799edc)

1. **fs.rs (RFS2)**: плоское хранилище полных путей, каталоги эмулируются синтетически (is_dir = префикс файлов), `resolve(cwd, path)` с "." / "..", read_at, 8MiB образ, NAME_LEN 64, pack_rfs.py ходит по rootfs рекурсивно.
2. **task.rs — полный рефакторинг**: `AddressSpace` (l4 + brk + mmap_next) в `Arc<Mutex<>>`, потоки делят АП; fork = глубокая копия L4[0] (`copy_user_space`); `load_elf_image` строит настоящий начальный стек Linux (argc/argv/envp/auxv с AT_PHDR/AT_RANDOM/AT_EXECFN...); `sys_execve` — новое АП + патч syscall-фрейма (возврата в старый код нет); планировщик восстанавливает FS BASE; `sys_brk`, `sys_mmap` (анонимный bump 0x50000000+), `alloc_thread_stack`. 32 слота задач.
3. **linux.rs (новый)**: ~60 syscall'ов Linux x86_64 (номера как в настоящем Linux): open/openat/read/write/close/lseek/dup2/fcntl, getdents64/stat/newfstatat/statx, brk/mmap/mprotect/munmap, clone/fork/execve/wait4/exit, pipe/pipe2/poll/select, nanosleep/clock_gettime, futex (WAIT=спин+hlt, WAKE=no-op), arch_prctl (FS BASE), set_tid_address/cleartid, uname/getrandom/sysinfo/prlimit64, ioctl (TCGETS/TIOCGWINSZ). Fd-таблица per-task (Arc<Mutex<Vec<Option<Fd>>>>): Console/File(с dirty-буфером, flush при close)/Dir/Pipe.
4. **syscall.rs**: Linux ABI (args rdi/rsi/rdx/r10/r8/r9), 6-м аргументом в диспетчер идёт указатель на сохранённый фрейм (`FRAME` — смещения в раскладке syscall_entry: RAX=11, RFLAGS=12, RIP=13, RSP=14).
5. **user-либа (user/src/lib.rs, крейт называется `rudra`, см. [lib] name)**: raw syscall6, readline, open/read/write/close, fork/execve/wait4/run_and_wait, mmap_anon, thread_spawn (через clone с CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_CHILD_CLEARTID; f/arg передаются в r12/r13!), Mutex на futex, thread_join (спин по cleartid). Без alloc — фиксированные буферы.
6. **Шелл (user/src/bin/shell.rs)**: билтины (help/ls/cat/echo/pwd/cd/rm/mkdir/ps/uname/clear/run/exit) + внешние команды: fork → execve как путь → /bin/<cmd> → /bin/<cmd>.elf → **busybox fallback** (execve /bin/busybox busybox <cmd> <args>).
7. **rootfs/bin/busybox** — настоящий static glibc busybox 1.37 из Debian (скачан с deb.debian.org). В build.rs добавлен бинарь `threads`.

## ЧТО РАБОТАЕТ (проверено в QEMU)

- Загрузка, шелл, readline, файловые билтины.
- **`run /bin/hello.elf` — ПОЛНОСТЬЮ РАБОТАЕТ**: fork → execve (новый АП, стек с auxv) → вывод «Hello from rudra userspace (ring 3)!» → wait4.

## ИЗВЕСТНЫЕ БАГИ (вот над ними работать)

1. **Форматирование чисел в user-программах**: `println!("pid = {}", getpid())` в hello — печатает «pid = » и умирает: `PAGE FAULT at 0x7, INSTRUCTION_FETCH, rip 0x7`. Первая println (строка без аргументов, fast-path `args.as_str()`) работает; с `{}` (путь через `W.write_fmt`) — прыжок на 0x7. Подозрения: (а) баг в моём `fmt_print`/`Write for W`; (б) core::fmt в no_std-таргете при делении u64 использует что-то, что ломается (код форматирования целых в core делит на 10 — проверь, нет ли проблем с отсутствующими intrinsics; таргет x86_64-unknown-none должен иметь compiler-builtins); (в) стек: fmt рекурсивен, окно стека... 256KB хватает. Смотри `user/src/lib.rs: fmt_print`. В v0.5 println! с числами РАБОТАЛ (там был свой itoa?) — сравни с коммитом da55227.
2. **`ls /` — PF at 0x58 USER_MODE в шелле** (task 1 погибает). Был до фикса фрейма, надо перепроверить — возможно уже иначе/исчез. Если нет: смотри `linux.rs sys_getdents64` и разбор записей в `shell.rs fn ls` (там `(p.add(16) as *const u16).read()` — unaligned, может валить? нет, PF на 0x58 = адрес-объект...). Логируй rip (уже логируется в kill-сообщении).
3. **threads.elf молчит** — вероятно тот же баг форматирования («spawning {} threads x {} iters» умирает молча? fault был бы виден в serial). Проверь после починки (1). Сам clone CLONE_VM не тестировался из-за этого.
4. **busybox не тестировался** — после починки (1) пробуй в шелле: `ls`, `cat /motd.txt`, `echo hi`, `wc -c /motd.txt`. Ожидаемые сюрпризы glibc-static: set_robust_list (есть→0), rseq (ENOSYS ✓), prlimit64 (✓), sched_getaffinity (✓ пишет маску=1), arch_prctl (✓), getrandom (✓). Может понадобиться: madvise, mprotect (есть→0), readlink, access, faccessat2 (439→ENOSYS, busybox ls может использовать faccessat2! если да — добавь 439 как access). Лог неизвестных: `SEEN_UNKNOWN` в linux.rs печатает номер один раз.
5. Мелочь: `sys_mmap` игнорирует addr даже с MAP_FIXED (условие написано криво — `if MAP_FIXED != 0 && ...` всегда истинно по первой части, но && (flags&MAP_FIXED) спасает; оставь или почини).
6. futex WAIT — spin+hlt (одноядерно ок); nanosleep гранулярность 55мс (PIT 18.2Hz, TICKS в timer_switch).

## КЛЮЧЕВЫЕ ГРАБЛИ (уже потрачено на них часы — не повторять)

- **Раскладка фрейма клонирования**: `syscall_entry` и `timer_entry` пушат/попают регистры в РАЗНОМ порядке! sys_clone строит стартовый фрейм ребёнка в раскладке timer_entry (см. комментарий и remap в `task.rs sys_clone`), rax=0 → ребёнок. Свежие задачи (spawn) не подвержены — их GPR-ы нули.
- **Стартовый фрейм на T-320, не T-160**: первое же аппаратное прерывание (CPU iret-фрейт + 15 пушей timer_entry) затирает верхние ~160 байт kernel-стека. `kernel_rsp = kstack_top - 2*(15+5)*8`.
- Оба фикса в `task.rs` (sys_clone и finish_task), без них fork давал ребёнка с rax=user-rsp → исполнял чужую ветку кода.
- r10 — Linux arg4 и одновременно syscall_entry кладёт туда user-rsp (`mov r10, rsp`); arg4 читается из r10-слота фрейма (=user-rsp!), arg5/arg6 — из r8/r9-слотов.

## Архитектура одним абзацем

Раскладка userspace (L4[0]): ELF 0x400000, main-стек растёт вниз от 0x40000000 (256KB), brk 0x10000000→0x50000000, mmap 0x50000000→0x60000000, стеки потоков 0x70000000 + i*1MB (см. константы в task.rs). Kernel-половина (индексы L4 1..512) копируется в каждое АП. Планировщик: round-robin по PIT в timer_switch (asm timer_entry сохраняет 15 регистров). Syscall через syscall/sysret, SFMask гасит IF, entry переключается на CURRENT_KSTACK (per-task kernel stack 64KB). User-бинарни: `-C relocation-model=static`, линковщик user/user.ld, ET_EXEC обязателен (PIE не грузим).

## Следующие шаги (приоритет)

1. Починить баг (1) форматирования — разблокирует threads.elf и busybox.
2. `ls /` и остальные билтины.
3. Полная сессия с busybox: ls/cat/echo/wc/true/yes + скриншот framebuffer (screendump через монитор: `screendump C:/OS/rudra/fb.png -f png`, читать ReadMediaFile).
4. Обновить README (v0.6), коммит, push.
5. Дальше: каталоги реальные (не синтетика), VirtIO-blk, SMP (APIC + startup IPI), мини-libc для user-программ (malloc через brk).

## Команды для быстрой проверки

```bash
cd /c/OS/rudra && export PATH="$HOME/.cargo/bin:$PATH"
taskkill //F //IM qemu-system-x86_64.exe
./scripts/build.sh && ./scripts/test.sh   # BUILD_EXIT=0, PASS
# интерактив: QEMU background с монитором, sendkey-набор команд, serial.log
```
