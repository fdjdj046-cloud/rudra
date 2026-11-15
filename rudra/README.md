
---

## v0.6 (WIP): Linux ABI + многопоточность + busybox

В разработке. Сделано: RFS2 (каталоги, 8MiB, длинные имена), адресные
пространства с refcount, fork/clone/execve/wait4, слой Linux syscall'ов
(файлы, brk/mmap, pipe, poll, futex-spin, stat), шелл на execve с
busybox-fallback, статический busybox в /bin/busybox, threads.elf.

Работает: `run /bin/hello.elf` (fork+execve+wait4, вывод в консоль).
Известные баги: (1) `println!("pid = {}", getpid())` — user fault rip=0x7
после первой строки hello (вторая println с форматированием числа);
(2) `ls /` — PF at 0x58 в шелле; (3) threads.elf молчит (вероятно тот же
баг форматирования). Диагностические логи: [clone] child frame, [execve].
Ключевой фикс этого релиза: remap регистров syscall_entry→timer_entry
в sys_clone (раскладки push/pop разные!) + стартовый фрейм на T-320
(верхние 160 байт kernel-стека затирает первое прерывание).
