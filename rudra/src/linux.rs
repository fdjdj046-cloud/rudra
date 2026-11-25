//! Слой совместимости с Linux ABI: запуск статических Linux-бинарников
//! (glibc/musl) без перекомпиляции.
//!
//! Реализовано подмножество syscall'ов x86_64: файловый ввод-вывод поверх
//! ext2 (если смонтирован) или RFS2 (open/openat/read/write/close/lseek/
//! dup2/fcntl), каталоги (getdents64/stat/newfstatat/statx/mkdir/rmdir/
//! unlink/rename/chdir/getcwd), память (brk/mmap, munmap отдаёт кадры, mprotect меняет PTE), процессы
//! (clone/fork/execve/wait4/exit) и pthreads (clone с CLONE_VM, futex,
//! arch_prctl, set_tid_address/robust_list), pipe/pipe2, poll, время,
//! uname, reboot, getrandom и мелочь.
//!
//! UDP/`AF_INET` и TCP есть (петля и провод). IPv6 — петля `::1` и
//! link-local `fe80::/10` с NDP (`AF_INET6`). Глобальный адрес —
//! `ENETUNREACH`. Netlink нет.
//! Сигналы 1–31 доставляются на возврате из syscall и с тика в ring 3, если
//! задан `SA_RESTORER`. Смерть по сигналу — `WIFSIGNALED`. Блокирующий сон,
//! futex, pipe, poll и recvfrom возвращают `EINTR`. Чтение консоли — нет.
//! Задача стартует как root (uid/gid 0). `setuid`/`setgid` меняют id.
//! `seccomp` strict режет всё, кроме read, write, rt_sigreturn и exit.
//! Номер 1024 — резолвер ленивого PLT: он идёт до фильтра и пишет только
//! уже посчитанный адрес в известный слот GOT.
//! epoll — level и edge по номеру fd. poll и select видят готовый epoll-fd.
//! `FD_CLOEXEC` хранится на номере: `O_CLOEXEC`, `SOCK_CLOEXEC`, `EPOLL_CLOEXEC`,
//! `pipe2` и `fcntl(F_SETFD)`. `execve` такие номера закрывает.
//! `accept` (43) отдаёт блокирующий сокет без этого бита. `accept4` (288)
//! принимает только `SOCK_NONBLOCK` и `SOCK_CLOEXEC`; другой бит — `EINVAL`
//! до поиска fd.
//! `dup3` (292) — это `dup2` плюс флаг: только `O_CLOEXEC`, иначе `EINVAL`
//! до поиска fd. `old == new` у `dup3` — `EINVAL`. Вытесненный номер
//! закрывается как `close`, включая сброс буфера файла.
//! Файловый mmap возвращает ENODEV. Анонимный пишет те же биты, что `mprotect`.
//! `munmap` отдаёт кадр после сброса TLB.
//! `mprotect` пишет present/user/writable и не ставит NX. `madvise` кадр не отдаёт.
//! `futex WAIT/WAKE` будит ждущих.
//! `sched_setaffinity` хранит маску целиком. x2APIC есть.
//! `link` копирует байты, `symlink` пишет цель как содержимое файла.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::syscall::FRAME;
use crate::task;

// ---- errno (возврат как -errno) ----

macro_rules! errno {
    ($($name:ident = $val:expr),* $(,)?) => {$(
        pub const $name: u64 = (-($val as i64)) as u64;
    )*};
}
errno! {
    EPERM = 1, ENOENT = 2, ESRCH = 3, EINTR = 4, EIO = 5, ENOMEM = 12, EFAULT = 14,
    EBUSY = 16, EEXIST = 17, ENODEV = 19, ENOTDIR = 20, EISDIR = 21,
    EINVAL = 22, ENFILE = 23, EMFILE = 24, ENOTTY = 25, EFBIG = 27,
    ENOSPC = 28, ESPIPE = 29, EROFS = 30, EMLINK = 31, EPIPE = 32,
    ERANGE = 34, ENOSYS = 38, ENOTEMPTY = 39, ELOOP = 40, EWOULDBLOCK = 11,
    E2BIG = 7, ENOEXEC = 8, EAGAIN = 11, EDESTADDRREQ = 89, EMSGSIZE = 90,
    ENOPROTOOPT = 92, EPROTONOSUPPORT = 93, EAFNOSUPPORT = 97, EADDRINUSE = 98,
    EADDRNOTAVAIL = 99, ENETDOWN = 100,
}

/// Больше этого за один read/write не копируем: иначе длина из syscall
/// заставляет ядро выделить гигантский буфер.
const MAX_IO: usize = 8 * 1024 * 1024;

fn u_read(addr: u64, buf: &mut [u8]) -> bool {
    task::user_read(addr, buf)
}

fn u_write(addr: u64, buf: &[u8]) -> bool {
    task::user_write(addr, buf)
}

fn copy_from_user(addr: u64, len: usize) -> Option<Vec<u8>> {
    if len > MAX_IO {
        return None;
    }
    let mut buf = Vec::new();
    if buf.try_reserve_exact(len).is_err() {
        return None;
    }
    buf.resize(len, 0);
    if !u_read(addr, &mut buf) {
        return None;
    }
    Some(buf)
}

// ---- Дескрипторы файлов ----

/// Дескриптор открытого файла задачи.
#[derive(Clone)]
pub enum Fd {
    /// Консоль: fd 0 — клавиатура (блокирующий read), fd 1/2 — вывод.
    Console { writable: bool },
    /// Файл RFS2. Запись буферизуется в `dirty` и сбрасывается при close
    /// (create-or-replace целиком). accmode: 0 = RDONLY, 1 = WRONLY, 2 = RDWR.
    File {
        name: String,
        offset: u64,
        accmode: u8,
        append: bool,
        dirty: Option<Vec<u8>>,
    },
    /// Каталог (синтетический): читается через getdents64.
    Dir { prefix: String, idx: usize },
    /// Канал pipe.
    Pipe { id: usize, writable: bool },
    /// UDP-сокет `AF_INET`. `id` — слот в `net`.
    Udp { id: usize },
    /// TCP на петле `127.0.0.0/8`. Проводного TCP нет.
    Tcp { id: usize },
    /// UDP `AF_INET6`. `id` — слот в `net6`. Только петля `::1`.
    Udp6 { id: usize },
    /// TCP `AF_INET6`. `id` — слот в `net6`. Только петля `::1`.
    Tcp6 { id: usize },
    /// Набор epoll. `id` — слот в `EPOLLS`. Интерес хранит номер fd, не описание.
    Epoll { id: usize },
}

impl Fd {
    pub fn console(writable: bool) -> Fd {
        Fd::Console { writable }
    }

    /// Копия для fork (pipe-канал: +1 ссылка на конец).
    pub fn clone_fd(&self) -> Fd {
        match self {
            Fd::Pipe { id, writable } => {
                pipe_chan_add_ref(*id, *writable);
                Fd::Pipe { id: *id, writable: *writable }
            }
            Fd::Udp { id } => {
                crate::net::udp_addref(*id);
                Fd::Udp { id: *id }
            }
            Fd::Tcp { id } => {
                crate::net::tcp_addref(*id);
                Fd::Tcp { id: *id }
            }
            Fd::Udp6 { id } => {
                crate::net6::udp_addref(*id);
                Fd::Udp6 { id: *id }
            }
            Fd::Tcp6 { id } => {
                crate::net6::tcp_addref(*id);
                Fd::Tcp6 { id: *id }
            }
            Fd::Epoll { id } => {
                epoll_addref(*id);
                Fd::Epoll { id: *id }
            }
            other => other.clone(),
        }
    }
}

/// Таблица дескрипторов одной задачи, не больше 64 номеров.
/// Бит `cloexec` — `FD_CLOEXEC` этого номера.
pub struct Fds {
    v: Vec<Option<Fd>>,
    cloexec: u64,
}

impl Fds {
    pub fn new(v: Vec<Option<Fd>>) -> Self {
        Self { v, cloexec: 0 }
    }

    /// Fork без `CLONE_FILES`. Биты копируются. pipe, сокет и epoll
    /// получают ещё одну ссылку, как `clone_fd`.
    pub fn clone_for_fork(&self) -> Self {
        Self {
            v: self
                .v
                .iter()
                .map(|f| f.as_ref().map(|f| f.clone_fd()))
                .collect(),
            cloexec: self.cloexec,
        }
    }

    pub fn set_cloexec(&mut self, fd: u64, on: bool) {
        if fd >= 64 {
            return;
        }
        let bit = 1u64 << (fd as u32);
        if on {
            self.cloexec |= bit;
        } else {
            self.cloexec &= !bit;
        }
    }

    pub fn is_cloexec(&self, fd: u64) -> bool {
        fd < 64 && self.cloexec & (1u64 << (fd as u32)) != 0
    }

    pub fn cloexec_bits(&self) -> u64 {
        self.cloexec
    }
}

impl Deref for Fds {
    type Target = Vec<Option<Fd>>;
    fn deref(&self) -> &Self::Target {
        &self.v
    }
}

impl DerefMut for Fds {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.v
    }
}

fn alloc_fd(slot: &mut Option<Fd>, fds: &mut Fds, cloexec: bool) -> u64 {
    if let Some(i) = fds.iter().position(|f| f.is_none()) {
        fds[i] = slot.take();
        fds.set_cloexec(i as u64, cloexec);
        return i as u64;
    }
    if fds.len() >= 64 {
        return EMFILE;
    }
    fds.push(slot.take());
    let i = (fds.len() - 1) as u64;
    fds.set_cloexec(i, cloexec);
    i
}

fn with_current_fds<R>(f: impl FnOnce(&mut Fds) -> R) -> Result<R, u64> {
    let fds = task::with_current_task(|t| t.fds.clone())
        .ok_or(EPERM)?;
    let mut guard = fds.lock();
    Ok(f(&mut guard))
}

/// Выполнить операцию с дескриптором (под локом таблицы fd).
fn with_fd<R>(fd: u64, f: impl FnOnce(&mut Fd) -> R) -> Result<R, u64> {
    with_current_fds(|fds| match fds.get_mut(fd as usize).and_then(|x| x.as_mut()) {
        Some(fdo) => Ok(f(fdo)),
        None => Err(EBADF),
    })?
}

const EBADF: u64 = (-(9i64)) as u64;

// ---- Pipes ----

const PIPE_CAP: usize = 64 * 1024;

struct PipeChan {
    ring: Box<[u8; PIPE_CAP]>,
    head: usize,
    len: usize,
    readers: usize,
    writers: usize,
}

static PIPES: Mutex<Vec<Option<PipeChan>>> = Mutex::new(Vec::new());

fn pipe_chan_add_ref(id: usize, writable: bool) {
    let mut pipes = PIPES.lock();
    if let Some(Some(p)) = pipes.get_mut(id) {
        if writable {
            p.writers += 1;
        } else {
            p.readers += 1;
        }
    }
}

fn new_pipe(cloexec: bool) -> (u64, u64) {
    let mut pipes = PIPES.lock();
    let chan = PipeChan {
        ring: Box::new([0u8; PIPE_CAP]),
        head: 0,
        len: 0,
        readers: 1,
        writers: 1,
    };
    let id = pipes.len();
    pipes.push(Some(chan));
    let r = with_current_fds(|fds| {
        let mut r = Some(Fd::Pipe { id, writable: false });
        let rfd = alloc_fd(&mut r, fds, cloexec);
        let mut w = Some(Fd::Pipe { id, writable: true });
        let wfd = alloc_fd(&mut w, fds, cloexec);
        (rfd, wfd)
    });
    match r {
        Ok(pair) => pair,
        Err(_) => (EMFILE, EMFILE),
    }
}

fn pipe_read(id: usize, buf: &mut [u8]) -> u64 {
    loop {
        let (n, writers) = {
            let mut pipes = PIPES.lock();
            match pipes.get_mut(id).and_then(|p| p.as_mut()) {
                Some(p) if p.len > 0 => {
                    let n = p.len.min(buf.len());
                    for i in 0..n {
                        buf[i] = p.ring[p.head];
                        p.head = (p.head + 1) % PIPE_CAP;
                    }
                    p.len -= n;
                    (n, p.writers)
                }
                Some(p) => (0, p.writers),
                None => return EPIPE,
            }
        };
        if n > 0 {
            return n as u64;
        }
        if writers == 0 {
            return 0; // EOF
        }
        if crate::signal::pending_interrupts() && !crate::signal::keep_waiting() {
            return EINTR;
        }
        x86_64::instructions::hlt(); // ждём писателя (таймер разбудит)
    }
}

fn pipe_write(id: usize, buf: &[u8]) -> u64 {
    let mut done = 0;
    while done < buf.len() {
        let (space, readers) = {
            let mut pipes = PIPES.lock();
            match pipes.get_mut(id).and_then(|p| p.as_mut()) {
                Some(p) => (PIPE_CAP - p.len, p.readers),
                None => return EPIPE,
            }
        };
        if readers == 0 {
            return EPIPE;
        }
        if space == 0 {
            if crate::signal::pending_interrupts() && !crate::signal::keep_waiting() {
                return if done == 0 { EINTR } else { done as u64 };
            }
            x86_64::instructions::hlt();
            continue;
        }
        let mut pipes = PIPES.lock();
        if let Some(Some(p)) = pipes.get_mut(id) {
            let n = space.min(buf.len() - done);
            for i in 0..n {
                let pos = (p.head + p.len) % PIPE_CAP;
                p.ring[pos] = buf[done + i];
                p.len += 1;
            }
            done += n;
        }
    }
    done as u64
}

fn pipe_close_end(id: usize, writable: bool) {
    let mut pipes = PIPES.lock();
    let free = match pipes.get_mut(id).and_then(|p| p.as_mut()) {
        Some(p) => {
            if writable {
                p.writers = p.writers.saturating_sub(1);
            } else {
                p.readers = p.readers.saturating_sub(1);
            }
            p.readers == 0 && p.writers == 0
        }
        None => false,
    };
    if free {
        pipes[id] = None;
    }
}

// ---- Ввод-вывод ----

fn console_write(bytes: &[u8]) -> u64 {
    // Serial получает байты как есть (UTF-8 текст рендерится терминалом),
    // на экран — только печатные ASCII и '\n'.
    for &b in bytes {
        use x86_64::instructions::port::Port;
        unsafe { Port::<u8>::new(0x3F8).write(b) };
        if b == b'\n' || (0x20..=0x7e).contains(&b) {
            crate::framebuffer::_print_screen(core::format_args!("{}", b as char));
        }
    }
    bytes.len() as u64
}

/// Блокирующее чтение одного байта из очереди клавиатуры.
/// IF включён (мы после sti в entry): таймер вытесняет задачу,
/// клавиатура пополняет очередь.
fn console_read_byte() -> u8 {
    loop {
        // Лок только на pop: спин с занятой очередью не дал бы IRQ клавиатуры
        // положить байт, если бы IF оставался включён внутри лока.
        if let Some(b) = crate::input::with_input(|q| q.pop()) {
            return b;
        }
        core::hint::spin_loop();
    }
}

// ---- Пути ----

fn task_resolve(path: &str) -> Option<String> {
    crate::fs::resolve(&task::current_cwd(), path)
}

fn fs_err(e: crate::fs::FsError) -> u64 {
    use crate::fs::FsError::*;
    match e {
        NoEnt => ENOENT,
        Exist => EEXIST,
        NotDir => ENOTDIR,
        IsDir => EISDIR,
        NotEmpty => ENOTEMPTY,
        NoSpc => ENOSPC,
        Inval => EINVAL,
        Perm => EPERM,
        Io => EIO,
        RoFs => EROFS,
    }
}

// ---- stat ----

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFCHR: u32 = 0o020000;
const S_IFLNK: u32 = 0o120000;

fn fake_ino(name: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in name.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h >> 16 | 1
}

/// struct stat x86_64 (144 байта) в user-буфер. `false` — битый указатель.
fn write_stat(buf: u64, size: u64, mode: u32, nlink: u64, uid: u32, gid: u32) -> bool {
    if buf == 0 {
        return false;
    }
    let now = (crate::interrupts::uptime_ms() / 1000) as u64;
    let mut st = [0u8; 144];
    st[0..8].copy_from_slice(&8u64.to_le_bytes());
    st[8..16].copy_from_slice(&fake_ino("stat").to_le_bytes());
    st[16..24].copy_from_slice(&nlink.to_le_bytes());
    st[24..28].copy_from_slice(&mode.to_le_bytes());
    st[28..32].copy_from_slice(&uid.to_le_bytes());
    st[32..36].copy_from_slice(&gid.to_le_bytes());
    st[48..56].copy_from_slice(&size.to_le_bytes());
    st[56..64].copy_from_slice(&4096u64.to_le_bytes());
    st[64..72].copy_from_slice(&((size + 511) / 512).to_le_bytes());
    for off in [72, 88, 104] {
        st[off..off + 8].copy_from_slice(&now.to_le_bytes());
    }
    u_write(buf, &st)
}

/// (size, mode, nlink, uid, gid). Владелец — из inode ext2, у остальных root.
fn stat_of(path: &str) -> Option<(u64, u32, u64, u32, u32)> {
    let mode = crate::fs::mode_of(path)?;
    let (uid, gid) = crate::fs::owner_of(path).unwrap_or((0, 0));
    if crate::fs::is_dir(path) {
        Some((0, mode, crate::fs::nlink_of(path).max(2), uid, gid))
    } else if crate::fs::exists(path) {
        let sz = crate::fs::size_of(path).max(0) as u64;
        Some((sz, mode, crate::fs::nlink_of(path).max(1), uid, gid))
    } else {
        None
    }
}

/// Консоль stat: char device, владелец — текущая задача.
fn write_console_stat(buf: u64) {
    let _ = write_stat(
        buf,
        0,
        S_IFCHR | 0o620,
        1,
        task::cred_euid() as u32,
        task::cred_egid() as u32,
    );
}

// ---- Диспетчер ----

static SEEN_UNKNOWN: Mutex<[u64; 16]> = Mutex::new([u64::MAX; 16]);

/// Главный диспетчер Linux syscall'ов. Аргументы 5 и 6 читаются из фрейма.
#[no_mangle]
pub fn dispatch(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, frame: *mut u64) -> u64 {
    let a5 = unsafe { *frame.add(FRAME::R8) };
    let a6 = unsafe { *frame.add(FRAME::R9) };
    // До фильтра: иначе строгий seccomp убивает процесс на первом PLT-вызове.
    if nr == task::DL_FIXUP_NR {
        return task::sys_dl_fixup(a1, a2);
    }
    if task::seccomp_kills(nr) {
        // Не ENOSYS: процесс умирает, запрещённый вызов не выполняется.
        task::sys_exit(128 + 9);
    }
    // rseq: syscall из критической секции обрывает её (rip → abort handler).
    task::rseq_syscall_abort(frame);
    match nr {
        0 => sys_read(a1, a2, a3),
        1 => sys_write(a1, a2, a3),
        2 => sys_openat(AT_FDCWD, a1, a2, a3), // open(path, flags, mode)
        3 => sys_close(a1),
        4 | 6 => {
            // stat / lstat (симлинки не различаем — лежат как файлы)
            let Some(path) = task::copy_user_cstr(a1, 256) else { return EFAULT };
            let Some(canon) = task_resolve(&path) else { return ENAMETOOLONG };
            match stat_of(&canon) {
                Some((sz, mode, nlink, uid, gid)) => {
                    if !write_stat(a2, sz, mode, nlink, uid, gid) {
                        return EFAULT;
                    }
                    0
                }
                None => ENOENT,
            }
        }
        5 => sys_fstat(a1, a2),
        7 => sys_poll(a1, a2, a3),
        213 => {
            // epoll_create(size): аргумент — int. Ноль и минус — EINVAL.
            if (a1 as i32) <= 0 {
                EINVAL
            } else {
                sys_epoll_create(0)
            }
        }
        232 => sys_epoll_wait(a1, a2, a3, a4),
        233 => sys_epoll_ctl(a1, a2, a3, a4),
        // epoll_pwait: как epoll_wait, но с временной маской сигналов.
        281 => sys_epoll_pwait(a1, a2, a3, a4, a5, a6),
        291 => sys_epoll_create(a1),
        8 => sys_lseek(a1, a2 as i64, a3),
        9 => task::sys_mmap(a1, a2, a3, a4, a5, a6),
        10 => task::sys_mprotect(a1, a2, a3),
        11 => task::sys_munmap(a1, a2),
        12 => task::sys_brk(a1),
        13 => crate::signal::sys_rt_sigaction(a1, a2, a3, a4),
        14 => crate::signal::sys_rt_sigprocmask(a1, a2, a3, a4),
        15 => crate::signal::sys_rt_sigreturn(frame),
        16 => sys_ioctl(a1, a2, a3),
        // pread64/pwrite64: смещение целиком в r10 (arg4). r8 — это arg5, не позиция.
        17 => sys_pread(a1, a2, a3, a4),
        18 => sys_pwrite(a1, a2, a3, a4),
        19 => sys_rwv(a1, a2, a3, false),
        20 => sys_rwv(a1, a2, a3, true),
        21 | 439 => {
            // access / faccessat2
            let Some(path) = task::copy_user_cstr(a1, 256) else { return EFAULT };
            let Some(canon) = task_resolve(&path) else { return ENAMETOOLONG };
            match stat_of(&canon) {
                Some(_) => 0,
                None => ENOENT,
            }
        }
        22 => sys_pipe(a1, 0),
        293 => sys_pipe(a1, a2),
        23 => sys_select(a1, a2, a3, a4, a5),
        24 => 0, // sched_yield: PIT и так вытесняет
        28 => 0, // madvise: страницы не отдаются
        32 => sys_dup(a1),
        33 => sys_dup2(a1, a2),
        292 => sys_dup3(a1, a2, a3),
        35 => sleep_timespec(a1, a2, false),
        230 => {
            // clock_nanosleep(clockid, flags, req, rem). TIMER_ABSTIME = 1.
            // Часы пока одни: монотонный TSC. При EINTR в rem пишется остаток.
            sleep_timespec(a3, a4, a2 & 1 != 0)
        }
        39 => task::current_tid(),
        41 => sys_socket(a1, a2, a3),
        42 => sys_connect(a1, a2, a3),
        43 => sys_accept(a1, a2, a3, 0),
        288 => sys_accept(a1, a2, a3, a4),
        44 => sys_sendto(a1, a2, a3, a4, a5, a6),
        45 => sys_recvfrom(a1, a2, a3, a4, a5, a6),
        49 => sys_bind(a1, a2, a3),
        50 => sys_listen(a1, a2),
        51 => sys_getsockname(a1, a2, a3),
        52 => sys_getpeername(a1, a2, a3),
        54 => sys_setsockopt(a1, a2, a3, a4, a5),
        55 => sys_getsockopt(a1, a2, a3, a4, a5),
        102 => task::cred_ruid(),
        104 => task::cred_rgid(),
        107 => task::cred_euid(),
        108 => task::cred_egid(),
        105 => task::cred_setuid(a1 as u32),
        106 => task::cred_setgid(a1 as u32),
        157 => task::sys_prctl(a1, a2),
        317 => task::sys_seccomp(a1, a2),
        56 => task::sys_clone(a1, a2, a3, a4, a5, frame),
        57 | 58 => {
            // fork / vfork: clone без флагов
            task::sys_clone(0, 0, 0, 0, 0, frame)
        }
        59 => task::sys_execve(a1, a2, a3, frame),
        60 | 231 => {
            // exit / exit_group
            let _ = task::sys_exit(a1);
        }
        61 => sys_wait4(a1, a2, a3),
        62 => crate::signal::sys_kill(a1, a2),
        // sigqueue: rt 34–64 кладёт значение в siginfo; 1–31 как kill.
        109 => crate::signal::sys_sigqueue(a1, a2, a3),
        63 => sys_uname(a1),
        169 => sys_reboot(a1, a2, a3),
        72 => sys_fcntl(a1, a2, a3),
        73 | 74 | 75 => 0, // flock / fsync / fdatasync
        76 => {
            // truncate
            let Some(path) = task::copy_user_cstr(a1, 256) else { return EFAULT };
            let Some(canon) = task_resolve(&path) else { return ENAMETOOLONG };
            if a2 == 0 {
                if let Err(e) = crate::fs::write_canon(&canon, &[]) {
                    return fs_err(e);
                }
            }
            0
        }
        77 => {
            // ftruncate
            match fd_name(a1) {
                Some(name) => {
                    if a2 == 0 {
                        if let Err(e) = crate::fs::write_canon(&name, &[]) {
                            return fs_err(e);
                        }
                    }
                    0
                }
                None => EBADF,
            }
        }
        78 | 217 => sys_getdents64(a1, a2, a3),
        79 => {
            // getcwd
            let cwd = task::current_cwd();
            let bytes = cwd.as_bytes();
            if a2 < bytes.len() as u64 + 1 {
                return ERANGE;
            }
            let mut tmp = alloc::vec![0u8; bytes.len() + 1];
            tmp[..bytes.len()].copy_from_slice(bytes);
            if !u_write(a1, &tmp) {
                return EFAULT;
            }
            (bytes.len() + 1) as u64
        }
        80 => {
            // chdir
            let Some(path) = task::copy_user_cstr(a1, 256) else { return EFAULT };
            let Some(canon) = task_resolve(&path) else { return ENAMETOOLONG };
            if crate::fs::is_dir(&canon) {
                task::set_cwd(canon);
                0
            } else if stat_of(&canon).is_some() {
                ENOTDIR
            } else {
                ENOENT
            }
        }
        82 => {
            // rename
            let Some(old) = task::copy_user_cstr(a1, 256) else { return EFAULT };
            let Some(new) = task::copy_user_cstr(a2, 256) else { return EFAULT };
            let (Some(o), Some(n)) = (task_resolve(&old), task_resolve(&new)) else {
                return ENAMETOOLONG;
            };
            match crate::fs::rename(&o, &n) {
                Ok(()) => 0,
                Err(e) => fs_err(e),
            }
        }
        83 => {
            // mkdir
            let Some(path) = task::copy_user_cstr(a1, 256) else { return EFAULT };
            let Some(canon) = task_resolve(&path) else { return ENAMETOOLONG };
            let perm = ((a2 as u32) & 0o777) & !task::current_umask();
            match crate::fs::mkdir_mode(&canon, perm as u16) {
                Ok(()) => 0,
                Err(e) => fs_err(e),
            }
        }
        84 => {
            // rmdir
            let Some(path) = task::copy_user_cstr(a1, 256) else { return EFAULT };
            let Some(canon) = task_resolve(&path) else { return ENAMETOOLONG };
            match crate::fs::rmdir(&canon) {
                Ok(()) => 0,
                Err(e) => fs_err(e),
            }
        }
        85 => {
            // creat(path, mode) = open(WRONLY|CREAT|TRUNC)
            sys_openat(AT_FDCWD, a1, 0x1 | 0x40 | 0x200, a2)
        }
        86 => {
            // link: копия содержимого
            let Some(old) = task::copy_user_cstr(a1, 256) else { return EFAULT };
            let Some(new) = task::copy_user_cstr(a2, 256) else { return EFAULT };
            let (Some(o), Some(n)) = (task_resolve(&old), task_resolve(&new)) else {
                return ENAMETOOLONG;
            };
            if crate::fs::is_dir(&o) {
                return EPERM;
            }
            match crate::fs::read_canon(&o) {
                Some(data) => match crate::fs::write_canon(&n, &data) {
                    Ok(_) => {
                        if let Some(m) = crate::fs::mode_of(&o) {
                            let _ = crate::fs::chmod(&n, (m as u16) & 0o7777);
                        }
                        0
                    }
                    Err(e) => fs_err(e),
                },
                None => ENOENT,
            }
        }
        87 => {
            // unlink
            let Some(path) = task::copy_user_cstr(a1, 256) else { return EFAULT };
            let Some(canon) = task_resolve(&path) else { return ENAMETOOLONG };
            match crate::fs::unlink(&canon) {
                Ok(()) => 0,
                Err(e) => fs_err(e),
            }
        }
        88 => {
            // symlink(target, linkpath): цель хранится как контент
            let Some(target) = task::copy_user_cstr(a1, 256) else { return EFAULT };
            let Some(path) = task::copy_user_cstr(a2, 256) else { return EFAULT };
            let Some(canon) = task_resolve(&path) else { return ENAMETOOLONG };
            match crate::fs::write_canon(&canon, target.as_bytes()) {
                Ok(_) => 0,
                Err(e) => fs_err(e),
            }
        }
        89 => {
            // readlink: читаем контент
            let Some(path) = task::copy_user_cstr(a1, 256) else { return EFAULT };
            let Some(canon) = task_resolve(&path) else { return ENAMETOOLONG };
            match crate::fs::read_canon(&canon) {
                Some(data) => {
                    let n = data.len().min(a3 as usize);
                    if n > 0 && !u_write(a2, &data[..n]) {
                        return EFAULT;
                    }
                    n as u64
                }
                None => EINVAL,
            }
        }
        90 => sys_chmod(a1, a2),
        91 => sys_fchmod(a1, a2),
        95 => {
            // umask
            task::swap_umask(a1 as u32) as u64
        }
        96 => {
            // gettimeofday. NULL tv — успех без записи.
            if a1 == 0 {
                return 0;
            }
            let ms = crate::interrupts::uptime_ms();
            let mut raw = [0u8; 16];
            raw[0..8].copy_from_slice(&(ms / 1000).to_le_bytes());
            raw[8..16].copy_from_slice(&(((ms % 1000) * 1_000_000).to_le_bytes()));
            if !u_write(a1, &raw) {
                return EFAULT;
            }
            0
        }
        97 | 302 => {
            // getrlimit / prlimit64: всё безлимитно
            let mut raw = [0u8; 16];
            raw[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
            raw[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
            if nr == 97 && a2 != 0 && !u_write(a2, &raw) {
                return EFAULT;
            }
            if nr == 302 && a4 != 0 && !u_write(a4, &raw) {
                return EFAULT;
            }
            0
        }
        99 => {
            // sysinfo
            if a1 != 0 {
                let mut buf = [0u8; 112];
                let up = (crate::interrupts::uptime_ms() / 1000).to_le_bytes();
                buf[0..8].copy_from_slice(&up);
                buf[32..40].copy_from_slice(&(64u64 << 20).to_le_bytes()); // totalram
                buf[80..82].copy_from_slice(&1u16.to_le_bytes()); // procs
                buf[104..108].copy_from_slice(&1u32.to_le_bytes()); // mem_unit
                if !u_write(a1, &buf) {
                    return EFAULT;
                }
            }
            0
        }
        100 => crate::interrupts::TICKS.load(Ordering::Relaxed) as u64, // times
        110 => task::current_ppid(),
        158 => task::sys_arch_prctl(a1, a2),
        186 => task::current_tid(), // gettid
        202 => sys_futex(a1, a2, a3, a4, a5, a6),
        203 => task::sys_sched_setaffinity(a1, a2, a3),
        204 => task::sys_sched_getaffinity(a1, a2, a3),
        309 => task::sys_getcpu(a1, a2),
        218 => {
            // set_tid_address
            task::with_current_task(|t| t.clear_tid = a1);
            task::current_tid()
        }
        228 => {
            // CLOCK_REALTIME (0) — UTC с RTC. Остальные id, которые мы принимаем, — TSC.
            let ns = if a1 == 0 {
                crate::time::realtime_ns()
            } else {
                crate::time::monotonic_ns()
            };
            let mut raw = [0u8; 16];
            raw[0..8].copy_from_slice(&(ns / 1_000_000_000).to_le_bytes());
            raw[8..16].copy_from_slice(&(ns % 1_000_000_000).to_le_bytes());
            if !u_write(a2, &raw) {
                return EFAULT;
            }
            0
        }
        257 => sys_openat(a1, a2, a3, a4),
        262 => sys_newfstatat(a1, a2, a3, a4),
        273 | 274 => 0, // set/get_robust_list
        318 => {
            // getrandom: xorshift от RDTSC (не криптостойко, для pointer guard хватает)
            if a1 == 0 || a2 == 0 {
                return EINVAL;
            }
            if a2 as usize > MAX_IO {
                return EFAULT;
            }
            let mut s = unsafe { core::arch::x86_64::_rdtsc() } | 1;
            let mut done = 0usize;
            let total = a2 as usize;
            while done < total {
                let n = (total - done).min(256);
                let mut tmp = [0u8; 256];
                for b in tmp.iter_mut().take(n) {
                    s ^= s << 13;
                    s ^= s >> 7;
                    s ^= s << 17;
                    *b = s as u8;
                }
                if !u_write(a1 + done as u64, &tmp[..n]) {
                    return EFAULT;
                }
                done += n;
            }
            a2
        }
        324 => 0, // membarrier
        332 => sys_statx(a1, a2, a3, a4, a5),
        334 => task::sys_rseq(a1, a2, a3, a4),
        1000 => {
            // rudra-specific: дамп задач в serial+экран (команда ps).
            task::debug_dump();
            0
        }
        1001 => {
            // rudra-specific: поднять IPv4 по DHCP (сеть поднята ли — проверяется).
            // Для тестов и ручного bring-up; сама загрузка DHCP не запрашивает.
            match crate::net::dhcp() {
                Ok(ip) => u64::from(ip),
                Err(_) => u64::MAX,
            }
        }
        _ => {
            // Неизвестный syscall: логируем один раз на номер, ENOSYS.
            let mut seen = SEEN_UNKNOWN.lock();
            if !seen.contains(&nr) {
                let slot = seen.iter().position(|&x| x == u64::MAX).unwrap_or(0);
                seen[slot] = nr;
                crate::serial_println!(
                    "[linux] unknown syscall {} args {:#x},{:#x},{:#x},{:#x}",
                    nr, a1, a2, a3, a4
                );
            }
            ENOSYS
        }
    }
}

const ENAMETOOLONG: u64 = (-(36i64)) as u64;
const AT_FDCWD: u64 = (-100i64) as u64;

fn sleep_timespec(ptr: u64, rem: u64, absolute: bool) -> u64 {
    let mut raw = [0u8; 16];
    if !u_read(ptr, &mut raw) {
        return EFAULT;
    }
    let sec = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let nsec = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    if nsec >= 1_000_000_000 {
        return EINVAL;
    }
    let span = sec.saturating_mul(1_000_000_000).saturating_add(nsec);
    let deadline = if absolute {
        span
    } else {
        crate::time::monotonic_ns().saturating_add(span)
    };
    while crate::time::monotonic_ns() < deadline {
        if crate::signal::pending_interrupts() {
            return sleep_interrupted(deadline, rem);
        }
        let left = deadline - crate::time::monotonic_ns();
        // Короткий хвост докручиваем по TSC, не дожидаясь тика планировщика.
        if left > 2_000_000 && x86_64::instructions::interrupts::are_enabled() {
            x86_64::instructions::hlt();
        } else {
            core::hint::spin_loop();
        }
    }
    0
}

fn sleep_interrupted(deadline: u64, rem: u64) -> u64 {
    let now = crate::time::monotonic_ns();
    let left = deadline.saturating_sub(now);
    if rem != 0 {
        let sec = left / 1_000_000_000;
        let nsec = left % 1_000_000_000;
        let mut raw = [0u8; 16];
        raw[0..8].copy_from_slice(&sec.to_le_bytes());
        raw[8..16].copy_from_slice(&nsec.to_le_bytes());
        if !u_write(rem, &raw) {
            return EFAULT;
        }
    }
    EINTR
}

fn neg_err(e: i32) -> u64 {
    (-(e as i64)) as u64
}

fn udp_id(fd: u64) -> Result<usize, u64> {
    match sock_kind(fd)? {
        SockKind::Udp(id) => Ok(id),
        SockKind::Tcp(_) | SockKind::Udp6(_) | SockKind::Tcp6(_) => Err(ENOTSOCK),
    }
}

#[derive(Clone, Copy)]
enum SockKind {
    Udp(usize),
    Tcp(usize),
    Udp6(usize),
    Tcp6(usize),
}

fn sock_kind(fd: u64) -> Result<SockKind, u64> {
    match with_fd(fd, |f| match f {
        Fd::Udp { id } => Ok(SockKind::Udp(*id)),
        Fd::Tcp { id } => Ok(SockKind::Tcp(*id)),
        Fd::Udp6 { id } => Ok(SockKind::Udp6(*id)),
        Fd::Tcp6 { id } => Ok(SockKind::Tcp6(*id)),
        _ => Err(ENOTSOCK),
    }) {
        Ok(inner) => inner,
        Err(e) => Err(e),
    }
}

const ENOTSOCK: u64 = (-(88i64)) as u64;
const EOPNOTSUPP: u64 = (-(95i64)) as u64;

fn read_sockaddr_in(ptr: u64, len: u64) -> Result<(u32, u16), u64> {
    if len < 16 {
        return Err(EINVAL);
    }
    let mut raw = [0u8; 16];
    if !u_read(ptr, &mut raw) {
        return Err(EFAULT);
    }
    let family = u16::from_le_bytes([raw[0], raw[1]]);
    if family != 2 {
        return Err(EAFNOSUPPORT);
    }
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    let addr = u32::from_be_bytes(raw[4..8].try_into().unwrap());
    Ok((addr, port))
}

fn write_sockaddr_in(ptr: u64, len_ptr: u64, addr: u32, port: u16) -> Result<(), u64> {
    if ptr == 0 {
        return Ok(());
    }
    let mut raw = [0u8; 16];
    raw[0..2].copy_from_slice(&2u16.to_le_bytes());
    raw[2..4].copy_from_slice(&port.to_be_bytes());
    raw[4..8].copy_from_slice(&addr.to_be_bytes());
    if !u_write(ptr, &raw) {
        return Err(EFAULT);
    }
    if len_ptr != 0 && !u_write(len_ptr, &16u32.to_le_bytes()) {
        return Err(EFAULT);
    }
    Ok(())
}

fn read_sockaddr_in6(ptr: u64, len: u64) -> Result<([u8; 16], u16), u64> {
    if len < 28 {
        return Err(EINVAL);
    }
    let mut raw = [0u8; 28];
    if !u_read(ptr, &mut raw) {
        return Err(EFAULT);
    }
    let family = u16::from_le_bytes([raw[0], raw[1]]);
    if family != 10 {
        return Err(EAFNOSUPPORT);
    }
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&raw[8..24]);
    Ok((addr, port))
}

fn write_sockaddr_in6(ptr: u64, len_ptr: u64, addr: [u8; 16], port: u16) -> Result<(), u64> {
    if ptr == 0 {
        return Ok(());
    }
    let mut raw = [0u8; 28];
    raw[0..2].copy_from_slice(&10u16.to_le_bytes());
    raw[2..4].copy_from_slice(&port.to_be_bytes());
    raw[8..24].copy_from_slice(&addr);
    if !u_write(ptr, &raw) {
        return Err(EFAULT);
    }
    if len_ptr != 0 && !u_write(len_ptr, &28u32.to_le_bytes()) {
        return Err(EFAULT);
    }
    Ok(())
}

fn sys_socket(domain: u64, typ: u64, proto: u64) -> u64 {
    const SOCK_DGRAM: u64 = 2;
    const SOCK_NONBLOCK: u64 = 0x800;
    const SOCK_CLOEXEC: u64 = 0x80000;
    // AF_INET и AF_INET6. AF_NETLINK нет.
    if domain != 2 && domain != 10 {
        return EAFNOSUPPORT;
    }
    let v6 = domain == 10;
    const SOCK_STREAM: u64 = 1;
    let flags = typ & (SOCK_NONBLOCK | SOCK_CLOEXEC);
    let kind = typ & !(SOCK_NONBLOCK | SOCK_CLOEXEC);
    let nonblock = flags & SOCK_NONBLOCK != 0;
    let cloexec = flags & SOCK_CLOEXEC != 0;
    let (id, slot_fd) = if kind == SOCK_STREAM {
        if proto != 0 && proto != 6 {
            return EPROTONOSUPPORT;
        }
        if v6 {
            match crate::net6::tcp_open(nonblock) {
                Ok(id) => (id, Fd::Tcp6 { id }),
                Err(e) => return neg_err(e),
            }
        } else {
            match crate::net::tcp_open(nonblock) {
                Ok(id) => (id, Fd::Tcp { id }),
                Err(e) => return neg_err(e),
            }
        }
    } else if kind == SOCK_DGRAM {
        if proto != 0 && proto != 17 {
            return EPROTONOSUPPORT;
        }
        if v6 {
            match crate::net6::udp_open(nonblock) {
                Ok(id) => (id, Fd::Udp6 { id }),
                Err(e) => return neg_err(e),
            }
        } else {
            match crate::net::udp_open(nonblock) {
                Ok(id) => (id, Fd::Udp { id }),
                Err(e) => return neg_err(e),
            }
        }
    } else {
        return EPROTONOSUPPORT;
    };
    let id_close = id;
    let mut slot = Some(slot_fd);
    match with_current_fds(|fds| alloc_fd(&mut slot, fds, cloexec)) {
        Ok(fd) if fd == EMFILE => {
            close_new_sock(&slot, id_close);
            EMFILE
        }
        Ok(fd) => fd,
        Err(e) => {
            close_new_sock(&slot, id_close);
            e
        }
    }
}

fn close_new_sock(slot: &Option<Fd>, id: usize) {
    match slot {
        Some(Fd::Tcp { .. }) => crate::net::tcp_close(id),
        Some(Fd::Udp { .. }) => crate::net::udp_close(id),
        Some(Fd::Tcp6 { .. }) => crate::net6::tcp_close(id),
        Some(Fd::Udp6 { .. }) => crate::net6::udp_close(id),
        _ => {}
    }
}

fn sys_bind(fd: u64, addr: u64, len: u64) -> u64 {
    let kind = match sock_kind(fd) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let r = match kind {
        SockKind::Udp(id) => {
            let (ip, port) = match read_sockaddr_in(addr, len) {
                Ok(v) => v,
                Err(e) => return e,
            };
            crate::net::udp_bind(id, ip, port)
        }
        SockKind::Tcp(id) => {
            let (ip, port) = match read_sockaddr_in(addr, len) {
                Ok(v) => v,
                Err(e) => return e,
            };
            crate::net::tcp_bind(id, ip, port)
        }
        SockKind::Udp6(id) => {
            let (ip, port) = match read_sockaddr_in6(addr, len) {
                Ok(v) => v,
                Err(e) => return e,
            };
            crate::net6::udp_bind(id, ip, port)
        }
        SockKind::Tcp6(id) => {
            let (ip, port) = match read_sockaddr_in6(addr, len) {
                Ok(v) => v,
                Err(e) => return e,
            };
            crate::net6::tcp_bind(id, ip, port)
        }
    };
    match r {
        Ok(()) => 0,
        Err(e) => neg_err(e),
    }
}

fn sys_listen(fd: u64, backlog: u64) -> u64 {
    let kind = match sock_kind(fd) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let r = match kind {
        SockKind::Tcp(id) => crate::net::tcp_listen(id, backlog),
        SockKind::Tcp6(id) => crate::net6::tcp_listen(id, backlog),
        SockKind::Udp(_) | SockKind::Udp6(_) => return EOPNOTSUPP,
    };
    match r {
        Ok(()) => 0,
        Err(e) => neg_err(e),
    }
}

fn sys_accept(fd: u64, addr: u64, len: u64, flags: u64) -> u64 {
    const SOCK_NONBLOCK: u64 = 0x800;
    const SOCK_CLOEXEC: u64 = 0x80000;
    // Linux смотрит флаги раньше fd: чужой бит не снимает соединение с очереди.
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return EINVAL;
    }
    let kind = match sock_kind(fd) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let (id, v6) = match kind {
        SockKind::Tcp(id) => (id, false),
        SockKind::Tcp6(id) => (id, true),
        SockKind::Udp(_) | SockKind::Udp6(_) => return EOPNOTSUPP,
    };
    // Блокирует ли сам accept — флаг слушателя. Ребёнок его не наследует.
    let nonblock = if v6 {
        crate::net6::tcp_nonblock(id)
    } else {
        crate::net::tcp_nonblock(id)
    };
    let child_nonblock = flags & SOCK_NONBLOCK != 0;
    let cloexec = flags & SOCK_CLOEXEC != 0;
    loop {
        let accepted = if v6 {
            match crate::net6::tcp_accept(id) {
                Ok((child, ip, port)) => Ok((child, Err((ip, port)))),
                Err(e) => Err(e),
            }
        } else {
            match crate::net::tcp_accept(id) {
                Ok((child, ip, port)) => Ok((child, Ok((ip, port)))),
                Err(e) => Err(e),
            }
        };
        match accepted {
            Ok((child, peer)) => {
                if child_nonblock {
                    let rc = if v6 {
                        crate::net6::tcp_set_nonblock(child, true)
                    } else {
                        crate::net::tcp_set_nonblock(child, true)
                    };
                    if let Err(e) = rc {
                        if v6 {
                            crate::net6::tcp_close(child);
                        } else {
                            crate::net::tcp_close(child);
                        }
                        return neg_err(e);
                    }
                }
                let mut slot = Some(if v6 {
                    Fd::Tcp6 { id: child }
                } else {
                    Fd::Tcp { id: child }
                });
                match with_current_fds(|fds| alloc_fd(&mut slot, fds, cloexec)) {
                    Ok(nfd) if nfd == EMFILE => {
                        if v6 {
                            crate::net6::tcp_close(child);
                        } else {
                            crate::net::tcp_close(child);
                        }
                        return EMFILE;
                    }
                    Ok(nfd) => {
                        let wrote = match peer {
                            Ok((ip, port)) => write_sockaddr_in(addr, len, ip, port),
                            Err((ip, port)) => write_sockaddr_in6(addr, len, ip, port),
                        };
                        if let Err(e) = wrote {
                            if v6 {
                                crate::net6::tcp_close(child);
                            } else {
                                crate::net::tcp_close(child);
                            }
                            let _ = with_current_fds(|fds| {
                                if (nfd as usize) < fds.len() {
                                    fds.set_cloexec(nfd, false);
                                    fds[nfd as usize] = None;
                                }
                            });
                            return e;
                        }
                        return nfd;
                    }
                    Err(e) => {
                        if v6 {
                            crate::net6::tcp_close(child);
                        } else {
                            crate::net::tcp_close(child);
                        }
                        return e;
                    }
                }
            }
            Err(crate::net::EAGAIN) if !nonblock => {
                if crate::signal::pending_interrupts() && !crate::signal::keep_waiting() {
                    return EINTR;
                }
                // Проводной клиент приходит кадром: качаем сами.
                crate::net::pump();
                x86_64::instructions::hlt();
            }
            Err(e) => return neg_err(e),
        }
    }
}

fn sys_connect(fd: u64, addr: u64, len: u64) -> u64 {
    let kind = match sock_kind(fd) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let r = match kind {
        SockKind::Udp(id) => {
            let (ip, port) = match read_sockaddr_in(addr, len) {
                Ok(v) => v,
                Err(e) => return e,
            };
            crate::net::udp_connect(id, ip, port)
        }
        SockKind::Tcp(id) => {
            let (ip, port) = match read_sockaddr_in(addr, len) {
                Ok(v) => v,
                Err(e) => return e,
            };
            crate::net::tcp_connect(id, ip, port)
        }
        SockKind::Udp6(id) => {
            let (ip, port) = match read_sockaddr_in6(addr, len) {
                Ok(v) => v,
                Err(e) => return e,
            };
            crate::net6::udp_connect(id, ip, port)
        }
        SockKind::Tcp6(id) => {
            let (ip, port) = match read_sockaddr_in6(addr, len) {
                Ok(v) => v,
                Err(e) => return e,
            };
            crate::net6::tcp_connect(id, ip, port)
        }
    };
    match r {
        Ok(()) => 0,
        Err(e) => neg_err(e),
    }
}

fn sys_sendto(fd: u64, buf: u64, len: u64, _flags: u64, dest: u64, destlen: u64) -> u64 {
    let kind = match sock_kind(fd) {
        Ok(k) => k,
        Err(e) => return e,
    };
    if let SockKind::Tcp(id) = kind {
        if dest != 0 {
            return EISCONN;
        }
        return tcp_write(id, buf, len);
    }
    if let SockKind::Tcp6(id) = kind {
        if dest != 0 {
            return EISCONN;
        }
        return tcp6_write(id, buf, len);
    }
    let id = match kind {
        SockKind::Udp(id) => id,
        SockKind::Udp6(id) => id,
        SockKind::Tcp(_) | SockKind::Tcp6(_) => return ENOTSOCK,
    };
    let v6 = matches!(kind, SockKind::Udp6(_));
    if len as usize > MAX_IO {
        return EFAULT;
    }
    if (len as usize) > crate::net::DGRAM_MAX {
        return EMSGSIZE;
    }
    let bytes = if len == 0 {
        Vec::new()
    } else {
        let Some(b) = copy_from_user(buf, len as usize) else {
            return EFAULT;
        };
        b
    };
    let sent = if v6 {
        let dst = if dest == 0 {
            None
        } else {
            match read_sockaddr_in6(dest, destlen) {
                Ok(v) => Some(v),
                Err(e) => return e,
            }
        };
        crate::net6::udp_send(id, &bytes, dst)
    } else {
        let dst = if dest == 0 {
            None
        } else {
            match read_sockaddr_in(dest, destlen) {
                Ok(v) => Some(v),
                Err(e) => return e,
            }
        };
        crate::net::udp_send(id, &bytes, dst)
    };
    match sent {
        Ok(n) => n as u64,
        Err(e) => neg_err(e),
    }
}

fn sys_recvfrom(fd: u64, buf: u64, len: u64, _flags: u64, src: u64, srclen: u64) -> u64 {
    let kind = match sock_kind(fd) {
        Ok(k) => k,
        Err(e) => return e,
    };
    if let SockKind::Tcp(id) = kind {
        return tcp_read(id, buf, len, src, srclen);
    }
    if let SockKind::Tcp6(id) = kind {
        return tcp6_read(id, buf, len, src, srclen);
    }
    let (id, v6) = match kind {
        SockKind::Udp(id) => (id, false),
        SockKind::Udp6(id) => (id, true),
        SockKind::Tcp(_) | SockKind::Tcp6(_) => return ENOTSOCK,
    };
    if buf == 0 || len == 0 {
        return 0;
    }
    if len as usize > MAX_IO {
        return EFAULT;
    }
    let cap = (len as usize).min(crate::net::DGRAM_MAX);
    let mut tmp = alloc::vec![0u8; cap];
    let nonblock = if v6 {
        crate::net6::udp_nonblock(id)
    } else {
        crate::net::udp_nonblock(id)
    };
    loop {
        let got = if v6 {
            crate::net6::udp_recv(id, &mut tmp).map(|(n, addr, port)| (n, Err((addr, port))))
        } else {
            crate::net::udp_recv(id, &mut tmp).map(|(n, addr, port)| (n, Ok((addr, port))))
        };
        match got {
            Ok((n, peer)) => {
                if !u_write(buf, &tmp[..n]) {
                    return EFAULT;
                }
                let wrote = match peer {
                    Ok((addr, port)) => write_sockaddr_in(src, srclen, addr, port),
                    Err((addr, port)) => write_sockaddr_in6(src, srclen, addr, port),
                };
                if let Err(e) = wrote {
                    return e;
                }
                return n as u64;
            }
            Err(crate::net::EAGAIN) if !nonblock => {
                if crate::signal::pending_interrupts() && !crate::signal::keep_waiting() {
                    return EINTR;
                }
                x86_64::instructions::hlt();
            }
            Err(e) => return neg_err(e),
        }
    }
}

fn sys_getsockname(fd: u64, addr: u64, len: u64) -> u64 {
    let wrote = match sock_kind(fd) {
        Ok(SockKind::Udp(id)) => {
            let (ip, port) = crate::net::udp_name(id).unwrap_or((0, 0));
            write_sockaddr_in(addr, len, ip, port)
        }
        Ok(SockKind::Tcp(id)) => {
            let (ip, port) = crate::net::tcp_name(id).unwrap_or((0, 0));
            write_sockaddr_in(addr, len, ip, port)
        }
        Ok(SockKind::Udp6(id)) => {
            let (ip, port) = crate::net6::udp_name(id).unwrap_or((crate::net6::UNSPEC, 0));
            write_sockaddr_in6(addr, len, ip, port)
        }
        Ok(SockKind::Tcp6(id)) => {
            let (ip, port) = crate::net6::tcp_name(id).unwrap_or((crate::net6::UNSPEC, 0));
            write_sockaddr_in6(addr, len, ip, port)
        }
        Err(e) => return e,
    };
    match wrote {
        Ok(()) => 0,
        Err(e) => e,
    }
}

fn sys_getpeername(fd: u64, addr: u64, len: u64) -> u64 {
    let wrote = match sock_kind(fd) {
        Ok(SockKind::Udp(id)) => match crate::net::udp_peer(id) {
            Some((ip, port)) => write_sockaddr_in(addr, len, ip, port),
            None => return ENOTCONN,
        },
        Ok(SockKind::Tcp(id)) => match crate::net::tcp_peer(id) {
            Some((ip, port)) => write_sockaddr_in(addr, len, ip, port),
            None => return ENOTCONN,
        },
        Ok(SockKind::Udp6(id)) => match crate::net6::udp_peer(id) {
            Some((ip, port)) => write_sockaddr_in6(addr, len, ip, port),
            None => return ENOTCONN,
        },
        Ok(SockKind::Tcp6(id)) => match crate::net6::tcp_peer(id) {
            Some((ip, port)) => write_sockaddr_in6(addr, len, ip, port),
            None => return ENOTCONN,
        },
        Err(e) => return e,
    };
    match wrote {
        Ok(()) => 0,
        Err(e) => e,
    }
}

const EISCONN: u64 = (-(106i64)) as u64;
const ENOTCONN: u64 = (-(107i64)) as u64;

fn tcp_write(id: usize, buf: u64, len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    let Some(bytes) = copy_from_user(buf, len as usize) else {
        return EFAULT;
    };
    let nonblock = crate::net::tcp_nonblock(id);
    let mut off = 0usize;
    loop {
        match crate::net::tcp_send(id, &bytes[off..]) {
            Ok(0) => return off as u64,
            Ok(n) => {
                off += n;
                if off == bytes.len() {
                    return off as u64;
                }
            }
            Err(crate::net::EAGAIN) if !nonblock => {
                if crate::signal::pending_interrupts() && !crate::signal::keep_waiting() {
                    return if off > 0 { off as u64 } else { EINTR };
                }
                x86_64::instructions::hlt();
            }
            Err(e) => return if off > 0 { off as u64 } else { neg_err(e) },
        }
    }
}

fn tcp6_write(id: usize, buf: u64, len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    let Some(bytes) = copy_from_user(buf, len as usize) else {
        return EFAULT;
    };
    let nonblock = crate::net6::tcp_nonblock(id);
    let mut off = 0usize;
    loop {
        match crate::net6::tcp_send(id, &bytes[off..]) {
            Ok(0) => return off as u64,
            Ok(n) => {
                off += n;
                if off == bytes.len() {
                    return off as u64;
                }
            }
            Err(crate::net6::EAGAIN) if !nonblock => {
                if crate::signal::pending_interrupts() && !crate::signal::keep_waiting() {
                    return if off > 0 { off as u64 } else { EINTR };
                }
                x86_64::instructions::hlt();
            }
            Err(e) => return if off > 0 { off as u64 } else { neg_err(e) },
        }
    }
}

fn tcp_read(id: usize, buf: u64, len: u64, src: u64, srclen: u64) -> u64 {
    if buf == 0 || len == 0 {
        return 0;
    }
    if len as usize > MAX_IO {
        return EFAULT;
    }
    let mut tmp = alloc::vec![0u8; len as usize];
    let nonblock = crate::net::tcp_nonblock(id);
    loop {
        match crate::net::tcp_recv(id, &mut tmp) {
            Ok((n, addr, port)) => {
                if n > 0 && !u_write(buf, &tmp[..n]) {
                    return EFAULT;
                }
                if let Err(e) = write_sockaddr_in(src, srclen, addr, port) {
                    return e;
                }
                return n as u64;
            }
            Err(crate::net::EAGAIN) if !nonblock => {
                if crate::signal::pending_interrupts() && !crate::signal::keep_waiting() {
                    return EINTR;
                }
                // Блокирующий читатель сам качает кадры: проводные данные
                // приходят по прерыванию, ждать некому.
                crate::net::pump();
                x86_64::instructions::hlt();
            }
            Err(e) => return neg_err(e),
        }
    }
}

fn tcp6_read(id: usize, buf: u64, len: u64, src: u64, srclen: u64) -> u64 {
    if buf == 0 || len == 0 {
        return 0;
    }
    if len as usize > MAX_IO {
        return EFAULT;
    }
    let mut tmp = alloc::vec![0u8; len as usize];
    let nonblock = crate::net6::tcp_nonblock(id);
    loop {
        match crate::net6::tcp_recv(id, &mut tmp) {
            Ok((n, addr, port)) => {
                if n > 0 && !u_write(buf, &tmp[..n]) {
                    return EFAULT;
                }
                if let Err(e) = write_sockaddr_in6(src, srclen, addr, port) {
                    return e;
                }
                return n as u64;
            }
            Err(crate::net6::EAGAIN) if !nonblock => {
                if crate::signal::pending_interrupts() && !crate::signal::keep_waiting() {
                    return EINTR;
                }
                // Блокирующий читатель сам качает кадры, как у IPv4.
                crate::net::pump();
                x86_64::instructions::hlt();
            }
            Err(e) => return neg_err(e),
        }
    }
}

/// `SO_REUSEADDR` (2) и `SO_BROADCAST` (6) пишутся в сокет и читаются обратно.
fn sys_setsockopt(fd: u64, level: u64, opt: u64, val: u64, len: u64) -> u64 {
    let kind = match sock_kind(fd) {
        Ok(k) => k,
        Err(e) => return e,
    };
    if level == 1 && (opt == 2 || opt == 6) {
        if len < 4 || val == 0 {
            return EINVAL;
        }
        let mut raw = [0u8; 4];
        if !u_read(val, &mut raw) {
            return EFAULT;
        }
        let on = i32::from_le_bytes(raw) != 0;
        let rc = match kind {
            SockKind::Udp(id) => crate::net::udp_set_opt(id, opt as u32, on),
            SockKind::Tcp(id) => crate::net::tcp_set_opt(id, opt as u32, on),
            SockKind::Udp6(id) => crate::net6::udp_set_opt(id, opt as u32, on),
            SockKind::Tcp6(id) => crate::net6::tcp_set_opt(id, opt as u32, on),
        };
        return match rc {
            Ok(()) => 0,
            Err(e) => neg_err(e),
        };
    }
    // IPV6_V6ONLY. Стек и так только IPv6: 0 отвергается, остальное успех.
    if level == 41 && opt == 26 {
        match kind {
            SockKind::Udp6(_) | SockKind::Tcp6(_) => {}
            _ => return ENOPROTOOPT,
        }
        if len < 4 || val == 0 {
            return EINVAL;
        }
        let mut raw = [0u8; 4];
        if !u_read(val, &mut raw) {
            return EFAULT;
        }
        if i32::from_le_bytes(raw) == 0 {
            return EOPNOTSUPP;
        }
        return 0;
    }
    ENOPROTOOPT
}

fn sys_getsockopt(fd: u64, level: u64, opt: u64, val: u64, len_ptr: u64) -> u64 {
    let kind = match sock_kind(fd) {
        Ok(k) => k,
        Err(_) => return ENOTSOCK,
    };
    // SOL_SOCKET / SO_TYPE. TCP — 1, UDP — 2.
    if level == 1 && opt == 3 {
        let typ: i32 = match kind {
            SockKind::Tcp(_) | SockKind::Tcp6(_) => 1,
            SockKind::Udp(_) | SockKind::Udp6(_) => 2,
        };
        if !u_write(val, &typ.to_le_bytes()) {
            return EFAULT;
        }
        if len_ptr != 0 && !u_write(len_ptr, &4u32.to_le_bytes()) {
            return EFAULT;
        }
        return 0;
    }
    if level == 1 && (opt == 2 || opt == 6) {
        let rc = match kind {
            SockKind::Udp(id) => crate::net::udp_get_opt(id, opt as u32),
            SockKind::Tcp(id) => crate::net::tcp_get_opt(id, opt as u32),
            SockKind::Udp6(id) => crate::net6::udp_get_opt(id, opt as u32),
            SockKind::Tcp6(id) => crate::net6::tcp_get_opt(id, opt as u32),
        };
        let v = match rc {
            Ok(v) => v,
            Err(e) => return neg_err(e),
        };
        if !u_write(val, &v.to_le_bytes()) {
            return EFAULT;
        }
        if len_ptr != 0 && !u_write(len_ptr, &4u32.to_le_bytes()) {
            return EFAULT;
        }
        return 0;
    }
    if level == 41 && opt == 26 {
        match kind {
            SockKind::Udp6(_) | SockKind::Tcp6(_) => {}
            _ => return ENOPROTOOPT,
        }
        let v: i32 = 1;
        if !u_write(val, &v.to_le_bytes()) {
            return EFAULT;
        }
        if len_ptr != 0 && !u_write(len_ptr, &4u32.to_le_bytes()) {
            return EFAULT;
        }
        return 0;
    }
    ENOPROTOOPT
}

// ---- Файловые операции ----

fn sys_read(fd: u64, buf: u64, len: u64) -> u64 {
    if buf == 0 || len == 0 {
        return 0;
    }
    if len as usize > MAX_IO {
        return EFAULT;
    }
    // Определяем вид fd коротко под локом, читаем без удержания лока
    // (консоль/pipe блокируются — их ждущие циклы не должны держать таблицу).
    enum Kind {
        Console,
        Pipe(usize),
        Udp,
        Tcp(usize),
        Udp6,
        Tcp6(usize),
        File(String, u64, Option<Vec<u8>>),
        Bad(u64),
    }
    let kind = with_current_fds(|fds| match fds.get_mut(fd as usize).and_then(|x| x.as_mut()) {
        Some(Fd::Console { writable: false }) => Kind::Console,
        Some(Fd::Udp { .. }) => Kind::Udp,
        Some(Fd::Tcp { id }) => Kind::Tcp(*id),
        Some(Fd::Udp6 { .. }) => Kind::Udp6,
        Some(Fd::Tcp6 { id }) => Kind::Tcp6(*id),
        Some(Fd::Pipe { id, writable: false }) => Kind::Pipe(*id),
        Some(Fd::File { name, offset, accmode, dirty, .. }) if *accmode != 1 => {
            Kind::File(name.clone(), *offset, dirty.clone())
        }
        Some(Fd::Dir { .. }) => Kind::Bad(EISDIR),
        Some(Fd::File { .. }) => Kind::Bad(EBADF),
        Some(Fd::Console { .. }) | Some(Fd::Pipe { .. }) | Some(Fd::Epoll { .. }) => {
            Kind::Bad(EBADF)
        }
        None => Kind::Bad(EBADF),
    });
    match kind {
        Err(e) => e,
        Ok(Kind::Udp) | Ok(Kind::Udp6) => sys_recvfrom(fd, buf, len, 0, 0, 0),
        Ok(Kind::Tcp(id)) => tcp_read(id, buf, len, 0, 0),
        Ok(Kind::Tcp6(id)) => tcp6_read(id, buf, len, 0, 0),
        Ok(Kind::Console) => console_read(buf, len),
        Ok(Kind::Pipe(id)) => {
            let mut tmp = alloc::vec![0u8; len as usize];
            let n = pipe_read(id, &mut tmp);
            if n as i64 >= 0 && n > 0 && !u_write(buf, &tmp[..n as usize]) {
                return EFAULT;
            }
            n
        }
        Ok(Kind::File(name, offset, dirty)) => {
            let mut written = 0u64;
            let mut pos = offset;
            while written < len {
                let chunk = ((len - written) as usize).min(256 * 1024);
                let mut tmp = alloc::vec![0u8; chunk];
                let n = if let Some(d) = &dirty {
                    if pos as usize >= d.len() {
                        0
                    } else {
                        let n = (d.len() - pos as usize).min(chunk);
                        tmp[..n].copy_from_slice(&d[pos as usize..pos as usize + n]);
                        n
                    }
                } else {
                    crate::fs::read_at(&name, pos, &mut tmp).max(0) as usize
                };
                if n == 0 {
                    break;
                }
                if !u_write(buf + written, &tmp[..n]) {
                    return if written == 0 { EFAULT } else { written };
                }
                pos += n as u64;
                written += n as u64;
                if (n as u64) < chunk as u64 {
                    break;
                }
            }
            // Продвигаем курсор.
            let _ = with_fd(fd, |f| {
                if let Fd::File { offset, .. } = f {
                    *offset = pos;
                }
            });
            written
        }
        Ok(Kind::Bad(e)) => e,
    }
}

/// Упрощённое чтение консоли: побайтово из очереди клавиатуры.
/// Сигнал это чтение не прерывает: здесь блокируется строка шелла.
fn console_read(buf: u64, len: u64) -> u64 {
    for i in 0..len {
        let b = console_read_byte();
        if !u_write(buf + i, &[b]) {
            return if i == 0 { EFAULT } else { i };
        }
    }
    len
}

fn sys_write(fd: u64, buf: u64, len: u64) -> u64 {
    if buf == 0 || len == 0 {
        return 0;
    }
    let Some(bytes) = copy_from_user(buf, len as usize) else {
        return EFAULT;
    };
    // Консоль/pipe пишем без удержания лока таблицы (pipe может блокировать).
    enum Kind {
        Console,
        Pipe(usize),
        Udp(usize),
        Tcp(usize),
        Udp6(usize),
        Tcp6(usize),
        File,
        Bad,
    }
    let kind = with_current_fds(|fds| match fds.get_mut(fd as usize).and_then(|x| x.as_mut()) {
        Some(Fd::Console { writable: true }) => Kind::Console,
        Some(Fd::Pipe { id, writable: true }) => Kind::Pipe(*id),
        Some(Fd::Udp { id }) => Kind::Udp(*id),
        Some(Fd::Tcp { id }) => Kind::Tcp(*id),
        Some(Fd::Udp6 { id }) => Kind::Udp6(*id),
        Some(Fd::Tcp6 { id }) => Kind::Tcp6(*id),
        Some(Fd::File { accmode, .. }) if *accmode != 0 => Kind::File,
        _ => Kind::Bad,
    });
    match kind {
        Ok(Kind::Console) => console_write(&bytes),
        Ok(Kind::Pipe(id)) => pipe_write(id, &bytes),
        Ok(Kind::Udp(id)) => match crate::net::udp_send(id, &bytes, None) {
            Ok(n) => n as u64,
            Err(e) => neg_err(e),
        },
        Ok(Kind::Udp6(id)) => match crate::net6::udp_send(id, &bytes, None) {
            Ok(n) => n as u64,
            Err(e) => neg_err(e),
        },
        Ok(Kind::Tcp(id)) => tcp_write(id, buf, len),
        Ok(Kind::Tcp6(id)) => tcp6_write(id, buf, len),
        Ok(Kind::File) => {
            // Запись в буфер dirty (сброс при close) — под локом fd.
            // Пустой dirty у уже существующего файла — это ещё не новый образ:
            // сначала читаем старые байты, иначе close затирает хвост.
            with_fd(fd, |f| match f {
                Fd::File {
                    name,
                    offset,
                    accmode,
                    append,
                    dirty,
                    ..
                } if *accmode != 0 => {
                    if let Err(e) = seed_dirty(name, dirty) {
                        return e;
                    }
                    let data = dirty.as_mut().unwrap();
                    if *append {
                        let end = data.len().saturating_add(bytes.len());
                        if end > DIRTY_CAP {
                            return EFBIG;
                        }
                        data.extend_from_slice(&bytes);
                    } else {
                        let pos = *offset as usize;
                        let end = pos.saturating_add(bytes.len());
                        if end > DIRTY_CAP {
                            return EFBIG;
                        }
                        if data.len() < end {
                            data.resize(end, 0);
                        }
                        data[pos..end].copy_from_slice(&bytes);
                        *offset += bytes.len() as u64;
                    }
                    bytes.len() as u64
                }
                _ => EBADF,
            })
            .unwrap_or(EBADF)
        }
        _ => EBADF,
    }
}

fn fd_name(fd: u64) -> Option<String> {
    with_fd(fd, |f| match f {
        Fd::File { name, .. } => Some(name.clone()),
        _ => None,
    })
    .ok().flatten()
}

fn sys_close(fd: u64) -> u64 {
    let taken = with_current_fds(|fds| {
        if fd as usize >= fds.len() {
            return None;
        }
        fds.set_cloexec(fd, false);
        fds[fd as usize].take()
    });
    match taken {
        Ok(Some(obj)) => finish_close(obj, fd),
        Ok(None) => EBADF,
        Err(e) => e,
    }
}

/// Закрыть описание, уже снятое с номера: сброс dirty, концы pipe, сокет, epoll.
fn finish_close(obj: Fd, fd: u64) -> u64 {
    let (ep_id, flushed) = match &obj {
        Fd::File { name, dirty: Some(data), .. } => {
            (None, crate::fs::write_canon(name, data).map(|_| ()))
        }
        Fd::Pipe { id, writable } => {
            pipe_close_end(*id, *writable);
            (None, Ok(()))
        }
        Fd::Udp { id } => {
            crate::net::udp_close(*id);
            (None, Ok(()))
        }
        Fd::Tcp { id } => {
            crate::net::tcp_close(*id);
            (None, Ok(()))
        }
        Fd::Udp6 { id } => {
            crate::net6::udp_close(*id);
            (None, Ok(()))
        }
        Fd::Tcp6 { id } => {
            crate::net6::tcp_close(*id);
            (None, Ok(()))
        }
        Fd::Epoll { id } => (Some(*id), Ok(())),
        _ => (None, Ok(())),
    };
    // Номер освобождён. Интересы, смотревшие на него, снимаем до повторной выдачи.
    epoll_on_close(ep_id, fd);
    match flushed {
        Ok(()) => 0,
        Err(e) => fs_err(e),
    }
}

/// `execve` закрывает номера с `FD_CLOEXEC`. Образ уже принят: неудачный
/// exec сюда не доходит и дескрипторы не трогает.
pub fn close_on_exec() {
    let bits = match with_current_fds(|fds| fds.cloexec_bits()) {
        Ok(b) => b,
        Err(_) => return,
    };
    for i in 0..64 {
        if bits & (1u64 << i) != 0 {
            let _ = sys_close(i as u64);
        }
    }
}

fn sys_chmod(path_ptr: u64, mode: u64) -> u64 {
    let Some(path) = task::copy_user_cstr(path_ptr, 256) else { return EFAULT };
    let Some(canon) = task_resolve(&path) else { return ENAMETOOLONG };
    // Биты пишутся и читаются через stat. Проверки доступа по ним нет.
    match crate::fs::chmod(&canon, (mode as u32 & 0o7777) as u16) {
        Ok(()) => 0,
        Err(e) => fs_err(e),
    }
}

fn sys_fchmod(fd: u64, mode: u64) -> u64 {
    let path = with_fd(fd, |f| match f {
        Fd::File { name, .. } => Some(name.clone()),
        Fd::Dir { prefix, .. } => Some(prefix.clone()),
        _ => None,
    });
    match path {
        Ok(Some(p)) => match crate::fs::chmod(&p, (mode as u32 & 0o7777) as u16) {
            Ok(()) => 0,
            Err(e) => fs_err(e),
        },
        Ok(None) => EINVAL,
        Err(e) => e,
    }
}

fn sys_openat(dirfd: u64, path_ptr: u64, flags: u64, mode: u64) -> u64 {
    const O_ACCMODE: u64 = 3;
    const O_CREAT: u64 = 0x40;
    const O_TRUNC: u64 = 0x200;
    const O_APPEND: u64 = 0x400;
    const O_DIRECTORY: u64 = 0x10000;
    const O_CLOEXEC: u64 = 0x80000;

    let Some(path) = task::copy_user_cstr(path_ptr, 256) else { return EFAULT };

    // Разрешение пути: относительный путь — от cwd, либо от dirfd-каталога.
    let canon = if path.starts_with('/') {
        match task_resolve(&path) {
            Some(c) => c,
            None => return ENAMETOOLONG,
        }
    } else if dirfd == AT_FDCWD || dirfd == u64::MAX {
        match task_resolve(&path) {
            Some(c) => c,
            None => return ENAMETOOLONG,
        }
    } else {
        // Относительно открытого каталога.
        let base = with_fd(dirfd, |f| match f {
            Fd::Dir { prefix, .. } => Some(prefix.clone()),
            _ => None,
        })
        .ok()
        .flatten();
        let Some(base) = base else { return ENOTDIR };
        let joined = if base == "/" {
            format!("/{}", path)
        } else {
            format!("{}/{}", base, path)
        };
        match task_resolve(&joined) {
            Some(c) => c,
            None => return ENAMETOOLONG,
        }
    };

    let accmode = flags & O_ACCMODE;
    let cloexec = flags & O_CLOEXEC != 0;
    let want_dir = flags & O_DIRECTORY != 0;
    let is_dir = crate::fs::is_dir(&canon);
    let exists = crate::fs::exists(&canon);

    if is_dir {
        if want_dir || accmode == 0 {
            let mut slot = Some(Fd::Dir { prefix: canon, idx: 0 });
            return with_current_fds(|fds| alloc_fd(&mut slot, fds, cloexec)).unwrap_or(EMFILE);
        }
        return EISDIR;
    }
    if want_dir {
        return if exists { ENOTDIR } else { ENOENT };
    }
    if !exists {
        if flags & O_CREAT == 0 {
            return ENOENT;
        }
        if let Err(e) = crate::fs::parent_ok(&canon) {
            return fs_err(e);
        }
        let perm = ((mode as u32) & 0o777) & !task::current_umask();
        if let Err(e) = crate::fs::create_file(&canon, perm as u16) {
            return fs_err(e);
        }
    }
    // Существующий файл.
    if accmode == 0 && flags & O_TRUNC != 0 {
        // RDONLY+TRUNC — молча игнорируем TRUNC (POSIX такое не валиден).
    }
    let dirty = if accmode != 0 && flags & O_TRUNC != 0 {
        Some(Vec::new())
    } else {
        None
    };
    let mut slot = Some(Fd::File {
        name: canon,
        offset: 0,
        accmode: accmode as u8,
        append: flags & O_APPEND != 0,
        dirty,
    });
    with_current_fds(|fds| alloc_fd(&mut slot, fds, cloexec)).unwrap_or(EMFILE)
}

fn sys_fstat(fd: u64, buf: u64) -> u64 {
    enum Hit {
        Ready(u64, u32, u64),
        File(String, Option<u64>),
        Dir(String),
    }
    let hit = with_fd(fd, |f| match f {
        Fd::Console { .. } => Hit::Ready(0, S_IFCHR | 0o620, 1),
        Fd::File { name, dirty, .. } => {
            Hit::File(name.clone(), dirty.as_ref().map(|d| d.len() as u64))
        }
        Fd::Dir { prefix, .. } => Hit::Dir(prefix.clone()),
        Fd::Pipe { .. } => Hit::Ready(0, S_IFCHR | 0o644, 1),
        Fd::Udp { .. } | Fd::Tcp { .. } | Fd::Udp6 { .. } | Fd::Tcp6 { .. } => {
            Hit::Ready(0, 0o140000 | 0o666, 1)
        }
        Fd::Epoll { .. } => Hit::Ready(0, S_IFREG | 0o600, 1),
    });
    let (uid, gid) = (task::cred_euid() as u32, task::cred_egid() as u32);
    let st = match hit {
        Ok(Hit::Ready(sz, mode, nlink)) => (sz, mode, nlink, uid, gid),
        Ok(Hit::File(name, dirty_len)) => {
            let size = dirty_len.unwrap_or_else(|| crate::fs::size_of(&name).max(0) as u64);
            let mode = crate::fs::mode_of(&name).unwrap_or(S_IFREG | 0o644);
            let (fuid, fgid) = crate::fs::owner_of(&name).unwrap_or((0, 0));
            (size, mode, 1, fuid, fgid)
        }
        Ok(Hit::Dir(name)) => {
            let mode = crate::fs::mode_of(&name).unwrap_or(S_IFDIR | 0o755);
            let (fuid, fgid) = crate::fs::owner_of(&name).unwrap_or((0, 0));
            (0, mode, crate::fs::nlink_of(&name).max(2), fuid, fgid)
        }
        Err(e) => return e,
    };
    if !write_stat(buf, st.0, st.1, st.2, st.3, st.4) {
        return EFAULT;
    }
    0
}

fn sys_newfstatat(dirfd: u64, path_ptr: u64, buf: u64, flags: u64) -> u64 {
    const AT_EMPTY_PATH: u64 = 0x1000;
    let empty = match task::copy_user_cstr(path_ptr, 256) {
        Some(p) => p.is_empty(),
        None => return EFAULT,
    };
    if empty && flags & AT_EMPTY_PATH != 0 {
        return sys_fstat(dirfd, buf);
    }
    let Some(path) = task::copy_user_cstr(path_ptr, 256) else { return EFAULT };
    let canon = if path.starts_with('/') || dirfd == AT_FDCWD || dirfd == u64::MAX {
        match task_resolve(&path) {
            Some(c) => c,
            None => return ENAMETOOLONG,
        }
    } else {
        let base = with_fd(dirfd, |f| match f {
            Fd::Dir { prefix, .. } => Some(prefix.clone()),
            _ => None,
        })
        .ok()
        .flatten();
        let Some(base) = base else { return ENOTDIR };
        let joined = if base == "/" {
            format!("/{}", path)
        } else {
            format!("{}/{}", base, path)
        };
        match task_resolve(&joined) {
            Some(c) => c,
            None => return ENAMETOOLONG,
        }
    };
    match stat_of(&canon) {
        Some((sz, mode, nlink, uid, gid)) => {
            if !write_stat(buf, sz, mode, nlink, uid, gid) {
                return EFAULT;
            }
            0
        }
        None => ENOENT,
    }
}

fn sys_statx(dirfd: u64, path_ptr: u64, _flags: u64, _mask: u64, buf: u64) -> u64 {
    if buf == 0 {
        return EFAULT;
    }
    // struct statx (256 байт): заполняем базовые поля.
    let st = match task::copy_user_cstr(path_ptr, 256) {
        Some(path) if !path.is_empty() => {
            let canon = if path.starts_with('/') || dirfd == AT_FDCWD || dirfd == u64::MAX {
                match task_resolve(&path) {
                    Some(c) => c,
                    None => return ENAMETOOLONG,
                }
            } else {
                match task_resolve(&path) {
                    Some(c) => c,
                    None => return ENAMETOOLONG,
                }
            };
            stat_of(&canon)
        }
        Some(_) => {
            // AT_EMPTY_PATH: fstat по dirfd
            return sys_fstat(dirfd, buf);
        }
        None => return EFAULT,
    };
    let mut raw = [0u8; 256];
    match st {
        Some((sz, mode, nlink, uid, gid)) => {
            let now = crate::interrupts::uptime_ms();
            raw[0..4].copy_from_slice(&0x7ffu32.to_le_bytes());
            raw[4..8].copy_from_slice(&4096u32.to_le_bytes());
            raw[16..20].copy_from_slice(&(nlink as u32).to_le_bytes());
            raw[20..24].copy_from_slice(&uid.to_le_bytes());
            raw[24..28].copy_from_slice(&gid.to_le_bytes());
            raw[28..30].copy_from_slice(&(mode as u16).to_le_bytes());
            raw[32..40].copy_from_slice(&fake_ino("statx").to_le_bytes());
            raw[40..48].copy_from_slice(&sz.to_le_bytes());
            raw[48..56].copy_from_slice(&((sz + 511) / 512).to_le_bytes());
            for off in [64, 96, 112] {
                raw[off..off + 8].copy_from_slice(&(now / 1000).to_le_bytes());
                raw[off + 8..off + 16].copy_from_slice(&(((now % 1000) * 1_000_000).to_le_bytes()));
            }
            if !u_write(buf, &raw) {
                return EFAULT;
            }
            0
        }
        None => ENOENT,
    }
}

fn sys_lseek(fd: u64, offset: i64, whence: u64) -> u64 {
    use x86_64::structures::paging::Translate;
    let r = with_fd(fd, |f| match f {
        Fd::File { name, offset: cur, dirty, .. } => {
            let size = match dirty {
                Some(d) => d.len() as i64,
                None => crate::fs::size_of(name).max(0) as i64,
            };
            let base = match whence {
                0 => 0,               // SEEK_SET
                1 => *cur as i64,     // SEEK_CUR
                2 => size,            // SEEK_END
                _ => return EINVAL,
            };
            let Some(new) = base.checked_add(offset) else {
                return EINVAL;
            };
            if new < 0 {
                return EINVAL;
            }
            *cur = new as u64;
            new as u64
        }
        Fd::Dir { .. } => {
            // SEEK_SET на индекс записи: разрешаем позиционирование каталога.
            match whence {
                0 => {
                    if offset < 0 {
                        return EINVAL;
                    }
                    if let Fd::Dir { idx, .. } = f {
                        *idx = offset as usize;
                    }
                    offset as u64
                }
                _ => ESPIPE,
            }
        }
        _ => ESPIPE,
    });
    match r {
        Ok(code) => code,
        Err(e) => e,
    }
}

fn sys_pread(fd: u64, buf: u64, len: u64, pos: u64) -> u64 {
    // x86_64: pread64(fd, buf, count, pos) — pos целиком в arg4 (r10).
    sys_pread_full(fd, buf, len, pos)
}

fn sys_pread_full(fd: u64, buf: u64, len: u64, pos: u64) -> u64 {
    if buf == 0 || len == 0 {
        return 0;
    }
    if len as usize > MAX_IO {
        return EFAULT;
    }
    let r = with_fd(fd, |f| match f {
        Fd::File { name, dirty, .. } => {
            let data = dirty.clone();
            let name = name.clone();
            let n = if let Some(d) = data {
                if pos as usize >= d.len() {
                    0
                } else {
                    let n = (d.len() - pos as usize).min(len as usize);
                    if n > 0 && !u_write(buf, &d[pos as usize..pos as usize + n]) {
                        return EFAULT;
                    }
                    n
                }
            } else {
                let mut tmp = alloc::vec![0u8; len as usize];
                let n = crate::fs::read_at(&name, pos, &mut tmp).max(0) as usize;
                if n > 0 && !u_write(buf, &tmp[..n]) {
                    return EFAULT;
                }
                n
            };
            n as u64
        }
        _ => EBADF,
    });
    match r {
        Ok(v) => v,
        Err(e) => e,
    }
}

fn sys_pwrite(fd: u64, buf: u64, len: u64, pos: u64) -> u64 {
    if buf == 0 || len == 0 {
        return 0;
    }
    if len as usize > MAX_IO {
        return EFAULT;
    }
    let Some(bytes) = copy_from_user(buf, len as usize) else {
        return EFAULT;
    };
    let Some(end) = (pos as usize).checked_add(bytes.len()) else {
        return EINVAL;
    };
    if end > DIRTY_CAP {
        return EFBIG;
    }
    let r = with_fd(fd, |f| match f {
        Fd::File {
            name, accmode, dirty, ..
        } if *accmode != 0 => {
            if let Err(e) = seed_dirty(name, dirty) {
                return e;
            }
            let data = dirty.as_mut().unwrap();
            if data.len() < end {
                data.resize(end, 0);
            }
            data[pos as usize..end].copy_from_slice(&bytes);
            bytes.len() as u64
        }
        _ => ESPIPE,
    });
    match r {
        Ok(v) => v,
        Err(e) => e,
    }
}

/// Образ файла для отложенной записи. Больше 1 МиБ не держим: иначе close
/// не сотрёт хвост молча, а вернёт ошибку ещё до изменения.
const DIRTY_CAP: usize = 1024 * 1024;

fn seed_dirty(name: &str, dirty: &mut Option<Vec<u8>>) -> Result<(), u64> {
    if dirty.is_some() {
        return Ok(());
    }
    let seeded = match crate::fs::read_canon(name) {
        Some(v) if v.len() > DIRTY_CAP => return Err(EFBIG),
        Some(v) => v,
        None => Vec::new(),
    };
    *dirty = Some(seeded);
    Ok(())
}

fn sys_rwv(fd: u64, iov: u64, iovcnt: u64, write: bool) -> u64 {
    if iovcnt == 0 || iovcnt > 1024 {
        return EINVAL;
    }
    let mut total = 0u64;
    for i in 0..iovcnt {
        let mut raw = [0u8; 16];
        if !u_read(iov + i * 16, &mut raw) {
            return if total > 0 { total } else { EFAULT };
        }
        let base = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let len = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        if len == 0 {
            continue;
        }
        let r = if write {
            sys_write(fd, base, len)
        } else {
            sys_read(fd, base, len)
        };
        if (r as i64) < 0 {
            return if total > 0 { total } else { r };
        }
        total += r;
        if r < len {
            break;
        }
    }
    total
}

fn sys_dup(fd: u64) -> u64 {
    match with_fd(fd, |f| f.clone_fd()) {
        Ok(clone) => {
            let mut slot = Some(clone);
            with_current_fds(|fds| alloc_fd(&mut slot, fds, false)).unwrap_or(EMFILE)
        }
        Err(e) => e,
    }
}

fn sys_dup2(old: u64, new: u64) -> u64 {
    // Совпадение номеров не трогает FD_CLOEXEC. У dup3 это EINVAL.
    if old == new {
        return match with_fd(old, |_| ()) {
            Ok(()) => old,
            Err(e) => e,
        };
    }
    sys_dup3(old, new, 0)
}

fn sys_dup3(old: u64, new: u64, flags: u64) -> u64 {
    const O_CLOEXEC: u64 = 0x80000;
    // Linux смотрит флаги и совпадение номеров раньше fd.
    if flags & !O_CLOEXEC != 0 {
        return EINVAL;
    }
    if old == new {
        return EINVAL;
    }
    if new >= 64 {
        return EMFILE;
    }
    let cloexec = flags & O_CLOEXEC != 0;
    match with_fd(old, |f| f.clone_fd()) {
        Ok(clone) => {
            // Замыкание забирает копию только если таблица есть. Иначе ссылку
            // надо отпустить: Drop у Fd этого не делает.
            let mut slot = Some(clone);
            let placed = with_current_fds(|fds| {
                let clone = slot.take().expect("dup clone");
                place_dup(fds, new, clone, cloexec)
            });
            match placed {
                Ok(prev) => {
                    // Ошибка сброса не отменяет уже выданный номер.
                    if let Some(prev) = prev {
                        let _ = finish_close(prev, new);
                    }
                    new
                }
                Err(e) => {
                    if let Some(left) = slot.take() {
                        release_clone(left);
                    }
                    e
                }
            }
        }
        Err(e) => e,
    }
}

/// Поставить копию на номер `new`. Прежний описатель возвращается вызывающему,
/// чтобы закрыть его уже без лока таблицы.
fn place_dup(fds: &mut Fds, new: u64, clone: Fd, cloexec: bool) -> Option<Fd> {
    let i = new as usize;
    if i >= fds.len() {
        fds.resize(i + 1, None);
    }
    let prev = fds[i].take();
    fds[i] = Some(clone);
    fds.set_cloexec(new, cloexec);
    prev
}

/// Снять лишнюю ссылку, если копия дескриптора так и не встала в таблицу.
fn release_clone(fd: Fd) {
    match fd {
        Fd::Pipe { id, writable } => pipe_close_end(id, writable),
        Fd::Udp { id } => crate::net::udp_close(id),
        Fd::Tcp { id } => crate::net::tcp_close(id),
        Fd::Udp6 { id } => crate::net6::udp_close(id),
        Fd::Tcp6 { id } => crate::net6::tcp_close(id),
        Fd::Epoll { id } => epoll_decref(id),
        _ => {}
    }
}

/// Наименьший свободный номер `>= min`. Пустые щели до `min` не занимаются.
fn dup_at_least(fds: &mut Fds, slot: &mut Option<Fd>, min: u64, cloexec: bool) -> u64 {
    if min >= 64 {
        return EMFILE;
    }
    let start = min as usize;
    for i in start..fds.len() {
        if fds[i].is_none() {
            fds[i] = slot.take();
            fds.set_cloexec(i as u64, cloexec);
            return i as u64;
        }
    }
    while fds.len() < start {
        fds.push(None);
    }
    if fds.len() >= 64 {
        return EMFILE;
    }
    fds.push(slot.take());
    let i = (fds.len() - 1) as u64;
    fds.set_cloexec(i, cloexec);
    i
}

fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> u64 {
    match cmd {
        0 | 1030 => {
            // F_DUPFD и F_DUPFD_CLOEXEC (1030): копия с номером >= arg.
            // Обычный dup бит сбрасывает, CLOEXEC-вариант ставит.
            let cloexec = cmd == 1030;
            match with_fd(fd, |f| f.clone_fd()) {
                Ok(clone) => {
                    let mut slot = Some(clone);
                    let rc = with_current_fds(|fds| dup_at_least(fds, &mut slot, arg, cloexec))
                        .unwrap_or(EMFILE);
                    if let Some(left) = slot.take() {
                        release_clone(left);
                    }
                    rc
                }
                Err(e) => e,
            }
        }
        1 => with_current_fds(|fds| {
            // F_GETFD
            if (fd as usize) >= fds.len() || fds[fd as usize].is_none() {
                return EBADF;
            }
            if fds.is_cloexec(fd) { 1 } else { 0 }
        })
        .unwrap_or(EBADF),
        2 => with_current_fds(|fds| {
            // F_SETFD: ядро хранит только FD_CLOEXEC (бит 0).
            if (fd as usize) >= fds.len() || fds[fd as usize].is_none() {
                return EBADF;
            }
            fds.set_cloexec(fd, arg & 1 != 0);
            0
        })
        .unwrap_or(EBADF),
        3 => {
            // F_GETFL: accmode в младших битах
            with_fd(fd, |f| match f {
                Fd::File { accmode, append, .. } => {
                    (*accmode as u64) | if *append { 0x400 } else { 0 }
                }
                Fd::Dir { .. } => 0,
                Fd::Console { writable } => *writable as u64,
                Fd::Pipe { writable, .. } => *writable as u64,
                Fd::Udp { id } => 2 | if crate::net::udp_nonblock(*id) { 0x800 } else { 0 },
                Fd::Tcp { id } => 1 | if crate::net::tcp_nonblock(*id) { 0x800 } else { 0 },
                Fd::Udp6 { id } => 2 | if crate::net6::udp_nonblock(*id) { 0x800 } else { 0 },
                Fd::Tcp6 { id } => 1 | if crate::net6::tcp_nonblock(*id) { 0x800 } else { 0 },
                Fd::Epoll { .. } => 2,
            })
            .unwrap_or(EBADF)
        }
        4 => 0, // F_SETFL
        _ => 0,
    }
}

fn sys_getdents64(fd: u64, buf: u64, len: u64) -> u64 {
    let r = with_fd(fd, |f| match f {
        Fd::Dir { prefix, idx } => {
            let names = crate::fs::list_dir(prefix);
            let is_root = prefix == "/";
            let mut written = 0u64;
            let mut i = *idx;
            while i < names.len() {
                let name = &names[i];
                // linux_dirent64: ino u64, off u64, reclen u16, type u8, name[] NUL.
                // Тип стоит в байте 18, сразу перед именем. NUL после имени
                // нельзя класть в тот же байт, иначе короткое имя теряет конец.
                let reclen = (19 + name.len() + 1 + 7) & !7;
                if written + reclen as u64 > len {
                    break;
                }
                let full = if is_root {
                    format!("/{}", name)
                } else {
                    format!("{}/{}", prefix, name)
                };
                let d_type = if crate::fs::is_dir(&full) { 4u8 } else { 8u8 }; // DT_DIR / DT_REG
                let mut ent = [0u8; 288];
                ent[0..8].copy_from_slice(&fake_ino(&full).to_le_bytes());
                ent[8..16].copy_from_slice(&((i as u64) + 1).to_le_bytes());
                ent[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
                ent[18] = d_type;
                ent[19..19 + name.len()].copy_from_slice(name.as_bytes());
                if !u_write(buf + written, &ent[..reclen]) {
                    return if written == 0 { EFAULT } else { written };
                }
                written += reclen as u64;
                i += 1;
            }
            *idx = i;
            written
        }
        _ => EBADF,
    });
    match r {
        Ok(v) => v,
        Err(e) => e,
    }
}

fn sys_pipe(fds_ptr: u64, flags: u64) -> u64 {
    const O_CLOEXEC: u64 = 0x80000;
    if fds_ptr == 0 {
        return EFAULT;
    }
    // O_NONBLOCK у канала нет: не делаем вид, что флаг принят.
    if flags & !O_CLOEXEC != 0 {
        return EINVAL;
    }
    let (r, w) = new_pipe(flags & O_CLOEXEC != 0);
    let mut raw = [0u8; 8];
    raw[0..4].copy_from_slice(&(r as u32).to_le_bytes());
    raw[4..8].copy_from_slice(&(w as u32).to_le_bytes());
    if !u_write(fds_ptr, &raw) {
        return EFAULT;
    }
    0
}

fn sys_poll(fds: u64, nfds: u64, timeout: u64) -> u64 {
    if nfds == 0 || nfds > 64 {
        return EINVAL;
    }
    let deadline = if timeout > 0 {
        Some(crate::interrupts::uptime_ms() + timeout)
    } else {
        None
    };
    loop {
        let mut ready = 0u64;
        for i in 0..nfds {
            let mut raw = [0u8; 8];
            if !u_read(fds + i * 8, &mut raw) {
                return EFAULT;
            }
            let fd = i32::from_le_bytes(raw[0..4].try_into().unwrap());
            let events = i16::from_le_bytes(raw[4..6].try_into().unwrap());
            if fd < 0 {
                continue;
            }
            let revents = poll_ready(fd as u64, events);
            if !u_write(fds + i * 8 + 6, &revents.to_le_bytes()) {
                return EFAULT;
            }
            if revents != 0 {
                ready += 1;
            }
        }
        if ready > 0 {
            return ready;
        }
        match deadline {
            Some(d) if crate::interrupts::uptime_ms() >= d => return 0,
            _ => {
                if crate::signal::pending_interrupts() && !crate::signal::keep_waiting() {
                    return EINTR;
                }
                x86_64::instructions::hlt();
            }
        }
    }
}

fn poll_ready(fd: u64, events: i16) -> i16 {
    match with_current_fds(|fds| ready_locked(fds, fd, events, 0)) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

/// Готовность fd по уже захваченной таблице. `depth` обрывает цикл epoll→epoll.
fn ready_locked(fds: &[Option<Fd>], fd: u64, events: i16, depth: u8) -> i16 {
    const POLLIN: i16 = 1;
    const POLLOUT: i16 = 4;
    let Some(f) = fds.get(fd as usize).and_then(|x| x.as_ref()) else {
        return 0;
    };
    let mut revents = 0i16;
    match f {
        Fd::Console { writable } => {
            if !writable && events & POLLIN != 0 && crate::input::with_input(|q| q.len() > 0) {
                revents |= POLLIN;
            }
            if *writable && events & POLLOUT != 0 {
                revents |= POLLOUT;
            }
        }
        Fd::File { .. } | Fd::Dir { .. } => {
            revents |= events & (POLLIN | POLLOUT);
        }
        Fd::Pipe { id, writable } => {
            let pipes = PIPES.lock();
            if let Some(Some(p)) = pipes.get(*id) {
                if !writable && p.len > 0 && events & POLLIN != 0 {
                    revents |= POLLIN;
                }
                if *writable && events & POLLOUT != 0 {
                    revents |= POLLOUT;
                }
            }
        }
        Fd::Udp { id } => {
            if events & POLLIN != 0 && crate::net::udp_pending(*id) {
                revents |= POLLIN;
            }
            if events & POLLOUT != 0 {
                revents |= POLLOUT;
            }
        }
        Fd::Tcp { id } => {
            if events & POLLIN != 0 && crate::net::tcp_pending(*id) {
                revents |= POLLIN;
            }
            if events & POLLOUT != 0 {
                revents |= POLLOUT;
            }
        }
        Fd::Udp6 { id } => {
            if events & POLLIN != 0 && crate::net6::udp_pending(*id) {
                revents |= POLLIN;
            }
            if events & POLLOUT != 0 {
                revents |= POLLOUT;
            }
        }
        Fd::Tcp6 { id } => {
            if events & POLLIN != 0 && crate::net6::tcp_pending(*id) {
                revents |= POLLIN;
            }
            if events & POLLOUT != 0 {
                revents |= POLLOUT;
            }
        }
        Fd::Epoll { id } => {
            if depth >= 2 || events & POLLIN == 0 {
                return 0;
            }
            let watched: Vec<(u64, i16)> = with_epolls(|tab| {
                let Some(set) = tab.get(*id).and_then(|s| s.as_ref()) else {
                    return Vec::new();
                };
                set.items
                    .iter()
                    .flatten()
                    .map(|it| (it.fd, (it.events & 5) as i16))
                    .collect()
            });
            for (wfd, want) in watched {
                if wfd == fd {
                    continue;
                }
                if ready_locked(fds, wfd, want, depth + 1) != 0 {
                    return POLLIN;
                }
            }
        }
    }
    revents
}

// ---- epoll ----
//
// Level-triggered по умолчанию; `EPOLLET` — edge: доставляется фронт
// «не готово → готово» по снимку прошлой готовности. Интерес — номер fd
// в таблице задачи, не описание файла: close этого номера снимает интерес,
// даже если остался dup. Больше 64 наборов или 128 интересов — ENOMEM.
// Таймаут — миллисекунды, как int у Linux, включая -1. `epoll_pwait`
// ставит временную маску сигналов на время ожидания. poll/select по
// самому epoll-fd видят POLLIN, когда готов хотя бы один интерес.

const EPOLL_MAX_SETS: usize = 64;
const EPOLL_MAX_ITEMS: usize = 128;
const EPOLLIN: u32 = 1;
const EPOLLET: u32 = 0x8000_0000;
const EPOLLOUT: u32 = 4;
const EPOLL_CLOEXEC: u64 = 0x80000;

#[derive(Clone, Copy)]
struct EpInterest {
    fd: u64,
    events: u32,
    data: u64,
}

struct EpollSet {
    refs: usize,
    items: [Option<EpInterest>; EPOLL_MAX_ITEMS],
    /// Последняя наблюдавшаяся готовность по слоту: для EPOLLET доставляем
    /// только фронт 0 → готово.
    last: [u32; EPOLL_MAX_ITEMS],
}

static EPOLLS: Mutex<Vec<Option<EpollSet>>> = Mutex::new(Vec::new());

fn with_epolls<R>(f: impl FnOnce(&mut Vec<Option<EpollSet>>) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut EPOLLS.lock()))
}

fn arg_fd(raw: u64) -> Result<u64, u64> {
    let fd = raw as i32;
    if fd < 0 {
        Err(EBADF)
    } else {
        Ok(fd as u64)
    }
}

fn epoll_alloc() -> Result<usize, u64> {
    with_epolls(|tab| {
        if tab.iter().filter(|s| s.is_some()).count() >= EPOLL_MAX_SETS {
            return Err(ENOMEM);
        }
        let set = EpollSet {
            refs: 1,
            items: [None; EPOLL_MAX_ITEMS],
            last: [0; EPOLL_MAX_ITEMS],
        };
        if let Some(i) = tab.iter().position(|s| s.is_none()) {
            tab[i] = Some(set);
            Ok(i)
        } else {
            tab.push(Some(set));
            Ok(tab.len() - 1)
        }
    })
}

fn epoll_addref(id: usize) {
    with_epolls(|tab| {
        if let Some(Some(set)) = tab.get_mut(id) {
            set.refs += 1;
        }
    });
}

fn epoll_decref(id: usize) {
    with_epolls(|tab| {
        if let Some(set) = tab.get_mut(id).and_then(|s| s.as_mut()) {
            set.refs = set.refs.saturating_sub(1);
            if set.refs == 0 {
                tab[id] = None;
            }
        }
    });
}

/// Снимает ссылку на набор и все интересы, смотревшие на номер `fd_num`.
fn epoll_on_close(ep_id: Option<usize>, fd_num: u64) {
    with_epolls(|tab| {
        if let Some(id) = ep_id {
            if let Some(set) = tab.get_mut(id).and_then(|s| s.as_mut()) {
                set.refs = set.refs.saturating_sub(1);
                if set.refs == 0 {
                    tab[id] = None;
                }
            }
        }
        for set in tab.iter_mut().flatten() {
            for it in set.items.iter_mut() {
                if it.is_some_and(|x| x.fd == fd_num) {
                    *it = None;
                }
            }
        }
    });
}

fn sys_epoll_create(flags: u64) -> u64 {
    if flags & !EPOLL_CLOEXEC != 0 {
        return EINVAL;
    }
    let id = match epoll_alloc() {
        Ok(id) => id,
        Err(e) => return e,
    };
    let mut slot = Some(Fd::Epoll { id });
    let cloexec = flags & EPOLL_CLOEXEC != 0;
    match with_current_fds(|fds| alloc_fd(&mut slot, fds, cloexec)) {
        Ok(fd) if slot.is_none() => fd,
        Ok(err) => {
            epoll_decref(id);
            err
        }
        Err(e) => {
            epoll_decref(id);
            e
        }
    }
}

fn sys_epoll_ctl(epfd: u64, op: u64, fd: u64, event: u64) -> u64 {
    const ADD: u64 = 1;
    const DEL: u64 = 2;
    const MOD: u64 = 3;
    let epfd = match arg_fd(epfd) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    let fd = match arg_fd(fd) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    if epfd == fd || (op != ADD && op != DEL && op != MOD) {
        return EINVAL;
    }
    let id = match with_current_fds(|fds| {
        let ep = match fds.get(epfd as usize).and_then(|x| x.as_ref()) {
            Some(Fd::Epoll { id }) => *id,
            Some(_) => return Err(EINVAL),
            None => return Err(EBADF),
        };
        if fds.get(fd as usize).and_then(|x| x.as_ref()).is_none() {
            return Err(EBADF);
        }
        Ok(ep)
    }) {
        Ok(Ok(id)) => id,
        Ok(Err(e)) | Err(e) => return e,
    };
    let interest = if op == DEL {
        None
    } else {
        if event == 0 {
            return EFAULT;
        }
        let mut raw = [0u8; 12];
        if !u_read(event, &mut raw) {
            return EFAULT;
        }
        Some(EpInterest {
            fd,
            events: u32::from_le_bytes(raw[0..4].try_into().unwrap()),
            data: u64::from_le_bytes(raw[4..12].try_into().unwrap()),
        })
    };
    with_epolls(|tab| {
        let Some(set) = tab.get_mut(id).and_then(|s| s.as_mut()) else {
            return EBADF;
        };
        let slot = set
            .items
            .iter()
            .position(|it| it.is_some_and(|x| x.fd == fd));
        match op {
            ADD => {
                if slot.is_some() {
                    return EEXIST;
                }
                let Some(free) = set.items.iter().position(|it| it.is_none()) else {
                    return ENOMEM;
                };
                set.items[free] = interest;
                // ET считает регистрацию фронтом: сбрасываем прошлое
                // состояние, чтобы готовый fd дал событие.
                set.last[free] = 0;
                0
            }
            DEL => {
                let Some(i) = slot else { return ENOENT };
                set.items[i] = None;
                0
            }
            MOD => {
                let Some(i) = slot else { return ENOENT };
                set.items[i] = interest;
                set.last[i] = 0;
                0
            }
            _ => EINVAL,
        }
    })
}

fn sys_epoll_wait(epfd: u64, events_ptr: u64, maxevents: u64, timeout: u64) -> u64 {
    epoll_wait_core(epfd, events_ptr, maxevents, timeout)
}

/// `epoll_pwait`: ждёт с временной маской сигналов (SIGKILL/SIGSTOP
/// разблокируемы, как в Linux: маска просто срезает биты).
fn sys_epoll_pwait(
    epfd: u64,
    events_ptr: u64,
    maxevents: u64,
    timeout: u64,
    sigmask: u64,
    sigsz: u64,
) -> u64 {
    if sigsz != 8 {
        return EINVAL;
    }
    let mut saved = None;
    if sigmask != 0 {
        let mut raw = [0u8; 8];
        if !u_read(sigmask, &mut raw) {
            return EFAULT;
        }
        // bit(sig) = 1 << (sig-1): SIGKILL 9, SIGSTOP 19.
        let mask = u64::from_le_bytes(raw) & !((1 << 8) | (1 << 18));
        saved = task::with_current_task(|t| {
            let old = t.signals.blocked_mask();
            t.signals.set_blocked_mask(mask);
            old
        });
    }
    let rc = epoll_wait_core(epfd, events_ptr, maxevents, timeout);
    if let Some(old) = saved {
        task::with_current_task(|t| t.signals.set_blocked_mask(old));
    }
    rc
}

fn epoll_wait_core(epfd: u64, events_ptr: u64, maxevents: u64, timeout: u64) -> u64 {
    let epfd = match arg_fd(epfd) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    let max = maxevents as i32;
    if max < 1 || max > EPOLL_MAX_ITEMS as i32 {
        return EINVAL;
    }
    let max = max as usize;
    // Таймаут — int в младших 32 битах: userspace кладёт -1 через mov r10d.
    let t = timeout as i32;
    if t < -1 {
        return EINVAL;
    }
    let deadline = if t > 0 {
        Some(crate::interrupts::uptime_ms().saturating_add(t as u64))
    } else {
        None
    };
    loop {
        let id = match with_current_fds(|fds| match fds.get(epfd as usize).and_then(|x| x.as_ref()) {
            Some(Fd::Epoll { id }) => Ok(*id),
            Some(_) => Err(EINVAL),
            None => Err(EBADF),
        }) {
            Ok(Ok(id)) => id,
            Ok(Err(e)) | Err(e) => return e,
        };
        let snap = with_epolls(|tab| {
            tab.get(id)
                .and_then(|s| s.as_ref())
                .map(|set| (set.items, set.last))
        });
        let Some((items, mut last)) = snap else {
            return EBADF;
        };
        let mut n = 0usize;
        let mut evs = [0u32; EPOLL_MAX_ITEMS];
        let mut data = [0u64; EPOLL_MAX_ITEMS];
        for (i, it) in items.iter().enumerate() {
            let Some(it) = it else {
                continue;
            };
            let want = (it.events & (EPOLLIN | EPOLLOUT)) as i16;
            let re = poll_ready(it.fd, want);
            let mut got = 0u32;
            if re & 1 != 0 {
                got |= EPOLLIN;
            }
            if re & 4 != 0 {
                got |= EPOLLOUT;
            }
            // Состояние обновляем всегда; EPOLLET доставляет только фронт
            // «не готово → готово».
            let edge = got != last[i];
            last[i] = got;
            if got != 0 && (it.events & EPOLLET == 0 || edge) {
                evs[n] = got;
                data[n] = it.data;
                n += 1;
                if n == max {
                    break;
                }
            }
        }
        with_epolls(|tab| {
            if let Some(set) = tab.get_mut(id).and_then(|s| s.as_mut()) {
                set.last = last;
            }
        });
        let expired = match deadline {
            Some(d) => crate::interrupts::uptime_ms() >= d,
            None => false,
        };
        if n > 0 || t == 0 || expired {
            if n == 0 {
                return 0;
            }
            if events_ptr == 0 {
                return EFAULT;
            }
            for i in 0..n {
                let mut raw = [0u8; 12];
                raw[0..4].copy_from_slice(&evs[i].to_le_bytes());
                raw[4..12].copy_from_slice(&data[i].to_le_bytes());
                if !u_write(events_ptr + (i as u64) * 12, &raw) {
                    return if i == 0 { EFAULT } else { i as u64 };
                }
            }
            return n as u64;
        }
        if crate::signal::pending_interrupts() && !crate::signal::keep_waiting() {
            return EINTR;
        }
        x86_64::instructions::hlt();
    }
}

fn sys_select(nfds: u64, readfds: u64, _writefds: u64, _exceptfds: u64, timeout: u64) -> u64 {
    // Минимальный select: readfds-консоль, блокирующий.
    let deadline = if timeout > 0 {
        Some(crate::interrupts::uptime_ms() + timeout)
    } else {
        None
    };
    loop {
        let mut ready = 0u64;
        for fd in 0..nfds.min(1024) {
            if readfds != 0 {
                let mut byte = [0u8; 1];
                if !u_read(readfds + fd / 8, &mut byte) {
                    return EFAULT;
                }
                let bit = (byte[0] >> (fd % 8)) & 1;
                if bit == 1 {
                    let r = poll_ready(fd, 1);
                    if r & 1 != 0 {
                        ready += 1;
                    } else {
                        byte[0] &= !(1 << (fd % 8));
                        if !u_write(readfds + fd / 8, &byte) {
                            return EFAULT;
                        }
                    }
                }
            }
        }
        if ready > 0 {
            return ready;
        }
        match deadline {
            Some(d) if crate::interrupts::uptime_ms() >= d => return 0,
            _ => {
                if crate::signal::pending_interrupts() && !crate::signal::keep_waiting() {
                    return EINTR;
                }
                x86_64::instructions::hlt();
            }
        }
    }
}

fn sys_reboot(magic1: u64, magic2: u64, cmd: u64) -> u64 {
    const MAGIC1: u64 = 0xfee1dead;
    const MAGIC2: u64 = 672274793;
    const RESTART: u64 = 0x01234567;
    const HALT: u64 = 0xCDEF0123;
    const POWER_OFF: u64 = 0x4321FEDC;
    const RESTART2: u64 = 0xA1B2C3D4;
    if magic1 != MAGIC1 || magic2 != MAGIC2 {
        return EINVAL;
    }
    crate::ext2::sync();
    crate::serial_println!("[reboot] cmd {:#x}", cmd);
    unsafe {
        match cmd {
            POWER_OFF => {
                let mut port = x86_64::instructions::port::Port::<u16>::new(0x604);
                port.write(0x2000);
            }
            HALT => {
                loop {
                    x86_64::instructions::hlt();
                }
            }
            RESTART | RESTART2 => {
                let mut status = x86_64::instructions::port::Port::<u8>::new(0x64);
                for _ in 0..100_000 {
                    if status.read() & 0x02 == 0 {
                        break;
                    }
                }
                status.write(0xFE);
            }
            _ => return EINVAL,
        }
    }
    loop {
        x86_64::instructions::hlt();
    }
}

fn sys_uname(buf: u64) -> u64 {
    if buf == 0 {
        return EFAULT;
    }
    let fields = ["rudra", "rudra", "1.0.1", "#1 rudra 1.0.1", "x86_64", "(none)"];
    let mut raw = [0u8; 6 * 65];
    for (i, f) in fields.iter().enumerate() {
        let start = i * 65;
        raw[start..start + f.len()].copy_from_slice(f.as_bytes());
    }
    if !u_write(buf, &raw) {
        return EFAULT;
    }
    0
}

fn sys_wait4(pid: u64, status: u64, options: u64) -> u64 {
    let me = task::current_tid();
    let wnohang = options & 1 != 0;
    loop {
        let want = if pid == u64::MAX { 0 } else { pid };
        if let Some((tid, code, term)) = task::reap_child(me, want) {
            if status != 0 {
                // Сигнал — младшие 7 бит (WIFSIGNALED). Иначе W_EXITCODE.
                let word = if term != 0 {
                    u32::from(term)
                } else {
                    ((code as u32) << 8) & 0xFF00
                };
                if !u_write(status, &word.to_le_bytes()) {
                    return EFAULT;
                }
            }
            return tid;
        }
        if !task::has_children(me) {
            return ECHILD;
        }
        if wnohang {
            return 0;
        }
        // Зомби забираем выше. Пойманный сигнал без зомби — EINTR.
        // SIGCHLD по умолчанию сюда не попадает: он не interrupts().
        if crate::signal::pending_interrupts() && !crate::signal::keep_waiting() {
            return EINTR;
        }
        x86_64::instructions::hlt();
    }
}

const ECHILD: u64 = (-(10i64)) as u64;

/// ioctl: для консоли — TCGETS (псевдо-termios) и TIOCGWINSZ; остальное 0.
fn sys_ioctl(fd: u64, request: u64, arg: u64) -> u64 {
    const TCGETS: u64 = 0x5401;
    const TCSETS: u64 = 0x5402;
    const TCSETSW: u64 = 0x5403;
    const TCSETSF: u64 = 0x5404;
    const TIOCGWINSZ: u64 = 0x5413;

    let is_console = with_fd(fd, |f| matches!(f, Fd::Console { .. }))
        .unwrap_or(false);
    if !is_console {
        return ENOTTY;
    }
    match request {
        TCGETS => {
            if arg == 0 {
                return EFAULT;
            }
            // struct termios (36 байт в kernel ABI): iflag/oflag/cflag/lflag +
            // line + cc[32]. Канонический режим + эхо, как у нормального tty.
            let mut raw = [0u8; 36];
            raw[0..4].copy_from_slice(&0x500u32.to_le_bytes());
            raw[4..8].copy_from_slice(&0x5u32.to_le_bytes());
            raw[8..12].copy_from_slice(&0xBFu32.to_le_bytes());
            raw[12..16].copy_from_slice(&0x8A3Bu32.to_le_bytes());
            if !u_write(arg, &raw) {
                return EFAULT;
            }
            0
        }
        TCSETS | TCSETSW | TCSETSF => 0, // принимаем, игнорируем (raw-mode no-op)
        TIOCGWINSZ => {
            if arg == 0 {
                return EFAULT;
            }
            // winsize: rows, cols, xpixels, ypixels (u16 x4).
            let vals = [61u16, 160u16, 1280u16, 800u16];
            let mut raw = [0u8; 8];
            for (i, v) in vals.iter().enumerate() {
                raw[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
            }
            if !u_write(arg, &raw) {
                return EFAULT;
            }
            0
        }
        _ => 0, // неизвестный ioctl консоли: мягкий успех
    }
}

fn sys_futex(uaddr: u64, op: u64, val: u64, val2: u64, uaddr2: u64, val3: u64) -> u64 {
    const FUTEX_WAIT: u64 = 0;
    const FUTEX_WAKE: u64 = 1;
    const FUTEX_REQUEUE: u64 = 3;
    const FUTEX_CMP_REQUEUE: u64 = 4;
    match op & 0x7f {
        FUTEX_WAIT => futex_wait(uaddr, val as u32),
        FUTEX_WAKE => futex_wake(uaddr, val as u32),
        // Разбудить val ждущих на uaddr, остальных (до val2) переставить на
        // uaddr2. У CMP_REQUEUE val3 — ожидаемое слово: не сошлось — EAGAIN.
        FUTEX_REQUEUE => futex_requeue(uaddr, val as u32, val2 as u32, uaddr2),
        FUTEX_CMP_REQUEUE => futex_cmp_requeue(uaddr, val as u32, val2 as u32, uaddr2, val3 as u32),
        _ => ENOSYS,
    }
}

struct FutexWait {
    addr: u64,
    val: u32,
    /// Проверять слово по адресу перед блокировкой. У переставленных
    /// (CMP_REQUEUE) — false: они спят на новом адресе до явного WAKE.
    check: bool,
    woke: bool,
}

const FUTEX_SLOTS: usize = 32;
static FUTEX_WAITERS: Mutex<[Option<FutexWait>; FUTEX_SLOTS]> = Mutex::new([
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
]);

fn with_futex<R>(f: impl FnOnce(&mut [Option<FutexWait>; FUTEX_SLOTS]) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut FUTEX_WAITERS.lock()))
}

fn futex_word(addr: u64) -> Result<u32, u64> {
    if addr == 0 || addr % 4 != 0 {
        return Err(EINVAL);
    }
    let mut raw = [0u8; 4];
    if !u_read(addr, &mut raw) {
        return Err(EFAULT);
    }
    Ok(u32::from_le_bytes(raw))
}

fn futex_wait(addr: u64, val: u32) -> u64 {
    let slot = with_futex(|waiters| {
        let cur = futex_word(addr)?;
        if cur != val {
            return Err(EAGAIN);
        }
        let idx = waiters.iter().position(|w| w.is_none());
        let Some(idx) = idx else {
            return Err(ENOMEM);
        };
        waiters[idx] = Some(FutexWait { addr, val, check: true, woke: false });
        Ok(idx)
    });
    let idx = match slot {
        Ok(i) => i,
        Err(e) => return e,
    };
    loop {
        let done = with_futex(|waiters| {
            let Some(w) = waiters[idx].as_mut() else {
                return Some(0);
            };
            if w.woke {
                waiters[idx] = None;
                return Some(0);
            }
            if !w.check {
                // Переставлен CMP_REQUEUE: блокируемся до явного WAKE.
                return None;
            }
            match futex_word(w.addr) {
                Ok(cur) if cur != w.val => {
                    waiters[idx] = None;
                    Some(EAGAIN)
                }
                Ok(_) => None,
                Err(e) => {
                    waiters[idx] = None;
                    Some(e)
                }
            }
        });
        if let Some(rc) = done {
            return rc;
        }
        if crate::signal::pending_interrupts() && !crate::signal::keep_waiting() {
            with_futex(|waiters| {
                waiters[idx] = None;
            });
            return EINTR;
        }
        x86_64::instructions::hlt();
    }
}

/// Разбудить до `n` ждущих на `addr`. Считает, скольких пометили.
pub fn futex_wake(addr: u64, n: u32) -> u64 {
    if n == 0 || addr == 0 {
        return 0;
    }
    with_futex(|waiters| {
        let mut woke = 0u32;
        for slot in waiters.iter_mut().flatten() {
            if slot.addr == addr && !slot.woke {
                slot.woke = true;
                woke += 1;
                if woke == n {
                    break;
                }
            }
        }
        u64::from(woke)
    })
}

/// FUTEX_REQUEUE (op 3) — как CMP_REQUEUE, но без сравнения слова.
fn futex_requeue(addr: u64, nr_wake: u32, nr_requeue: u32, addr2: u64) -> u64 {
    futex_requeue_common(addr, nr_wake, nr_requeue, addr2, None)
}

/// FUTEX_CMP_REQUEUE (op 4): слово по `addr` должно быть `val3`. Разбудить до
/// `nr_wake` ждущих на `addr`, до `nr_requeue` остальных переставить на
/// `addr2` (они просыпаются от FUTEX_WAKE на новом адресе). Возвращает
/// woken + requeued.
fn futex_cmp_requeue(addr: u64, nr_wake: u32, nr_requeue: u32, addr2: u64, val3: u32) -> u64 {
    futex_requeue_common(addr, nr_wake, nr_requeue, addr2, Some(val3))
}

fn futex_requeue_common(
    addr: u64,
    nr_wake: u32,
    nr_requeue: u32,
    addr2: u64,
    cmp: Option<u32>,
) -> u64 {
    if addr == 0 || addr % 4 != 0 || addr2 == 0 || addr2 % 4 != 0 {
        return EINVAL;
    }
    if let Some(val3) = cmp {
        let cur = match futex_word(addr) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if cur != val3 {
            return EAGAIN;
        }
    }
    with_futex(|waiters| {
        let mut moved = 0u32;
        for slot in waiters.iter_mut().flatten() {
            if slot.addr != addr || slot.woke {
                continue;
            }
            if moved < nr_wake {
                slot.woke = true;
                moved += 1;
            } else if moved - nr_wake < nr_requeue {
                slot.addr = addr2;
                slot.check = false;
                moved += 1;
            } else {
                break;
            }
        }
        u64::from(moved)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn cloexec_bit_follows_the_fd_not_the_dup() {
        crate::serial_print!("test cloexec_bit_follows_the_fd_not_the_dup... ");
        let mut fds = Fds::new(alloc::vec![
            Some(Fd::console(false)),
            Some(Fd::console(true)),
            Some(Fd::console(true)),
        ]);
        assert!(!fds.is_cloexec(0));
        fds.set_cloexec(1, true);
        assert!(fds.is_cloexec(1));
        assert_eq!(fds.cloexec_bits(), 1u64 << 1);

        let mut slot = Some(Fd::console(false));
        let n = alloc_fd(&mut slot, &mut fds, true);
        assert_eq!(n, 3);
        assert!(slot.is_none());
        assert!(fds.is_cloexec(3));

        // fork копирует биты. Консоль ссылок не считает.
        let child = fds.clone_for_fork();
        assert!(child.is_cloexec(1));
        assert!(child.is_cloexec(3));
        assert!(!child.is_cloexec(0));

        // Повторная выдача дырки берёт флаг этого вызова, не старый бит.
        fds[3] = None;
        fds.set_cloexec(3, true);
        let mut slot = Some(Fd::console(true));
        let again = alloc_fd(&mut slot, &mut fds, false);
        assert_eq!(again, 3);
        assert!(!fds.is_cloexec(3));

        // F_DUPFD_CLOEXEC занимает наименьший номер не ниже запрошенного.
        let mut slot = Some(Fd::console(false));
        let high = dup_at_least(&mut fds, &mut slot, 5, true);
        assert_eq!(high, 5);
        assert!(fds.is_cloexec(5));
        assert!(fds[4].is_none());
        assert!(!fds.is_cloexec(4));

        let mut slot = Some(Fd::console(false));
        assert_eq!(dup_at_least(&mut fds, &mut slot, 64, true), EMFILE);
        assert!(slot.is_some());

        // exec закрывает ровно помеченные номера.
        let bits = fds.cloexec_bits();
        let mut marked = [false; 64];
        for i in 0..64 {
            if bits & (1u64 << i) != 0 {
                marked[i] = true;
            }
        }
        assert!(marked[1]);
        assert!(marked[5]);
        assert!(!marked[0]);
        assert!(!marked[2]);
        assert!(!marked[3]);
        crate::serial_println!("[ok]");
    }

    #[test_case]
    fn dup3_sets_cloexec_and_rejects_before_the_fd() {
        crate::serial_print!("test dup3_sets_cloexec_and_rejects_before_the_fd... ");
        // Чужой бит и old == new — EINVAL до поиска fd. Раннер — не задача.
        assert_eq!(sys_dup3(0, 1, 1), EINVAL);
        assert_eq!(sys_dup3(0, 1, 0x800), EINVAL);
        assert_eq!(sys_dup3(0, 0, 0), EINVAL);
        assert_eq!(sys_dup3(4, 4, 0x80000), EINVAL);
        assert_eq!(sys_dup3(99, 64, 1), EINVAL);
        assert_eq!(sys_dup3(99, 64, 0), EMFILE);
        assert_eq!(sys_dup3(99, 64, 0x80000), EMFILE);
        // Верные флаги доходят до таблицы. Без задачи это EPERM.
        assert_eq!(sys_dup3(0, 1, 0), EPERM);
        assert_eq!(sys_dup3(0, 1, 0x80000), EPERM);

        let mut fds = Fds::new(alloc::vec![
            Some(Fd::console(false)),
            Some(Fd::console(true)),
        ]);
        fds.set_cloexec(0, true);
        fds.set_cloexec(1, true);
        let prev = place_dup(&mut fds, 1, Fd::console(false), true);
        assert!(matches!(prev, Some(Fd::Console { writable: true })));
        assert!(fds.is_cloexec(0));
        assert!(fds.is_cloexec(1));
        // Флаги 0 сбрасывают бит нового номера. Бит источника остаётся.
        let prev = place_dup(&mut fds, 1, Fd::console(false), false);
        assert!(prev.is_some());
        assert!(fds.is_cloexec(0));
        assert!(!fds.is_cloexec(1));
        let prev = place_dup(&mut fds, 3, Fd::console(true), true);
        assert!(prev.is_none());
        assert!(fds[2].is_none());
        assert!(!fds.is_cloexec(2));
        assert!(fds.is_cloexec(3));

        // Вытесненный конец канала закрывается так же, как close.
        let id = {
            let mut pipes = PIPES.lock();
            pipes.push(Some(PipeChan {
                ring: Box::new([0u8; PIPE_CAP]),
                head: 0,
                len: 0,
                readers: 1,
                writers: 1,
            }));
            pipes.len() - 1
        };
        let prev = place_dup(&mut fds, 1, Fd::Pipe { id, writable: false }, false);
        assert!(matches!(prev, Some(Fd::Console { .. })));
        let prev = place_dup(&mut fds, 1, Fd::console(false), false).expect("pipe");
        assert_eq!(finish_close(prev, 63), 0);
        {
            let pipes = PIPES.lock();
            let p = pipes[id].as_ref().expect("chan");
            assert_eq!(p.readers, 0);
            assert_eq!(p.writers, 1);
        }
        assert_eq!(finish_close(Fd::Pipe { id, writable: true }, 63), 0);
        assert!(PIPES.lock()[id].is_none());
        crate::serial_println!("[ok]");
    }

    #[test_case]
    fn accept4_rejects_unknown_flags_before_the_fd() {
        crate::serial_print!("test accept4_rejects_unknown_flags_before_the_fd... ");
        // Чужой бит — EINVAL до поиска fd. Раннер — не задача.
        assert_eq!(sys_accept(0, 0, 0, 1), EINVAL);
        assert_eq!(sys_accept(0, 0, 0, 0x800 | 0x80000 | 1), EINVAL);
        // Верные флаги доходят до таблицы. Без задачи это EPERM, не разбор fd.
        assert_eq!(sys_accept(0, 0, 0, 0), EPERM);
        assert_eq!(sys_accept(0, 0, 0, 0x800), EPERM);
        assert_eq!(sys_accept(0, 0, 0, 0x80000), EPERM);
        assert_eq!(sys_accept(0, 0, 0, 0x800 | 0x80000), EPERM);
        crate::serial_println!("[ok]");
    }
}
