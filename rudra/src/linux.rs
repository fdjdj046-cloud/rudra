//! Слой совместимости с Linux ABI: запуск статических Linux-бинарников
//! (glibc/musl) без перекомпиляции.
//!
//! Реализовано подмножество syscall'ов x86_64: файловый ввод-вывод поверх
//! ext2 (если смонтирован) или RFS2 (open/openat/read/write/close/lseek/
//! dup2/fcntl), каталоги (getdents64/stat/newfstatat/statx/mkdir/rmdir/
//! unlink/rename/chdir/getcwd), память (brk/mmap/munmap/mprotect), процессы
//! (clone/fork/execve/wait4/exit) и pthreads (clone с CLONE_VM, futex,
//! arch_prctl, set_tid_address/robust_list), pipe/pipe2, poll, время,
//! uname, reboot, getrandom и мелочь.
//!
//! Не поддержано: сокеты, доставка сигналов, файловые маппинги (mmap файла →
//! ENODEV), настоящие блокировки (futex WAIT — spin с hlt; SMP нет).
//! `link` копирует байты, `symlink` пишет цель как содержимое файла.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
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
    EPERM = 1, ENOENT = 2, EINTR = 4, EIO = 5, ENOMEM = 12, EFAULT = 14,
    EBUSY = 16, EEXIST = 17, ENODEV = 19, ENOTDIR = 20, EISDIR = 21,
    EINVAL = 22, ENFILE = 23, EMFILE = 24, ENOTTY = 25, EFBIG = 27,
    ENOSPC = 28, ESPIPE = 29, EROFS = 30, EMLINK = 31, EPIPE = 32,
    ERANGE = 34, ENOSYS = 38, ENOTEMPTY = 39, ELOOP = 40, EWOULDBLOCK = 11,
    E2BIG = 7, ENOEXEC = 8,
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
            other => other.clone(),
        }
    }
}

fn alloc_fd(slot: &mut Option<Fd>, fds: &mut Vec<Option<Fd>>) -> u64 {
    for (i, f) in fds.iter_mut().enumerate() {
        if f.is_none() {
            *f = slot.take();
            return i as u64;
        }
    }
    if fds.len() >= 64 {
        return EMFILE;
    }
    fds.push(slot.take());
    (fds.len() - 1) as u64
}

fn with_current_fds<R>(f: impl FnOnce(&mut Vec<Option<Fd>>) -> R) -> Result<R, u64> {
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

fn new_pipe() -> (u64, u64) {
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
        let rfd = alloc_fd(&mut r, fds);
        let mut w = Some(Fd::Pipe { id, writable: true });
        let wfd = alloc_fd(&mut w, fds);
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
        let b = crate::input::INPUT_QUEUE.lock().pop();
        if let Some(b) = b {
            return b;
        }
        core::hint::spin_loop();
    }
}

// ---- Пути ----

fn task_resolve(path: &str) -> Option<String> {
    let cwd = task::with_current_task(|t| t.cwd.clone()).unwrap_or_else(|| String::from("/"));
    crate::fs::resolve(&cwd, path)
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
fn write_stat(buf: u64, size: u64, mode: u32, nlink: u64) -> bool {
    if buf == 0 {
        return false;
    }
    let now = (crate::interrupts::uptime_ms() / 1000) as u64;
    let mut st = [0u8; 144];
    st[0..8].copy_from_slice(&8u64.to_le_bytes());
    st[8..16].copy_from_slice(&fake_ino("stat").to_le_bytes());
    st[16..24].copy_from_slice(&nlink.to_le_bytes());
    st[24..28].copy_from_slice(&mode.to_le_bytes());
    st[28..32].copy_from_slice(&1000u32.to_le_bytes());
    st[32..36].copy_from_slice(&1000u32.to_le_bytes());
    st[48..56].copy_from_slice(&size.to_le_bytes());
    st[56..64].copy_from_slice(&4096u64.to_le_bytes());
    st[64..72].copy_from_slice(&((size + 511) / 512).to_le_bytes());
    for off in [72, 88, 104] {
        st[off..off + 8].copy_from_slice(&now.to_le_bytes());
    }
    u_write(buf, &st)
}

fn stat_of(path: &str) -> Option<(u64, u32, u64)> {
    if crate::fs::is_dir(path) {
        Some((0, S_IFDIR | 0o755, crate::fs::nlink_of(path).max(2)))
    } else if crate::fs::exists(path) {
        let sz = crate::fs::size_of(path).max(0) as u64;
        Some((sz, S_IFREG | 0o644, crate::fs::nlink_of(path).max(1)))
    } else {
        None
    }
}

/// Консоль stat: char device.
fn write_console_stat(buf: u64) {
    let _ = write_stat(buf, 0, S_IFCHR | 0o620, 1);
}

// ---- Диспетчер ----

static SEEN_UNKNOWN: Mutex<[u64; 16]> = Mutex::new([u64::MAX; 16]);

/// Главный диспетчер Linux syscall'ов. Аргументы 5 и 6 читаются из фрейма.
#[no_mangle]
pub fn dispatch(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, frame: *mut u64) -> u64 {
    let a5 = unsafe { *frame.add(FRAME::R8) };
    let a6 = unsafe { *frame.add(FRAME::R9) };
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
                Some((sz, mode, nlink)) => {
                    if !write_stat(a2, sz, mode, nlink) {
                        return EFAULT;
                    }
                    0
                }
                None => ENOENT,
            }
        }
        5 => sys_fstat(a1, a2),
        7 => sys_poll(a1, a2, a3),
        8 => sys_lseek(a1, a2 as i64, a3),
        9 => task::sys_mmap(a1, a2, a3, a4, a5, a6),
        10 | 11 => 0, // mprotect / munmap: без noop (память текёт, ох)
        12 => task::sys_brk(a1),
        13 | 14 => 0, // rt_sigaction / rt_sigprocmask
        16 => sys_ioctl(a1, a2, a3),
        17 => sys_pread(a1, a2, a3, a5, a6),
        18 => sys_pwrite(a1, a2, a3, a5, a6),
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
        22 | 293 => sys_pipe(a1),
        23 => sys_select(a1, a2, a3, a4, a5),
        24 => 0, // sched_yield: PIT и так вытесняет
        28 => 0, // madvise
        32 => sys_dup(a1),
        33 => sys_dup2(a1, a2),
        35 | 230 => {
            // nanosleep / clock_nanosleep
            let mut raw = [0u8; 16];
            if !u_read(a1, &mut raw) {
                return EFAULT;
            }
            let sec = u64::from_le_bytes(raw[0..8].try_into().unwrap());
            let nsec = u64::from_le_bytes(raw[8..16].try_into().unwrap());
            sleep_ms(sec.saturating_mul(1000).saturating_add(nsec / 1_000_000));
            0
        }
        39 => task::current_tid(),
        102 | 104 | 107 | 108 => 1000, // getuid/getgid/geteuid/getegid
        105 | 106 => 0,                 // setuid/setgid: один пользователь
        157 => 0,                     // prctl: PR_SET_NAME и прочее — no-op
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
        62 => 0, // kill: сигналов нет, притворяемся успехом
        63 => sys_uname(a1),
        169 => sys_reboot(a1, a2, a3),
        72 => sys_fcntl(a1, a2, a3),
        73 | 74 | 75 => 0, // flock / fsync / fdatasync
        76 => {
            // truncate
            let Some(path) = task::copy_user_cstr(a1, 256) else { return EFAULT };
            let Some(canon) = task_resolve(&path) else { return ENAMETOOLONG };
            if a2 == 0 {
                crate::fs::write_canon(&canon, &[]);
            }
            0
        }
        77 => {
            // ftruncate
            match fd_name(a1) {
                Some(name) => {
                    if a2 == 0 {
                        crate::fs::write_canon(&name, &[]);
                    }
                    0
                }
                None => EBADF,
            }
        }
        78 | 217 => sys_getdents64(a1, a2, a3),
        79 => {
            // getcwd
            let cwd = task::with_current_task(|t| t.cwd.clone()).unwrap_or_else(|| String::from("/"));
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
                task::with_current_task(|t| t.cwd = canon);
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
            match crate::fs::mkdir(&canon) {
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
                Some(data) if crate::fs::write_canon(&n, &data) >= 0 => 0,
                Some(_) => ENOSPC,
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
            if crate::fs::write_canon(&canon, target.as_bytes()) >= 0 {
                0
            } else {
                ENOSPC
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
        90 | 91 => 0, // chmod / fchmod
        95 => {
            // umask
            let old = task::with_current_task(|t| t.umask).unwrap_or(0o022);
            task::with_current_task(|t| t.umask = a1 as u32 & 0o777);
            old as u64
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
        110 => {
            // getppid
            let parent = task::with_current_task(|t| t.parent).unwrap_or(-1);
            if parent < 0 {
                1
            } else {
                task::with_task_at(parent as usize, |t| t.tid).unwrap_or(1)
            }
        }
        158 => task::sys_arch_prctl(a1, a2),
        186 => task::current_tid(), // gettid
        202 => sys_futex(a1, a2, a3),
        203 => 0, // sched_setaffinity
        204 => {
            // sched_getaffinity: 1 CPU
            if a2 == 0 || a3 == 0 {
                return EINVAL;
            }
            let n = (a2 as usize).min(128);
            let mut tmp = [0u8; 128];
            tmp[0] = 1;
            if !u_write(a3, &tmp[..n]) {
                return EFAULT;
            }
            8
        }
        218 => {
            // set_tid_address
            task::with_current_task(|t| t.clear_tid = a1);
            task::current_tid()
        }
        228 => {
            // clock_gettime
            let ms = crate::interrupts::uptime_ms();
            let mut raw = [0u8; 16];
            raw[0..8].copy_from_slice(&(ms / 1000).to_le_bytes());
            raw[8..16].copy_from_slice(&(((ms % 1000) * 1_000_000).to_le_bytes()));
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
        334 => ENOSYS, // rseq: glibc терпимо относится к ENOSYS
        1000 => {
            // rudra-specific: дамп задач в serial+экран (команда ps).
            task::debug_dump();
            0
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

fn sleep_ms(ms: u64) {
    let deadline = crate::interrupts::uptime_ms() + ms;
    while crate::interrupts::uptime_ms() < deadline {
        x86_64::instructions::hlt();
    }
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
        File(String, u64, Option<Vec<u8>>),
        Bad(u64),
    }
    let kind = with_current_fds(|fds| match fds.get_mut(fd as usize).and_then(|x| x.as_mut()) {
        Some(Fd::Console { writable: false }) => Kind::Console,
        Some(Fd::Pipe { id, writable: false }) => Kind::Pipe(*id),
        Some(Fd::File { name, offset, accmode, dirty, .. }) if *accmode != 1 => {
            Kind::File(name.clone(), *offset, dirty.clone())
        }
        Some(Fd::Dir { .. }) => Kind::Bad(EISDIR),
        Some(Fd::File { .. }) => Kind::Bad(EBADF),
        Some(Fd::Console { .. }) | Some(Fd::Pipe { .. }) => Kind::Bad(EBADF),
        None => Kind::Bad(EBADF),
    });
    match kind {
        Err(e) => e,
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
        File,
        Bad,
    }
    let kind = with_current_fds(|fds| match fds.get_mut(fd as usize).and_then(|x| x.as_mut()) {
        Some(Fd::Console { writable: true }) => Kind::Console,
        Some(Fd::Pipe { id, writable: true }) => Kind::Pipe(*id),
        Some(Fd::File { accmode, .. }) if *accmode != 0 => Kind::File,
        _ => Kind::Bad,
    });
    match kind {
        Ok(Kind::Console) => console_write(&bytes),
        Ok(Kind::Pipe(id)) => pipe_write(id, &bytes),
        Ok(Kind::File) => {
            // Запись в буфер dirty (сброс при close) — под локом fd.
            with_fd(fd, |f| match f {
                Fd::File { offset, accmode, append, dirty, .. } if *accmode != 0 => {
                    let data = dirty.get_or_insert_with(Vec::new);
                    if *append {
                        data.extend_from_slice(&bytes);
                    } else {
                        let pos = *offset as usize;
                        if data.len() < pos + bytes.len() {
                            data.resize(pos + bytes.len(), 0);
                        }
                        data[pos..pos + bytes.len()].copy_from_slice(&bytes);
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
        fds[fd as usize].take()
    });
    match taken {
        Ok(Some(Fd::File { name, dirty: Some(data), .. })) => {
            crate::fs::write_canon(&name, &data);
            0
        }
        Ok(Some(Fd::Pipe { id, writable })) => {
            pipe_close_end(id, writable);
            0
        }
        Ok(Some(_)) => 0,
        Ok(None) => EBADF,
        Err(e) => e,
    }
}

fn sys_openat(dirfd: u64, path_ptr: u64, flags: u64, _mode: u64) -> u64 {
    const O_ACCMODE: u64 = 3;
    const O_CREAT: u64 = 0x40;
    const O_TRUNC: u64 = 0x200;
    const O_APPEND: u64 = 0x400;
    const O_DIRECTORY: u64 = 0x10000;

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
    let want_dir = flags & O_DIRECTORY != 0;
    let is_dir = crate::fs::is_dir(&canon);
    let exists = crate::fs::exists(&canon);

    if is_dir {
        if want_dir || accmode == 0 {
            let mut slot = Some(Fd::Dir { prefix: canon, idx: 0 });
            return with_current_fds(|fds| alloc_fd(&mut slot, fds)).unwrap_or(EMFILE);
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
        let mut slot = Some(Fd::File {
            name: canon,
            offset: 0,
            accmode: accmode as u8,
            append: flags & O_APPEND != 0,
            dirty: Some(Vec::new()),
        });
        return with_current_fds(|fds| alloc_fd(&mut slot, fds)).unwrap_or(EMFILE);
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
    with_current_fds(|fds| alloc_fd(&mut slot, fds)).unwrap_or(EMFILE)
}

fn sys_fstat(fd: u64, buf: u64) -> u64 {
    let st = with_fd(fd, |f| match f {
        Fd::Console { .. } => Some((0u64, S_IFCHR | 0o620, 1u64)),
        Fd::File { name, dirty, .. } => {
            let size = match dirty {
                Some(d) => d.len() as u64,
                None => crate::fs::size_of(name).max(0) as u64,
            };
            Some((size, S_IFREG | 0o644, 1))
        }        Fd::Dir { .. } => Some((0, S_IFDIR | 0o755, 2)),
        Fd::Pipe { .. } => Some((0, S_IFCHR | 0o644, 1)),
    });
    match st {
        Ok(Some((sz, mode, nlink))) => {
            if !write_stat(buf, sz, mode, nlink) {
                return EFAULT;
            }
            0
        }
        Ok(None) => EBADF,
        Err(e) => e,
    }
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
        Some((sz, mode, nlink)) => {
            if !write_stat(buf, sz, mode, nlink) {
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
        Some((sz, mode, nlink)) => {
            let now = crate::interrupts::uptime_ms();
            raw[0..4].copy_from_slice(&0x7ffu32.to_le_bytes());
            raw[4..8].copy_from_slice(&4096u32.to_le_bytes());
            raw[16..20].copy_from_slice(&(nlink as u32).to_le_bytes());
            raw[20..24].copy_from_slice(&1000u32.to_le_bytes());
            raw[24..28].copy_from_slice(&1000u32.to_le_bytes());
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
            let new = base + offset;
            if new < 0 {
                return EINVAL;
            }
            *cur = new as u64;
            0
        }
        Fd::Dir { .. } => {
            // SEEK_SET на индекс записи: разрешаем позиционирование каталога.
            match whence {
                0 => {
                    if let Fd::Dir { idx, .. } = f {
                        *idx = offset.max(0) as usize;
                    }
                    0
                }
                _ => ESPIPE,
            }
        }
        _ => ESPIPE,
    });
    match r {
        Ok(code) => {
            // Код 0 = успех; EINVAL/ESPIPE уже значения-ошибки.
            code
        }
        Err(e) => e,
    }
}

fn sys_pread(fd: u64, buf: u64, len: u64, pos: u64, _pos_hi: u64) -> u64 {
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

fn sys_pwrite(fd: u64, buf: u64, len: u64, pos_lo: u64, pos_hi: u64) -> u64 {
    let _ = (pos_lo, pos_hi);
    // pwrite: пишем по текущему offset (позиционные записи редки).
    sys_write(fd, buf, len)
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
            with_current_fds(|fds| alloc_fd(&mut slot, fds)).unwrap_or(EMFILE)
        }
        Err(e) => e,
    }
}

fn sys_dup2(old: u64, new: u64) -> u64 {
    if old == new {
        return match with_fd(old, |_| ()) {
            Ok(()) => old,
            Err(e) => e,
        };
    }
    match with_fd(old, |f| f.clone_fd()) {
        Ok(clone) => {
            with_current_fds(|fds| {
                let i = new as usize;
                if i >= fds.len() {
                    fds.resize(i + 1, None);
                }
                if let Some(Some(old_fd)) = fds.get(i) {
                    if let Fd::Pipe { id, writable } = old_fd {
                        pipe_close_end(*id, *writable);
                    }
                }
                fds[i] = Some(clone);
                new
            })
            .unwrap_or(EMFILE)
        }
        Err(e) => e,
    }
}

fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> u64 {
    match cmd {
        0 => {
            // F_DUPFD: копия с номером >= arg
            match with_fd(fd, |f| f.clone_fd()) {
                Ok(clone) => {
                    let mut slot = Some(clone);
                    with_current_fds(|fds| {
                        let min = arg as usize;
                        for i in min..fds.len() {
                            if fds[i].is_none() {
                                fds[i] = slot.take();
                                return i as u64;
                            }
                        }
                        if fds.len() < 64 {
                            fds.push(slot.take());
                            return (fds.len() - 1) as u64;
                        }
                        EMFILE
                    })
                    .unwrap_or(EMFILE)
                }
                Err(e) => e,
            }
        }
        1 | 2 => 0, // F_GETFD / F_SETFD
        3 => {
            // F_GETFL: accmode в младших битах
            with_fd(fd, |f| match f {
                Fd::File { accmode, append, .. } => {
                    (*accmode as u64) | if *append { 0x400 } else { 0 }
                }
                Fd::Dir { .. } => 0,
                Fd::Console { writable } => *writable as u64,
                Fd::Pipe { writable, .. } => *writable as u64,
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

fn sys_pipe(fds_ptr: u64) -> u64 {
    if fds_ptr == 0 {
        return EFAULT;
    }
    let (r, w) = new_pipe();
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
            _ => x86_64::instructions::hlt(),
        }
    }
}

fn poll_ready(fd: u64, events: i16) -> i16 {
    const POLLIN: i16 = 1;
    const POLLOUT: i16 = 4;
    let mut revents = 0i16;
    let _ = with_fd(fd, |f| {
        match f {
            Fd::Console { writable } => {
                if !*writable && events & POLLIN != 0 && crate::input::INPUT_QUEUE.lock().len() > 0 {
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
                    if !*writable && p.len > 0 && events & POLLIN != 0 {
                        revents |= POLLIN;
                    }
                    if *writable && events & POLLOUT != 0 {
                        revents |= POLLOUT;
                    }
                }
            }
        }
    });
    revents
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
            _ => x86_64::instructions::hlt(),
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
        if let Some((tid, code)) = task::reap_child(me, want) {
            if status != 0 {
                // W_EXITCODE(code, 0)
                let word = (((code as i32) << 8) & 0xFF00).to_le_bytes();
                if !u_write(status, &word) {
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

fn sys_futex(uaddr: u64, op: u64, val: u64) -> u64 {
    const FUTEX_WAIT: u64 = 0;
    const FUTEX_WAKE: u64 = 1;
    match op & 0x7f {
        FUTEX_WAIT => {
            if uaddr == 0 {
                return EFAULT;
            }
            // Спин с hlt: писатель изменит значение в userspace, таймер
            // разбудит нас для перепроверки. Одноядерно корректно.
            loop {
                let mut raw = [0u8; 4];
                if !u_read(uaddr, &mut raw) {
                    return EFAULT;
                }
                let cur = u32::from_le_bytes(raw);
                if cur != val as u32 {
                    return 0;
                }
                x86_64::instructions::hlt();
            }
        }
        FUTEX_WAKE => 0, // ждущих в квартире нет — все спинят сами
        _ => ENOSYS,
    }
}
