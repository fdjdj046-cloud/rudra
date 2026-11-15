#![no_std]

//! Общая библиотека user-программ rudra: обёртки над Linux ABI syscall'ами
//! (номера x86_64, как в настоящем Linux — поэтому те же бинарники можно
//! собирать под Linux для сравнения).

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_err("rudra-user: panic\n");
    exit(101);
}

// ---- raw syscall ----

pub unsafe fn syscall6(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        in("r10") a4,
        in("r8") a5,
        in("r9") a6,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

// Номера syscall'ов x86_64.
pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_LSEEK: u64 = 8;
pub const SYS_MMAP: u64 = 9;
pub const SYS_BRK: u64 = 12;
pub const SYS_IOCTL: u64 = 16;
pub const SYS_PIPE: u64 = 22;
pub const SYS_YIELD: u64 = 24;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_GETPID: u64 = 39;
pub const SYS_CLONE: u64 = 56;
pub const SYS_FORK: u64 = 57;
pub const SYS_EXECVE: u64 = 59;
pub const SYS_EXIT: u64 = 60;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_UNAME: u64 = 63;
pub const SYS_GETDENTS64: u64 = 217;
pub const SYS_FUTEX: u64 = 202;
pub const SYS_OPENAT: u64 = 257;
pub const SYS_GETRANDOM: u64 = 318;
pub const SYS_DEBUG_TASKS: u64 = 1000; // rudra-specific

pub const AT_FDCWD: u64 = -100i64 as u64;

pub const O_RDONLY: u64 = 0;
pub const O_WRONLY: u64 = 1;
pub const O_RDWR: u64 = 2;
pub const O_CREAT: u64 = 0x40;
pub const O_TRUNC: u64 = 0x200;
pub const O_APPEND: u64 = 0x400;
pub const O_DIRECTORY: u64 = 0x10000;

pub const MAP_PRIVATE: u64 = 0x2;
pub const MAP_ANONYMOUS: u64 = 0x20;

// clone-флаги (Linux)
pub const CLONE_VM: u64 = 0x100;
pub const CLONE_FS: u64 = 0x200;
pub const CLONE_FILES: u64 = 0x400;
pub const CLONE_SETTLS: u64 = 0x80000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x200000;

pub const FUTEX_WAIT_PRIVATE: u64 = 128;
pub const FUTEX_WAKE_PRIVATE: u64 = 129;

// ---- базовый ввод-вывод ----

pub fn write_str(s: &str) {
    unsafe { syscall6(SYS_WRITE, 1, s.as_ptr() as u64, s.len() as u64, 0, 0, 0) };
}

pub fn write_err(s: &str) {
    unsafe { syscall6(SYS_WRITE, 2, s.as_ptr() as u64, s.len() as u64, 0, 0, 0) };
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::fmt_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

pub fn fmt_print(args: core::fmt::Arguments) {
    let mut buf = [0u8; 512];
    if let Some(s) = args.as_str() {
        write_str(s);
        return;
    }
    use core::fmt::Write;
    struct W;
    impl Write for W {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            write_str(s);
            Ok(())
        }
    }
    // Простейший форматтер: пишем через Write в serial по кускам.
    let _ = W.write_fmt(args);
    let _ = &mut buf;
}

/// Прочитать до `len` байт из fd. Возвращает байты прочитанные.
pub fn read(fd: u64, buf: &mut [u8]) -> isize {
    unsafe { syscall6(SYS_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0) as isize }
}

/// Блокирующее чтение строки из консоли (fd 0) с эхом и backspace.
/// Возвращает строку из статического буфера (перезаписывается следующим вызовом).
pub fn readline(prompt: &str) -> &'static str {
    write_str(prompt);
    let mut len = 0usize;
    loop {
        let mut b = [0u8; 1];
        if read(0, &mut b) <= 0 {
            continue;
        }
        match b[0] {
            b'\n' | b'\r' => {
                write_str("\n");
                break;
            }
            0x08 | 0x7F => {
                if len > 0 {
                    len -= 1;
                    write_str("\x08 \x08");
                }
            }
            c if len < unsafe { LINE_BUF.len() } - 1 => {
                unsafe { LINE_BUF[len] = c };
                len += 1;
                write_str(core::str::from_utf8(&b).unwrap_or("?"));
            }
            _ => {}
        }
    }
    unsafe {
        LINE_BUF[len] = 0;
        core::str::from_utf8(&LINE_BUF[..len]).unwrap_or("")
    }
}

static mut LINE_BUF: [u8; 256] = [0u8; 256];

pub fn exit(code: u64) -> ! {
    unsafe { syscall6(SYS_EXIT, code, 0, 0, 0, 0, 0) };
    loop {
        core::hint::spin_loop();
    }
}

// ---- файлы ----

pub fn open(path: &str, flags: u64) -> isize {
    openat(AT_FDCWD, path, flags)
}

pub fn openat(dirfd: u64, path: &str, flags: u64) -> isize {
    let mut p = [0u8; 128];
    let pb = path.as_bytes();
    if pb.len() >= p.len() {
        return -1;
    }
    p[..pb.len()].copy_from_slice(pb);
    unsafe {
        syscall6(SYS_OPENAT, dirfd, p.as_ptr() as u64, flags, 0, 0, 0) as isize
    }
}

pub fn close(fd: u64) {
    unsafe { syscall6(SYS_CLOSE, fd, 0, 0, 0, 0, 0) };
}

/// Прочитать файл целиком в буфер. Возвращает размер или -1.
pub fn read_file(path: &str, buf: &mut [u8]) -> isize {
    let fd = open(path, O_RDONLY);
    if fd < 0 {
        return -1;
    }
    let n = read(fd as u64, buf);
    close(fd as u64);
    n
}

/// Создать/перезаписать файл.
pub fn write_file(path: &str, data: &[u8]) -> isize {
    let fd = open(path, O_WRONLY | O_CREAT | O_TRUNC);
    if fd < 0 {
        return -1;
    }
    let n = unsafe {
        syscall6(SYS_WRITE, fd as u64, data.as_ptr() as u64, data.len() as u64, 0, 0, 0) as isize
    };
    close(fd as u64);
    n
}

pub fn mkdir(path: &str) -> i64 {
    let mut p = [0u8; 128];
    let pb = path.as_bytes();
    if pb.len() >= p.len() {
        return -1;
    }
    p[..pb.len()].copy_from_slice(pb);
    unsafe { syscall6(83, p.as_ptr() as u64, 0, 0, 0, 0, 0) as i64 }
}

pub fn delete(path: &str) -> bool {
    // unlink == syscall 87
    let mut p = [0u8; 128];
    let pb = path.as_bytes();
    if pb.len() >= p.len() {
        return false;
    }
    p[..pb.len()].copy_from_slice(pb);
    unsafe { syscall6(87, p.as_ptr() as u64, 0, 0, 0, 0, 0) == 0 }
}

// ---- процессы ----

pub fn getpid() -> u64 {
    unsafe { syscall6(SYS_GETPID, 0, 0, 0, 0, 0, 0) }
}

pub fn fork() -> u64 {
    unsafe { syscall6(SYS_FORK, 0, 0, 0, 0, 0, 0) }
}

pub fn execve(path: &str, args: &[&str]) -> u64 {
    execve_env(path, args, &["PATH=/bin", "HOME=/", "TERM=rudra"])
}

pub fn execve_env(path: &str, args: &[&str], env: &[&str]) -> u64 {
    let mut pbuf = [0u8; 128];
    let pb = path.as_bytes();
    if pb.len() >= pbuf.len() {
        return u64::MAX;
    }
    pbuf[..pb.len()].copy_from_slice(pb);
    pbuf[pb.len()] = 0;

    let mut argv: [*const u8; 32] = [core::ptr::null(); 32];
    let mut abuf = [0u8; 32 * 64];
    let mut apos = 0usize;
    // args[0] = путь (как в execve-конвенции), затем аргументы.
    let count = args.len().min(30);
    argv[0] = pbuf.as_ptr();
    for (i, a) in args.iter().take(count).enumerate() {
        let b = a.as_bytes();
        if apos + b.len() + 1 > abuf.len() {
            break;
        }
        abuf[apos..apos + b.len()].copy_from_slice(b);
        abuf[apos + b.len()] = 0;
        argv[i + 1] = unsafe { abuf.as_ptr().add(apos) };
        apos += b.len() + 1;
    }
    argv[count + 1] = core::ptr::null();

    let mut envp: [*const u8; 16] = [core::ptr::null(); 16];
    let mut ebuf = [0u8; 16 * 64];
    let mut epos = 0usize;
    for (i, e) in env.iter().take(14).enumerate() {
        let b = e.as_bytes();
        if epos + b.len() + 1 > ebuf.len() {
            break;
        }
        ebuf[epos..epos + b.len()].copy_from_slice(b);
        ebuf[epos + b.len()] = 0;
        envp[i] = unsafe { ebuf.as_ptr().add(epos) };
        epos += b.len() + 1;
    }
    envp[env.len().min(14)] = core::ptr::null();

    unsafe {
        syscall6(
            SYS_EXECVE,
            pbuf.as_ptr() as u64,
            argv.as_ptr() as u64,
            envp.as_ptr() as u64,
            0,
            0,
            0,
        )
    }
}

/// Ожидать завершения ребёнка. Возвращает (tid, exit_code<<8) или -1.
pub fn wait4(pid: u64) -> (u64, i32) {
    let mut status = 0i32;
    let tid = unsafe {
        syscall6(
            SYS_WAIT4,
            pid,
            &mut status as *mut i32 as u64,
            0,
            0,
            0,
            0,
        )
    };
    (tid, status)
}

/// Запустить программу и дождаться завершения. Возвращает exit code.
pub fn run_and_wait(path: &str, args: &[&str]) -> i32 {
    let pid = fork();
    if pid == 0 {
        let r = execve(path, args);
        let _ = r;
        write_err("rudra: exec failed\n");
        exit(127);
    }
    if pid == u64::MAX {
        return -1;
    }
    let (_, status) = wait4(pid);
    (status >> 8) & 0xFF
}

// ---- mmap / sleep ----

pub fn mmap_anon(len: usize) -> u64 {
    unsafe {
        syscall6(
            SYS_MMAP,
            0,
            len as u64,
            3, // PROT_READ|PROT_WRITE
            MAP_PRIVATE | MAP_ANONYMOUS,
            u64::MAX,
            0,
        )
    }
}

pub fn sleep_ms(ms: u64) {
    let ts = [ms / 1000, (ms % 1000) * 1_000_000];
    unsafe { syscall6(SYS_NANOSLEEP, ts.as_ptr() as u64, 0, 0, 0, 0, 0) };
}

// ---- потоки ----

/// Создать поток в общем адресном пространстве. `cleartid` — AtomicU32,
/// который ядро обнулит при выходе потока (основа для join).
pub fn thread_spawn(
    cleartid: *mut u32,
    f: extern "C" fn(*mut u8),
    arg: *mut u8,
) -> u64 {
    let stack = mmap_anon(256 * 1024);
    if stack == 0 || (stack as i64) < 0 {
        return u64::MAX;
    }
    let stack_top = stack + 256 * 1024 - 16;
    unsafe {
        // Аргументы передаём через регистры: raw_clone оборачиваем.
        raw_clone_thread(stack_top, cleartid as u64, f as u64, arg as u64)
    }
}

/// Низкоуровневый clone: флаги VM|FS|FILES|CHILD_CLEARTID.
/// f/arg передаём через r12/r13: ядро копирует все GPR родителя ребёнку,
/// а user-стек у ребёнка новый — локальные переменные там недоступны.
unsafe fn raw_clone_thread(stack_top: u64, cleartid: u64, f: u64, arg: u64) -> u64 {
    let flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_CHILD_CLEARTID;
    let tid: u64;
    let f_out: u64;
    let arg_out: u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") SYS_CLONE => tid,
        in("rdi") flags,
        in("rsi") stack_top,
        in("rdx") 0,
        in("r10") cleartid,
        in("r8") 0,
        inlateout("r12") f => f_out,
        inlateout("r13") arg => arg_out,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack)
    );
    if tid == 0 {
        // Ребёнок: новый стек, r12/r13 = f/arg.
        let f: extern "C" fn(*mut u8) = core::mem::transmute(f_out);
        f(arg_out as *mut u8);
        // f вернулся — выходим (ядро обнулит cleartid).
        exit(0);
    }
    tid
}

/// Спин-мьютекс. На одном ядре с тиком PIT ~55 мс futex-сон на каждую
/// короткую критическую секцию не успевает отпустить 400 тысяч итераций:
/// ждущий помечает «есть waiters», и каждый unlock становится syscall.
/// Планировщик и так вытесняет по таймеру, поэтому достаточно pause.
pub struct Mutex {
    lock: core::sync::atomic::AtomicU32,
}

impl Mutex {
    pub const fn new() -> Self {
        Mutex { lock: core::sync::atomic::AtomicU32::new(0) }
    }

    pub fn lock(&self) {
        use core::sync::atomic::Ordering;
        while self
            .lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    pub fn unlock(&self) {
        use core::sync::atomic::Ordering;
        self.lock.store(0, Ordering::Release);
    }
}

/// Ждать обнуления cleartid (завершения потока).
pub fn thread_join(cleartid: *const u32) {
    unsafe {
        while core::ptr::read_volatile(cleartid) != 0 {
            syscall6(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }
    }
}

// ---- точка входа ----

/// Макрос `_start` для user-программ: вызывает main() и exit(0).
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[no_mangle]
        pub extern "C" fn _start() -> ! {
            let m: fn() = $main;
            m();
            $crate::exit(0);
        }
    };
}
