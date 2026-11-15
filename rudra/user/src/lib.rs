#![no_std]

//! Общая библиотека user-программ rudra: обёртки syscall'ов.

pub const SYS_WRITE: u64 = 1;
pub const SYS_EXIT: u64 = 2;
pub const SYS_READ: u64 = 3;
pub const SYS_YIELD: u64 = 4;
pub const SYS_READ_FILE: u64 = 6;
pub const SYS_WRITE_FILE: u64 = 7;
pub const SYS_LIST: u64 = 8;
pub const SYS_DELETE: u64 = 9;
pub const SYS_SPAWN_PATH: u64 = 10;

unsafe fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

unsafe fn syscall4(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        in("r8") a4,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

pub fn write(s: &str) {
    unsafe { syscall3(SYS_WRITE, s.as_ptr() as u64, s.len() as u64, 0) };
}

/// Прочитать до `len` байт из консоли. Блокируется, пока не появятся данные.
pub fn read(buf: &mut [u8]) -> usize {
    let n = unsafe { syscall3(SYS_READ, buf.as_mut_ptr() as u64, buf.len() as u64, 0) };
    n as usize
}

pub fn r#yield() {
    unsafe { syscall3(SYS_YIELD, 0, 0, 0) };
}

pub fn exit(code: u64) -> ! {
    unsafe { syscall3(SYS_EXIT, code, 0, 0) };
    loop {
        core::hint::spin_loop();
    }
}

// ---- Файловая система (ramdisk) ----

pub const FS_BUF_SIZE: usize = 4096;

/// Прочитать файл целиком (до размера буфера). Возвращает байты или -1.
pub fn read_file(path: &str, buf: &mut [u8]) -> isize {
    (unsafe {
        syscall4(
            SYS_READ_FILE,
            path.as_ptr() as u64,
            path.len() as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    }) as isize
}

/// Создать или заменить файл. Возвращает размер или -1.
pub fn write_file(path: &str, data: &[u8]) -> isize {
    (unsafe {
        syscall4(
            SYS_WRITE_FILE,
            path.as_ptr() as u64,
            path.len() as u64,
            data.as_ptr() as u64,
            data.len() as u64,
        )
    }) as isize
}

/// Имя i-го живого файла (для ls). Возвращает длину имени или -1 (конец).
pub fn list(index: u64, buf: &mut [u8]) -> isize {
    (unsafe {
        syscall3(
            SYS_LIST,
            index,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    }) as isize
}

pub fn delete(path: &str) -> bool {
    unsafe { syscall3(SYS_DELETE, path.as_ptr() as u64, path.len() as u64, 0) != 0 }
}

/// Запустить программу из ramdisk по пути (напр. "/bin/hello.elf").
/// Возвращает номер слота или -1 (u64::MAX).
pub fn spawn_path(path: &str) -> u64 {
    unsafe { syscall3(SYS_SPAWN_PATH, path.as_ptr() as u64, path.len() as u64, 0) }
}
