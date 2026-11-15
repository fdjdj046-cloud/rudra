#![no_std]

//! Общая библиотека user-программ rudra: обёртки syscall'ов.

pub const SYS_WRITE: u64 = 1;
pub const SYS_EXIT: u64 = 2;
pub const SYS_READ: u64 = 3;
pub const SYS_YIELD: u64 = 4;
pub const SYS_SPAWN: u64 = 5;

/// Программы, встроенные в ядро (индексы для spawn).
pub const PROG_SHELL: u64 = 0;
pub const PROG_HELLO: u64 = 1;
pub const PROG_COUNTER: u64 = 2;

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

pub fn write(s: &str) {
    unsafe { syscall3(SYS_WRITE, s.as_ptr() as u64, s.len() as u64, 0) };
}

/// Прочитать до `len` байт из консоли. Блокируется, пока не появятся данные.
pub fn read(buf: &mut [u8]) -> usize {
    let n = unsafe { syscall3(SYS_READ, buf.as_mut_ptr() as u64, buf.len() as u64, 0) };
    n as usize
}

pub fn spawn(program: u64) -> u64 {
    unsafe { syscall3(SYS_SPAWN, program, 0, 0) }
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
