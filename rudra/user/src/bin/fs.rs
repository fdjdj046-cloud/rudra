//! CLONE_FS делит cwd и umask. Обычный fork копирует.
//! Двойной fork: внук должен уйти к init, а не остаться у шелла и не стать сиротой с ppid 0.
//! ppid == 1 — ложный успех, если шелл всё ещё PID1 (его tid тоже 1).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use rudra::{exit, fork, getpid, println, sleep_ms, syscall6, thread_join, thread_spawn, wait4};

static CLEAR: AtomicU32 = AtomicU32::new(1);
static DONE: AtomicU32 = AtomicU32::new(0);
static SHELL: AtomicU64 = AtomicU64::new(0);
static MID: AtomicU64 = AtomicU64::new(0);

fn chdir(path: &[u8]) -> u64 {
    unsafe { syscall6(80, path.as_ptr() as u64, 0, 0, 0, 0, 0) }
}

fn getcwd_is(expect: &[u8]) -> bool {
    let mut buf = [0u8; 64];
    let n = unsafe { syscall6(79, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0, 0) };
    if n == 0 || (n as i64) < 0 || n as usize > buf.len() {
        return false;
    }
    let n = n as usize;
    &buf[..n - 1] == expect
}

fn ppid() -> u64 {
    unsafe { syscall6(110, 0, 0, 0, 0, 0, 0) }
}

extern "C" fn worker(_: *mut u8) {
    if chdir(b"/\0") != 0 {
        DONE.store(2, Ordering::Release);
        exit(1);
    }
    let _old = unsafe { syscall6(95, 0o077, 0, 0, 0, 0, 0) };
    DONE.store(1, Ordering::Release);
    exit(0);
}

fn main() {
    if chdir(b"/bin\0") != 0 || !getcwd_is(b"/bin") {
        println!("fs-bad chdir");
        exit(1);
    }

    let child = fork();
    if child == 0 {
        if chdir(b"/\0") != 0 || !getcwd_is(b"/") {
            println!("fs-bad child");
            exit(2);
        }
        exit(0);
    }
    if child == u64::MAX {
        println!("fs-bad fork");
        exit(3);
    }
    let (w, st) = wait4(child);
    if w == u64::MAX || w == ((-10i64) as u64) || ((st >> 8) & 0xFF) != 0 {
        println!("fs-bad child-exit");
        exit(4);
    }
    if !getcwd_is(b"/bin") {
        println!("fs-bad parent-cwd");
        exit(5);
    }

    let tid = thread_spawn(
        &CLEAR as *const AtomicU32 as *mut u32,
        worker,
        core::ptr::null_mut(),
    );
    if tid == u64::MAX {
        println!("fs-bad thread");
        exit(6);
    }
    let mut spins = 0;
    while DONE.load(Ordering::Acquire) == 0 {
        sleep_ms(10);
        spins += 1;
        if spins > 200 {
            println!("fs-bad thread-timeout");
            exit(7);
        }
    }
    thread_join(&CLEAR as *const AtomicU32 as *const u32);
    if DONE.load(Ordering::Acquire) != 1 || !getcwd_is(b"/") {
        println!("fs-bad shared-cwd");
        exit(8);
    }
    let old = unsafe { syscall6(95, 0o022, 0, 0, 0, 0, 0) };
    if old != 0o077 {
        println!("fs-bad umask {}", old);
        exit(9);
    }

    // ppid шелла запоминаем до двойного fork. Внук сравнивает с ним, не с числом 1.
    SHELL.store(ppid(), Ordering::Relaxed);
    let mid = fork();
    if mid == 0 {
        MID.store(getpid(), Ordering::Relaxed);
        let gc = fork();
        if gc == 0 {
            let shell = SHELL.load(Ordering::Relaxed);
            let orig = MID.load(Ordering::Relaxed);
            let mut spins = 0;
            loop {
                let p = ppid();
                if p != orig {
                    if p != 0 && p != shell && p != orig {
                        println!("reparent-ok");
                    } else {
                        println!("reparent-bad {} {} {}", p, shell, orig);
                    }
                    exit(0);
                }
                sleep_ms(10);
                spins += 1;
                if spins > 80 {
                    println!("reparent-bad timeout {} {}", orig, shell);
                    exit(1);
                }
            }
        }
        if gc == u64::MAX {
            println!("reparent-bad fork");
            exit(1);
        }
        exit(0);
    }
    if mid == u64::MAX {
        println!("fs-bad mid");
        exit(10);
    }
    let _ = wait4(mid);
    sleep_ms(1200);
    println!("fs-ok");
}

rudra::entry!(main);
