//! Сигнал прерывает сон, pipe и futex. SIGCHLD приходит с тика после fork.
//!
//! Консоль здесь не читается. Если nanosleep доспит до конца, код возврата
//! будет 0 и тест напечатает intr-bad.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use rudra::{exit, fork, getpid, println, sleep_ms, syscall6, thread_join, thread_spawn};

const SIGUSR1: u64 = 10;
const SIGUSR2: u64 = 12;
const SIGCHLD: u64 = 17;
const SA_SIGINFO: u64 = 4;
const SA_RESTORER: u64 = 0x0400_0000;
const EINTR: u64 = -4i64 as u64;

static CHLD: AtomicU32 = AtomicU32::new(0);
static USR1: AtomicU32 = AtomicU32::new(0);
static USR2: AtomicU32 = AtomicU32::new(0);
static READY: AtomicU32 = AtomicU32::new(0);
static PARENT: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU32 = AtomicU32::new(1);
static WORD: AtomicU32 = AtomicU32::new(0);

core::arch::global_asm!(
    ".global intr_restorer",
    "intr_restorer:",
    "mov rax, 15",
    "syscall",
    "ud2",
);

unsafe extern "C" {
    fn intr_restorer();
}

extern "C" fn on_sig(sig: i32, _info: usize, _ctx: usize) {
    match sig as u64 {
        SIGCHLD => CHLD.store(1, Ordering::Release),
        SIGUSR1 => USR1.store(1, Ordering::Release),
        SIGUSR2 => USR2.store(1, Ordering::Release),
        _ => {}
    }
}

extern "C" fn poke(arg: *mut u8) {
    let sig = arg as u64;
    while READY.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    let parent = PARENT.load(Ordering::Relaxed);
    unsafe { syscall6(62, parent, sig, 0, 0, 0, 0) };
}

fn sigaction(sig: u64) -> bool {
    let mut act = [0u8; 32];
    let handler = on_sig as *const () as u64;
    let restorer = intr_restorer as *const () as u64;
    act[0..8].copy_from_slice(&handler.to_le_bytes());
    let flags = SA_RESTORER | SA_SIGINFO;
    act[8..16].copy_from_slice(&flags.to_le_bytes());
    act[16..24].copy_from_slice(&restorer.to_le_bytes());
    unsafe { syscall6(13, sig, act.as_ptr() as u64, 0, 8, 0, 0) == 0 }
}

fn kick(sig: u64) -> bool {
    DONE.store(1, Ordering::Relaxed);
    READY.store(0, Ordering::Relaxed);
    let tid = thread_spawn(
        &DONE as *const AtomicU32 as *mut u32,
        poke,
        sig as *mut u8,
    );
    if tid == u64::MAX {
        return false;
    }
    READY.store(1, Ordering::Release);
    true
}

fn join_killer() {
    thread_join(&DONE as *const AtomicU32 as *const u32);
}

fn main() {
    if !sigaction(SIGCHLD) || !sigaction(SIGUSR1) || !sigaction(SIGUSR2) {
        println!("intr-bad sigaction");
        exit(2);
    }
    PARENT.store(getpid(), Ordering::Relaxed);

    let pid = fork();
    if pid == u64::MAX {
        println!("intr-bad fork");
        exit(3);
    }
    if pid == 0 {
        sleep_ms(100);
        exit(0);
    }
    if CHLD.load(Ordering::Acquire) != 0 {
        println!("intr-bad early");
        exit(4);
    }
    let mut spins = 0u64;
    while CHLD.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
        spins = spins.wrapping_add(1);
        if spins > 300_000_000 {
            println!("intr-bad chld");
            exit(5);
        }
    }
    let mut st = [0u8; 4];
    unsafe { syscall6(61, pid, st.as_mut_ptr() as u64, 0, 0, 0, 0) };

    USR1.store(0, Ordering::Relaxed);
    if !kick(SIGUSR1) {
        println!("intr-bad spawn");
        exit(6);
    }
    let req = [1u64, 0];
    let mut rem = [0u64; 2];
    // `as_ptr()` — shared. rustc 1.102 в release тогда не перечитывает буфер
    // после syscall и оставляет нули, которые записала сама программа.
    let rc = unsafe { syscall6(35, req.as_ptr() as u64, rem.as_mut_ptr() as u64, 0, 0, 0, 0) };
    let left = rem[0].saturating_mul(1_000_000_000).saturating_add(rem[1]);
    if rc != EINTR || USR1.load(Ordering::Acquire) != 1 || left == 0 {
        println!("intr-bad sleep {:#x} {}", rc, left);
        exit(7);
    }
    join_killer();

    USR2.store(0, Ordering::Relaxed);
    let mut fds = [0u32; 2];
    let prc = unsafe { syscall6(22, fds.as_mut_ptr() as u64, 0, 0, 0, 0, 0) };
    if prc != 0 || !kick(SIGUSR2) {
        println!("intr-bad pipe {:#x}", prc);
        exit(8);
    }
    let mut byte = [0u8; 1];
    let n = unsafe { syscall6(0, u64::from(fds[0]), byte.as_mut_ptr() as u64, 1, 0, 0, 0) };
    if n != EINTR || USR2.load(Ordering::Acquire) != 1 {
        println!("intr-bad read {:#x}", n);
        exit(9);
    }
    unsafe {
        syscall6(3, u64::from(fds[0]), 0, 0, 0, 0, 0);
        syscall6(3, u64::from(fds[1]), 0, 0, 0, 0, 0);
    }
    join_killer();

    USR1.store(0, Ordering::Relaxed);
    if !kick(SIGUSR1) {
        println!("intr-bad spawn2");
        exit(10);
    }
    let frc = unsafe { syscall6(202, &WORD as *const AtomicU32 as u64, 0, 0, 0, 0, 0) };
    if frc != EINTR || USR1.load(Ordering::Acquire) != 1 {
        println!("intr-bad futex {:#x}", frc);
        exit(11);
    }
    join_killer();
    println!("intr-ok");
}

rudra::entry!(main);
