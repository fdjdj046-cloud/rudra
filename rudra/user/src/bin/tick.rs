//! Перехваченный SIGUSR1 должен прийти с тика, без syscall в цикле ожидания.
//!
//! Поток ждёт флаг и только потом вызывает `kill`. Если обработчик ставится
//! лишь на возврате из syscall, цикл доходит до `tick-bad`.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use rudra::{exit, getpid, println, syscall6, thread_join, thread_spawn};

const SIGUSR1: u64 = 10;
const SA_SIGINFO: u64 = 4;
const SA_RESTORER: u64 = 0x0400_0000;

static HITS: AtomicU32 = AtomicU32::new(0);
static READY: AtomicU32 = AtomicU32::new(0);
static PARENT: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU32 = AtomicU32::new(1);

core::arch::global_asm!(
    ".global tick_restorer",
    "tick_restorer:",
    "mov rax, 15",
    "syscall",
    "ud2",
);

unsafe extern "C" {
    fn tick_restorer();
}

extern "C" fn on_usr1(sig: i32, _info: usize, _ctx: usize) {
    if sig == SIGUSR1 as i32 {
        HITS.store(1, Ordering::Release);
    }
}

extern "C" fn poke(_arg: *mut u8) {
    while READY.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    let parent = PARENT.load(Ordering::Relaxed);
    let rc = unsafe { syscall6(62, parent, SIGUSR1, 0, 0, 0, 0) };
    if rc != 0 {
        HITS.store(2, Ordering::Release);
    }
}

fn main() {
    let mut act = [0u8; 32];
    let handler = on_usr1 as *const () as u64;
    let restorer = tick_restorer as *const () as u64;
    act[0..8].copy_from_slice(&handler.to_le_bytes());
    let flags = SA_RESTORER | SA_SIGINFO;
    act[8..16].copy_from_slice(&flags.to_le_bytes());
    act[16..24].copy_from_slice(&restorer.to_le_bytes());
    let rc = unsafe { syscall6(13, SIGUSR1, act.as_ptr() as u64, 0, 8, 0, 0) };
    if rc != 0 {
        println!("tick-bad sigaction {:#x}", rc);
        exit(2);
    }
    PARENT.store(getpid(), Ordering::Relaxed);
    let tid = thread_spawn(&DONE as *const AtomicU32 as *mut u32, poke, core::ptr::null_mut());
    if tid == u64::MAX {
        println!("tick-bad spawn");
        exit(3);
    }
    READY.store(1, Ordering::Release);
    let mut spins = 0u64;
    while HITS.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
        spins = spins.wrapping_add(1);
        if spins > 100_000_000 {
            println!("tick-bad");
            exit(5);
        }
    }
    if HITS.load(Ordering::Acquire) != 1 {
        println!("tick-bad kill");
        exit(6);
    }
    println!("tick-ok");
    thread_join(&DONE as *const AtomicU32 as *const u32);
}

rudra::entry!(main);
