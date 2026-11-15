//! Проверка доставки SIGUSR1 текущему потоку.
//!
//! Кадр — ядерный `struct sigaction` (32 байта): handler, flags, restorer, mask.
//! `SA_RESTORER` обязателен. Пока сигнал заблокирован, `kill` не вызывает
//! обработчик. Снятие блока доставляет его на возврате из `rt_sigprocmask`.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};
use rudra::{exit, getpid, println, syscall6};

const SIGUSR1: u64 = 10;
const SA_SIGINFO: u64 = 4;
const SA_RESTORER: u64 = 0x0400_0000;

static HITS: AtomicU32 = AtomicU32::new(0);

core::arch::global_asm!(
    ".global signal_restorer",
    "signal_restorer:",
    "mov rax, 15",
    "syscall",
    "ud2",
);

unsafe extern "C" {
    fn signal_restorer();
}

extern "C" fn on_usr1(sig: i32, _info: usize, _ctx: usize) {
    if sig == SIGUSR1 as i32 {
        HITS.fetch_add(1, Ordering::Relaxed);
    }
}

fn main() {
    let mut act = [0u8; 32];
    let handler = on_usr1 as *const () as u64;
    let restorer = signal_restorer as *const () as u64;
    act[0..8].copy_from_slice(&handler.to_le_bytes());
    let flags = SA_RESTORER | SA_SIGINFO;
    act[8..16].copy_from_slice(&flags.to_le_bytes());
    act[16..24].copy_from_slice(&restorer.to_le_bytes());
    let rc = unsafe { syscall6(13, SIGUSR1, act.as_ptr() as u64, 0, 8, 0, 0) };
    if rc != 0 {
        println!("signal-bad sigaction {:#x}", rc);
        exit(2);
    }

    let block = (1u64 << (SIGUSR1 - 1)).to_le_bytes();
    let rc = unsafe { syscall6(14, 0, block.as_ptr() as u64, 0, 8, 0, 0) };
    if rc != 0 {
        println!("signal-bad block {:#x}", rc);
        exit(2);
    }
    let pid = getpid();
    let killed = unsafe { syscall6(62, pid, SIGUSR1, 0, 0, 0, 0) };
    if killed != 0 || HITS.load(Ordering::Relaxed) != 0 {
        println!(
            "signal-bad masked kill {:#x} hits {}",
            killed,
            HITS.load(Ordering::Relaxed)
        );
        exit(3);
    }
    let rc = unsafe { syscall6(14, 1, block.as_ptr() as u64, 0, 8, 0, 0) };
    if rc != 0 || HITS.load(Ordering::Relaxed) != 1 {
        println!(
            "signal-bad unblock {:#x} hits {}",
            rc,
            HITS.load(Ordering::Relaxed)
        );
        exit(4);
    }
    println!("signal-ok");
}

rudra::entry!(main);
