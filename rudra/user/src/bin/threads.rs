//! Многопоточность: 4 потока в общем адресном пространстве инкрементят
//! общий счётчик под спин-мьютексом. Демонстрация clone(CLONE_VM) и join.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use rudra::{print, println};

const THREADS: usize = 4;
const ITERS: u64 = 100_000;

static COUNTER: AtomicU32 = AtomicU32::new(0);
static MUTEX: rudra::Mutex = rudra::Mutex::new();

// Флаги завершения потоков (CLONE_CHILD_CLEARTID обнуляет их при exit).
static DONE: [AtomicU32; THREADS] = [
    AtomicU32::new(1),
    AtomicU32::new(1),
    AtomicU32::new(1),
    AtomicU32::new(1),
];

extern "C" fn worker(_arg: *mut u8) {
    for _ in 0..ITERS {
        MUTEX.lock();
        let v = COUNTER.load(Ordering::Relaxed) + 1;
        COUNTER.store(v, Ordering::Relaxed);
        MUTEX.unlock();
    }
}

fn main() {
    println!("spawning {} threads x {} iters...", THREADS, ITERS);
    for i in 0..THREADS {
        let tid = rudra::thread_spawn(
            &DONE[i] as *const AtomicU32 as *mut u32,
            worker,
            core::ptr::null_mut(),
        );
        if tid == u64::MAX {
            println!("thread {}: spawn failed", i);
        }
    }
    for i in 0..THREADS {
        rudra::thread_join(&DONE[i] as *const AtomicU32 as *const u32);
        print!(".");
    }
    println!();
    println!(
        "counter = {} (expected {}) — {}",
        COUNTER.load(Ordering::Relaxed),
        THREADS as u64 * ITERS,
        if COUNTER.load(Ordering::Relaxed) as u64 == THREADS as u64 * ITERS {
            "OK, race-free"
        } else {
            "RACE DETECTED"
        }
    );
}

rudra::entry!(main);
