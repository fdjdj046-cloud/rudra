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

// На каком CPU исполнился каждый поток (getcpu на старте).
static CPU_IDS: [AtomicU32; THREADS] = [
    AtomicU32::new(!0),
    AtomicU32::new(!0),
    AtomicU32::new(!0),
    AtomicU32::new(!0),
];

/// Номер CPU читается в той же функции, что и syscall.
fn cpu_now() -> u32 {
    let mut raw = [0u8; 4];
    unsafe { rudra::syscall6(309, raw.as_mut_ptr() as u64, 0, 0, 0, 0, 0) };
    u32::from_le_bytes(raw)
}

extern "C" fn worker(arg: *mut u8) {
    CPU_IDS[arg as usize].store(cpu_now(), Ordering::Relaxed);
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
            i as *mut u8,
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
    // Serial под нагрузкой теряет байты — дублируем результат в файл.
    // Без кучи: строка фиксированной длины, CPU < 10.
    let mut line = *b"threads on cpus: 0 0 0 0\n";
    for (i, ch) in line[17..24].iter_mut().step_by(2).enumerate() {
        *ch = b'0' + (CPU_IDS[i].load(Ordering::Relaxed) as u8) % 10;
    }
    let fd = unsafe {
        rudra::syscall6(2, b"/threads-cpus.txt\0".as_ptr() as u64, 0x41, 0o644, 0, 0, 0)
    };
    println!("cpus-file fd={:#x}", fd as i64);
    if (fd as i64) >= 0 {
        unsafe { rudra::syscall6(1, fd as u64, line.as_ptr() as u64, line.len() as u64, 0, 0, 0) };
        unsafe { rudra::syscall6(3, fd as u64, 0, 0, 0, 0, 0) };
    }
    println!(
        "threads on cpus: {} {} {} {}",
        CPU_IDS[0].load(Ordering::Relaxed),
        CPU_IDS[1].load(Ordering::Relaxed),
        CPU_IDS[2].load(Ordering::Relaxed),
        CPU_IDS[3].load(Ordering::Relaxed)
    );
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
