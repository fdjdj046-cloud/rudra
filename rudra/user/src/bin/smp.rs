//! Привязка к CPU 1 и проверка, что getcpu видит именно его.

#![no_std]
#![no_main]

use rudra::{exit, println, syscall6};

fn bad(what: &str) -> ! {
    println!("smp-bad {}", what);
    exit(1);
}

/// Номер CPU читается в той же функции, что и syscall.
fn cpu_now() -> u32 {
    let mut raw = [0u8; 4];
    let rc = unsafe { syscall6(309, raw.as_mut_ptr() as u64, 0, 0, 0, 0, 0) };
    if (rc as i64) < 0 {
        return !0;
    }
    u32::from_le_bytes(raw)
}

fn main() {
    let mut mask = [0u8; 8];
    mask[0] = 0b10;
    let rc = unsafe { syscall6(203, 0, 8, mask.as_ptr() as u64, 0, 0, 0) };
    if (rc as i64) < 0 {
        bad("affinity");
    }
    for _ in 0..2000 {
        for _ in 0..2000 {
            unsafe {
                core::arch::asm!("pause", options(nomem, nostack, preserves_flags));
            }
        }
        if cpu_now() == 1 {
            println!("smp-ok");
            exit(0);
        }
    }
    bad("cpu");
}

rudra::entry!(main);
