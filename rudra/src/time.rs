//! Монотонные часы по TSC.
//!
//! `clock_gettime` и `nanosleep` считают наносекунды от TSC, откалиброванного
//! по каналу 2 PIT (1_193_182 Гц). Тик планировщика — отдельный источник
//! (LAPIC либо IRQ0) и на эти часы не влияет.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use x86_64::instructions::port::Port;

const PIT_HZ: u64 = 1_193_182;
/// ~10 мс канала 2. Ноль в счётчике означал бы 65536, поэтому число ненулевое.
const PIT2_COUNT: u16 = 11932;

static TSC_HZ: AtomicU64 = AtomicU64::new(0);
static TSC_EPOCH: AtomicU64 = AtomicU64::new(0);
static CALIBRATED: AtomicBool = AtomicBool::new(false);

pub fn tsc_hz() -> u64 {
    TSC_HZ.load(Ordering::Relaxed)
}

pub fn calibrated() -> bool {
    CALIBRATED.load(Ordering::Relaxed)
}

/// Наносекунды с конца калибровки. До калибровки — 0.
pub fn monotonic_ns() -> u64 {
    let hz = TSC_HZ.load(Ordering::Relaxed);
    if hz == 0 {
        return 0;
    }
    let now = rdtsc();
    let base = TSC_EPOCH.load(Ordering::Relaxed);
    let delta = now.wrapping_sub(base);
    ((delta as u128) * 1_000_000_000 / hz as u128) as u64
}

/// Калибровка до включения прерываний: канал 2 PIT, IRQ не нужен.
pub fn init() {
    crate::serial_println!("[time] calibrating tsc via pit channel 2");
    match calibrate_pit2() {
        Some(hz) if hz > 50_000_000 && hz < 20_000_000_000 => {
            TSC_HZ.store(hz, Ordering::Relaxed);
            TSC_EPOCH.store(rdtsc(), Ordering::Relaxed);
            CALIBRATED.store(true, Ordering::Relaxed);
            crate::serial_println!("[time] tsc {} Hz", hz);
        }
        Some(hz) => {
            crate::serial_println!("[time] pit ch2 gave implausible {} Hz", hz);
        }
        None => {
            crate::serial_println!("[time] pit ch2 did not finish");
        }
    }
}

/// Если канал 2 не сработал, два тика IRQ0 уже идущего PIT.
/// Звать после `interrupts::enable`.
pub fn finish() {
    if calibrated() {
        return;
    }
    let start_tick = crate::interrupts::TICKS.load(Ordering::Relaxed);
    let t0 = rdtsc();
    let mut spins = 0u64;
    while crate::interrupts::TICKS.load(Ordering::Relaxed).wrapping_sub(start_tick) < 2 {
        if x86_64::instructions::interrupts::are_enabled() {
            x86_64::instructions::hlt();
        } else {
            core::hint::spin_loop();
        }
        spins += 1;
        if spins > 50_000_000 {
            crate::serial_println!("[time] pit irq0 calibration failed");
            return;
        }
    }
    let ticks = crate::interrupts::TICKS.load(Ordering::Relaxed).wrapping_sub(start_tick);
    let delta = rdtsc().wrapping_sub(t0);
    if ticks == 0 || delta == 0 {
        return;
    }
    // Делитель канала 0 по умолчанию — 65536, частота тика 1193182/65536.
    let hz = (delta as u128) * (PIT_HZ as u128) / (65_536u128 * ticks as u128);
    let hz = hz as u64;
    if hz > 50_000_000 && hz < 20_000_000_000 {
        TSC_HZ.store(hz, Ordering::Relaxed);
        TSC_EPOCH.store(rdtsc(), Ordering::Relaxed);
        CALIBRATED.store(true, Ordering::Relaxed);
        crate::serial_println!("[time] tsc {} Hz (from pit irq0)", hz);
    }
}

fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "lfence",
            "rdtsc",
            "lfence",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Один отсчёт канала 2 в режиме 0. `None`, если выход не поднялся.
fn calibrate_pit2() -> Option<u64> {
    let mut command = Port::<u8>::new(0x43);
    let mut ch2 = Port::<u8>::new(0x42);
    let mut gate = Port::<u8>::new(0x61);
    unsafe {
        let orig = gate.read();
        // Бит 0 — ворота канала 2, бит 1 — динамик. Оба вниз, пока пишем счёт.
        gate.write(orig & !0x03);
        // Канал 2, младший/старший байт, режим 0, двоичный.
        command.write(0xB0);
        ch2.write(PIT2_COUNT as u8);
        ch2.write((PIT2_COUNT >> 8) as u8);
        let t0 = rdtsc();
        gate.write((orig & !0x02) | 0x01);
        let mut spins = 0u64;
        while gate.read() & 0x20 == 0 {
            core::hint::spin_loop();
            spins += 1;
            if spins > 200_000_000 {
                gate.write(orig);
                return None;
            }
        }
        let delta = rdtsc().wrapping_sub(t0);
        gate.write(orig);
        if delta < 1_000 {
            return None;
        }
        let hz = (delta as u128) * (PIT_HZ as u128) / (PIT2_COUNT as u128);
        Some(hz as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serial_print, serial_println};

    #[test_case]
    fn tsc_scale_matches_rdtsc() {
        serial_print!("test tsc_scale_matches_rdtsc... ");
        assert!(calibrated(), "tsc was not calibrated");
        let hz = tsc_hz();
        assert!(hz > 50_000_000 && hz < 20_000_000_000, "hz {}", hz);
        let t0 = monotonic_ns();
        let start = rdtsc();
        let need = hz / 200;
        while rdtsc().wrapping_sub(start) < need {
            core::hint::spin_loop();
        }
        let dt = monotonic_ns().saturating_sub(t0);
        // Пять миллисекунд по самому TSC. Ловит ошибку шкалы, не частоту PIT.
        assert!(
            (2_000_000..20_000_000).contains(&dt),
            "dt {} ns, hz {}",
            dt,
            hz
        );
        serial_println!("[ok]");
    }
}
