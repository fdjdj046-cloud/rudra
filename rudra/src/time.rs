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
/// `unix_ns - monotonic_ns` на момент чтения RTC. 0, пока RTC не прочитан.
static REALTIME_BASE: AtomicU64 = AtomicU64::new(0);
static REALTIME_OK: AtomicBool = AtomicBool::new(false);

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

/// UTC в наносекундах. Без удачного RTC это те же монотонные часы, не календарь.
pub fn realtime_ns() -> u64 {
    if !REALTIME_OK.load(Ordering::Relaxed) {
        return monotonic_ns();
    }
    monotonic_ns().saturating_add(REALTIME_BASE.load(Ordering::Relaxed))
}

/// Прочитать CMOS RTC один раз и запомнить сдвиг к [`monotonic_ns`].
pub fn init_realtime() {
    match read_rtc_unix() {
        Some(sec) if (1_577_836_800..4_102_444_800).contains(&sec) => {
            let mono = monotonic_ns();
            let unix_ns = sec.saturating_mul(1_000_000_000);
            REALTIME_BASE.store(unix_ns.saturating_sub(mono), Ordering::Relaxed);
            REALTIME_OK.store(true, Ordering::Relaxed);
            crate::serial_println!("[time] rtc unix {} s", sec);
        }
        Some(sec) => crate::serial_println!("[time] rtc unix {} s rejected", sec),
        None => crate::serial_println!("[time] rtc unread, realtime stays monotonic"),
    }
}

fn cmos_read(index: u8) -> u8 {
    let mut idx = Port::<u8>::new(0x70);
    let mut data = Port::<u8>::new(0x71);
    unsafe {
        idx.write(index | 0x80);
        data.read()
    }
}

fn cmos_wait_ready() -> bool {
    for _ in 0..1_000_000 {
        if cmos_read(0x0A) & 0x80 == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn bcd_or_bin(v: u8, binary: bool) -> u8 {
    if binary {
        v
    } else {
        (v >> 4) * 10 + (v & 0x0F)
    }
}

/// Секунды Unix с CMOS. `None`, если часы не отдают устойчивое значение.
fn read_rtc_unix() -> Option<u64> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        if !cmos_wait_ready() {
            return None;
        }
        let first = read_rtc_raw()?;
        if !cmos_wait_ready() {
            return None;
        }
        let second = read_rtc_raw()?;
        if first != second {
            if !cmos_wait_ready() {
                return None;
            }
            read_rtc_raw()
        } else {
            Some(first)
        }
    })
}

fn read_rtc_raw() -> Option<u64> {
    let status_b = cmos_read(0x0B);
    let binary = status_b & 0x04 != 0;
    let hour24 = status_b & 0x02 != 0;
    let mut sec = bcd_or_bin(cmos_read(0x00), binary) as u64;
    let min = bcd_or_bin(cmos_read(0x02), binary) as u64;
    let hour_raw = cmos_read(0x04);
    let mut hour = bcd_or_bin(hour_raw & 0x7F, binary) as u64;
    if !hour24 {
        let pm = hour_raw & 0x80 != 0;
        if hour == 12 {
            hour = 0;
        }
        if pm {
            hour += 12;
        }
    }
    let day = bcd_or_bin(cmos_read(0x07), binary) as u64;
    let month = bcd_or_bin(cmos_read(0x08), binary) as u64;
    let mut year = bcd_or_bin(cmos_read(0x09), binary) as u64;
    if year < 100 {
        year += 2000;
    }
    if !(1..=60).contains(&sec) && sec != 0 {
        return None;
    }
    if sec == 60 {
        sec = 59;
    }
    if min > 59 || hour > 23 || day == 0 || day > 31 || month == 0 || month > 12 {
        return None;
    }
    Some(civil_to_unix(year, month, day, hour, min, sec))
}

/// Дни Howard Hinnant, затем секунды. Год — полный (2026, не 26).
fn civil_to_unix(year: u64, month: u64, day: u64, hour: u64, min: u64, sec: u64) -> u64 {
    let mut y = year as i64;
    let m = month as i64;
    let d = day as i64;
    y -= if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u64;
    let days = era * 146097 + doe as i64 - 719468;
    (days as u64) * 86400 + hour * 3600 + min * 60 + sec
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

    #[test_case]
    fn rtc_realtime_is_a_calendar() {
        serial_print!("test rtc_realtime_is_a_calendar... ");
        assert!(REALTIME_OK.load(Ordering::Relaxed), "rtc was not read");
        let sec = realtime_ns() / 1_000_000_000;
        assert!(
            (1_735_689_600..1_893_456_000).contains(&sec),
            "unix {}",
            sec
        );
        serial_println!("[ok] unix {}", sec);
    }
}
