//! Локальный APIC загрузочного процессора.
//!
//! Читаем базу из `IA32_APIC_BASE`, отображаем MMIO одной страницей и
//! забираем id с version. x2APIC не включаем. Если прошивка уже подняла x2APIC,
//! id берём из MSR, потому что MMIO в этом режиме отключено, и старт AP
//! пропускается: IPI ниже ходят через xAPIC ICR.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use x86_64::registers::model_specific::Msr;
use x86_64::structures::paging::{FrameAllocator, Mapper, Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

const IA32_APIC_BASE: u32 = 0x1B;
const IA32_X2APIC_APICID: u32 = 0x802;
/// Сразу за кучей `0x4444_4444_0000` + 48 МиБ, одна страница.
const APIC_VIRT: u64 = 0x4444_4800_0000;

static PRESENT: AtomicBool = AtomicBool::new(false);
static MMIO: AtomicBool = AtomicBool::new(false);
static APIC_ID: AtomicU32 = AtomicU32::new(0);
static APIC_VERSION: AtomicU32 = AtomicU32::new(0);
static TIMER_ARMED: AtomicBool = AtomicBool::new(false);
static TIMER_HZ: AtomicU64 = AtomicU64::new(0);
/// Начальный счёт, которым BSP завёл periodic. Ноль — таймер не калиброван.
static TIMER_COUNT: AtomicU32 = AtomicU32::new(0);

/// Вектор IDT для таймера локального APIC. PIC занимает 32..=47.
pub const TIMER_VECTOR: u8 = 48;
const TIMER_TARGET_HZ: u64 = 250;

pub fn present() -> bool {
    PRESENT.load(Ordering::Relaxed)
}

pub fn id() -> u32 {
    APIC_ID.load(Ordering::Relaxed)
}

/// Id локального APIC того CPU, который выполняет чтение. `id` — кэш BSP.
pub fn local_id() -> u32 {
    if MMIO.load(Ordering::Relaxed) {
        read32(0x20) >> 24
    } else {
        APIC_ID.load(Ordering::Relaxed)
    }
}

pub fn timer_count() -> u32 {
    TIMER_COUNT.load(Ordering::Relaxed)
}

pub fn version() -> u32 {
    APIC_VERSION.load(Ordering::Relaxed)
}

pub fn timer_armed() -> bool {
    TIMER_ARMED.load(Ordering::Relaxed)
}

pub fn timer_hz() -> u64 {
    TIMER_HZ.load(Ordering::Relaxed)
}

pub fn mmio_ready() -> bool {
    MMIO.load(Ordering::Relaxed)
}

pub fn init(mapper: &mut impl Mapper<Size4KiB>, fa: &mut impl FrameAllocator<Size4KiB>) {
    let mut msr = Msr::new(IA32_APIC_BASE);
    let mut base = unsafe { msr.read() };
    let bsp = base & (1 << 8) != 0;
    if base & (1 << 11) == 0 {
        base |= 1 << 11;
        unsafe { msr.write(base) };
    }
    let x2apic = base & (1 << 10) != 0;
    let phys = base & 0xFFFF_F000;

    if x2apic {
        let id = unsafe { Msr::new(IA32_X2APIC_APICID).read() } as u32;
        APIC_ID.store(id, Ordering::Relaxed);
        PRESENT.store(true, Ordering::Relaxed);
        crate::serial_println!("[apic] x2apic bsp {} id {} (APs not started)", bsp, id);
        return;
    }

    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(APIC_VIRT));
    let frame = match PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(phys)) {
        Ok(f) => f,
        Err(_) => {
            crate::serial_println!("[apic] base {:#x} is not page-aligned", phys);
            return;
        }
    };
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
    // SAFETY: phys — страница MMIO локального APIC из IA32_APIC_BASE, virt свободен
    // (выше кучи). Кадры таблиц страниц выдаёт переданный аллокатор.
    let mapped = unsafe { mapper.map_to(page, frame, flags, fa) };
    match mapped {
        Ok(flush) => flush.flush(),
        Err(e) => {
            crate::serial_println!("[apic] map {:#x} failed: {:?}", phys, e);
            return;
        }
    }

    let id = read32(0x20) >> 24;
    let version = read32(0x30) & 0xFF;
    if version == 0 {
        crate::serial_println!("[apic] version 0 at {:#x}, ignoring", phys);
        return;
    }
    APIC_ID.store(id, Ordering::Relaxed);
    APIC_VERSION.store(version, Ordering::Relaxed);
    PRESENT.store(true, Ordering::Relaxed);
    MMIO.store(true, Ordering::Relaxed);
    crate::serial_println!(
        "[apic] base {:#x} bsp {} id {} version {:#x}",
        phys,
        bsp,
        id,
        version
    );
}

/// Включить периодический таймер ~250 Гц и замаскировать IRQ0 PIT.
/// Период меряем по приходу IRQ, не по регистру текущего счёта: в QEMU
/// эти две шкалы расходятся. Без удачной калибровки планировщик остаётся на PIT.
pub fn start_timer() {
    if !MMIO.load(Ordering::Relaxed) || !crate::time::calibrated() {
        crate::serial_println!("[apic] timer stays on pit");
        return;
    }
    let svr = read32(0xF0);
    write32(0xF0, (svr & !0x1FF) | 0x1FF);
    // Делитель 16 (биты 0 и 1 регистра DCR; бит 2 зарезервирован).
    write32(0x3E0, 0x3);

    // Старт с середины периода: два фронта IRQ0 — это от ~55 мс до ~110 мс, не ровно два кванта.
    let pit_ns = pit_ticks_ns(2);
    crate::serial_println!("[time] 2 pit irq0 ticks = {} ns", pit_ns);

    const PROBE: u32 = 100_000;
    let probed = match measure_ticks_ns(PROBE, 16) {
        Some(ns) if ns > 1_000_000 => ns,
        Some(ns) => {
            crate::serial_println!("[apic] timer probe too fast: {} ns", ns);
            crate::interrupts::unmask_pit();
            TIMER_ARMED.store(false, Ordering::Relaxed);
            return;
        }
        None => {
            crate::serial_println!("[apic] timer probe got no ticks");
            crate::interrupts::unmask_pit();
            TIMER_ARMED.store(false, Ordering::Relaxed);
            return;
        }
    };
    // 16 тиков должны занять 16/250 с.
    let want = 16 * 1_000_000_000 / TIMER_TARGET_HZ;
    let initial = (u64::from(PROBE)).saturating_mul(want) / probed;
    if initial == 0 || initial > u32::MAX as u64 {
        crate::serial_println!("[apic] timer initial count {} unusable", initial);
        crate::interrupts::unmask_pit();
        TIMER_ARMED.store(false, Ordering::Relaxed);
        return;
    }
    arm_periodic(initial as u32);
    TIMER_HZ.store(TIMER_TARGET_HZ, Ordering::Relaxed);
    crate::serial_println!(
        "[apic] timer {} Hz, count {} (probe {} ns, pit irq0 masked)",
        TIMER_TARGET_HZ,
        initial,
        probed
    );
}

fn pit_ticks_ns(ticks: u64) -> u64 {
    let start = crate::time::monotonic_ns();
    let base = crate::interrupts::TICKS.load(Ordering::Relaxed);
    let mut spins = 0u64;
    while crate::interrupts::TICKS
        .load(Ordering::Relaxed)
        .wrapping_sub(base)
        < ticks
    {
        x86_64::instructions::hlt();
        spins += 1;
        if spins > 1_000_000 {
            return 0;
        }
    }
    crate::time::monotonic_ns().saturating_sub(start)
}

/// Замаскировать PIT, запустить periodic и дождаться `ticks` целых периодов.
fn measure_ticks_ns(count: u32, ticks: u64) -> Option<u64> {
    arm_periodic(count);
    let warmup = crate::interrupts::TICKS.load(Ordering::Relaxed);
    let mut spins = 0u64;
    while crate::interrupts::TICKS
        .load(Ordering::Relaxed)
        .wrapping_sub(warmup)
        < 2
    {
        x86_64::instructions::hlt();
        spins += 1;
        if spins > 5_000_000 {
            return None;
        }
    }
    let start = crate::time::monotonic_ns();
    let base = crate::interrupts::TICKS.load(Ordering::Relaxed);
    spins = 0;
    while crate::interrupts::TICKS
        .load(Ordering::Relaxed)
        .wrapping_sub(base)
        < ticks
    {
        x86_64::instructions::hlt();
        spins += 1;
        if spins > 5_000_000 {
            return None;
        }
    }
    Some(crate::time::monotonic_ns().saturating_sub(start))
}

fn arm_periodic(count: u32) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        crate::interrupts::mask_pit();
        // Бит 17 — periodic, бит 16 (маска) снят.
        write32(0x320, u32::from(TIMER_VECTOR) | (1 << 17));
        write32(0x380, count);
        TIMER_ARMED.store(true, Ordering::Relaxed);
        TIMER_COUNT.store(count, Ordering::Relaxed);
    });
}

/// Таймер того AP, с которого нас позвали. LINT маскируются, таймер — нет.
/// Тот же период, что у BSP. Нулевой счёт значит, что калибровки не было.
pub fn arm_ap_timer() {
    let count = TIMER_COUNT.load(Ordering::Relaxed);
    if count == 0 {
        return;
    }
    let svr = read32(0xF0);
    write32(0xF0, (svr & !0x1FF) | 0x1FF);
    for off in [0x350u64, 0x360, 0x370] {
        let v = read32(off);
        write32(off, v | (1 << 16));
    }
    write32(0x3E0, 0x3);
    write32(0x320, u32::from(TIMER_VECTOR) | (1 << 17));
    write32(0x380, count);
}

pub fn eoi() {
    write32(0xB0, 0);
}

fn wait_icr() -> bool {
    for _ in 0..1_000_000 {
        if read32(0x300) & (1 << 12) == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// INIT IPI одному APIC id. xAPIC, destination в старшем байте ICR.
pub fn send_init(dest: u32) -> bool {
    if !MMIO.load(Ordering::Relaxed) || dest > 0xFF || !wait_icr() {
        return false;
    }
    write32(0x310, dest << 24);
    write32(0x300, 0x4500);
    wait_icr()
}

/// SIPI. `vector` — физическая страница трамплина >> 12.
pub fn send_startup(dest: u32, vector: u8) -> bool {
    if !MMIO.load(Ordering::Relaxed) || dest > 0xFF || !wait_icr() {
        return false;
    }
    write32(0x310, dest << 24);
    write32(0x300, 0x4600 | u32::from(vector));
    wait_icr()
}

/// Обычный IPI (fixed, physical, edge).
pub fn send_fixed(dest: u32, vector: u8) -> bool {
    if !MMIO.load(Ordering::Relaxed) || dest > 0xFF || !wait_icr() {
        return false;
    }
    write32(0x310, dest << 24);
    write32(0x300, u32::from(vector) | (1 << 14));
    wait_icr()
}

fn read32(offset: u64) -> u32 {
    unsafe { core::ptr::read_volatile((APIC_VIRT + offset) as *const u32) }
}

fn write32(offset: u64, value: u32) {
    unsafe { core::ptr::write_volatile((APIC_VIRT + offset) as *mut u32, value) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serial_print, serial_println};

    #[test_case]
    fn bsp_apic_is_readable() {
        serial_print!("test bsp_apic_is_readable... ");
        assert!(present(), "local apic was not identified");
        assert!(
            version() > 0 && version() < 0x20,
            "version {:#x}",
            version()
        );
        serial_println!("[ok] id {} version {:#x}", id(), version());
    }

    #[test_case]
    fn lapic_timer_period() {
        serial_print!("test lapic_timer_period... ");
        assert!(timer_armed(), "lapic timer was not armed");
        assert_eq!(timer_hz(), 250);
        let t0 = crate::time::monotonic_ns();
        let tick0 = crate::interrupts::TICKS.load(Ordering::Relaxed);
        while crate::interrupts::TICKS
            .load(Ordering::Relaxed)
            .wrapping_sub(tick0)
            < 8
        {
            x86_64::instructions::hlt();
        }
        let dt = crate::time::monotonic_ns().saturating_sub(t0);
        // 8 тиков по 4 мс. Допуск — ошибка калибровки и неполный первый период.
        assert!(
            (10_000_000..80_000_000).contains(&dt),
            "dt {} ns over 8 ticks",
            dt
        );
        serial_println!("[ok]");
    }
}
