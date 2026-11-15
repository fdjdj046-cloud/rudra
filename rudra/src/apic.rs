//! Локальный APIC загрузочного процессора.
//!
//! Читаем базу из `IA32_APIC_BASE`, отображаем MMIO одной страницей и
//! забираем id с version. Application processors не стартуют: это ещё не SMP.
//! x2APIC не включаем. Если прошивка уже подняла x2APIC, id берём из MSR,
//! потому что MMIO в этом режиме отключено.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use x86_64::registers::model_specific::Msr;
use x86_64::structures::paging::{FrameAllocator, Mapper, Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

const IA32_APIC_BASE: u32 = 0x1B;
const IA32_X2APIC_APICID: u32 = 0x802;
/// Сразу за кучей `0x4444_4444_0000` + 48 МиБ, одна страница.
const APIC_VIRT: u64 = 0x4444_4800_0000;

static PRESENT: AtomicBool = AtomicBool::new(false);
static APIC_ID: AtomicU32 = AtomicU32::new(0);
static APIC_VERSION: AtomicU32 = AtomicU32::new(0);

pub fn present() -> bool {
    PRESENT.load(Ordering::Relaxed)
}

pub fn id() -> u32 {
    APIC_ID.load(Ordering::Relaxed)
}

pub fn version() -> u32 {
    APIC_VERSION.load(Ordering::Relaxed)
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
    crate::serial_println!(
        "[apic] base {:#x} bsp {} id {} version {:#x} (APs not started)",
        phys,
        bsp,
        id,
        version
    );
}

fn read32(offset: u64) -> u32 {
    unsafe { core::ptr::read_volatile((APIC_VIRT + offset) as *const u32) }
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
}
