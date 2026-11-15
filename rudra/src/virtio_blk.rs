//! Legacy virtio-blk по PCI (device id `0x1001`, один virtqueue).
//!
//! QEMU запускаем с `disable-modern=on`: тогда BAR0 — порт ввода-вывода,
//! а не MMIO capability современного virtio 1.0. Возможности согласуем
//! (читаем host features, гостю оставляем 0 — базовый IN/OUT не за флагом).
//! Прерывание не ждём: `VIRTQ_AVAIL_F_NO_INTERRUPT` и опрос used-кольца.

use core::sync::atomic::{fence, Ordering};
use spin::Mutex;
use x86_64::instructions::port::Port;

use crate::memory::alloc_contiguous;

const VIRTIO_VENDOR: u16 = 0x1AF4;
const VIRTIO_BLK_LEGACY: u16 = 0x1001;

const STATUS_ACK: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FAILED: u8 = 128;

const T_IN: u32 = 0;
const T_OUT: u32 = 1;

const DESC_NEXT: u16 = 1;
const DESC_WRITE: u16 = 2;
const AVAIL_NO_INTERRUPT: u16 = 1;

const SECTOR: usize = 512;
const DATA_PAGES: usize = 1;

struct Dev {
    io: u16,
    qsize: u16,
    /// Виртуальный адрес начала очереди (desc, потом avail, потом used).
    queue: u64,
    used_off: usize,
    capacity: u64,
    hdr: u64,
    hdr_phys: u64,
    data: u64,
    data_phys: u64,
    seen: u16,
}

static DEV: Mutex<Option<Dev>> = Mutex::new(None);

fn phys_to_virt(phys: u64) -> u64 {
    crate::PHYS_OFFSET.load(Ordering::Relaxed) + phys
}

fn in32(io: u16, off: u16) -> u32 {
    unsafe { Port::<u32>::new(io + off).read() }
}
fn out32(io: u16, off: u16, v: u32) {
    unsafe { Port::<u32>::new(io + off).write(v) }
}
fn in16(io: u16, off: u16) -> u16 {
    unsafe { Port::<u16>::new(io + off).read() }
}
fn out16(io: u16, off: u16, v: u16) {
    unsafe { Port::<u16>::new(io + off).write(v) }
}
fn in8(io: u16, off: u16) -> u8 {
    unsafe { Port::<u8>::new(io + off).read() }
}
fn out8(io: u16, off: u16, v: u8) {
    unsafe { Port::<u8>::new(io + off).write(v) }
}

fn vring_used_off(qsize: usize) -> usize {
    // Как vring_init в Linux: после ring[num] лежит used_event (u16),
    // used-кольцо начинается со следующей страницы.
    let raw = qsize * 16 + 6 + 2 * qsize;
    (raw + 4095) & !4095
}

fn vring_pages(qsize: usize) -> usize {
    let bytes = vring_used_off(qsize) + 4 + 8 * qsize;
    (bytes + 4095) / 4096
}

/// Поднять устройство. Повторять нельзя: очередь выделяется один раз.
pub fn init() -> Result<(), &'static str> {
    let Some((slot, func)) = crate::pci::find(VIRTIO_VENDOR, VIRTIO_BLK_LEGACY) else {
        return Err("no 1af4:1001");
    };
    let irq = crate::pci::interrupt_line(slot, func);
    crate::interrupts::mask_irq(irq);
    crate::pci::enable_io_bus_master(slot, func);
    let Some(io) = crate::pci::bar0_io(slot, func) else {
        crate::serial_println!("[virtio-blk] BAR0 is not an IO port (need disable-modern=on)");
        return Err("bar");
    };

    // Сброс и согласование. Legacy-регистр features — младшие 32 бита.
    out8(io, 0x12, 0);
    for _ in 0..100_000 {
        if in8(io, 0x12) == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    out8(io, 0x12, STATUS_ACK);
    out8(io, 0x12, STATUS_ACK | STATUS_DRIVER);
    let host = in32(io, 0x00);
    let guest = 0u32;
    out32(io, 0x04, guest);

    out16(io, 0x0E, 0);
    let qsize = in16(io, 0x0C);
    if qsize == 0 || qsize > 256 {
        out8(io, 0x12, STATUS_FAILED);
        crate::serial_println!("[virtio-blk] bad queue size {}", qsize);
        return Err("qsize");
    }
    let pages = vring_pages(qsize as usize);
    let Some(queue_phys) = alloc_contiguous(pages) else {
        out8(io, 0x12, STATUS_FAILED);
        return Err("queue mem");
    };
    let Some(hdr_phys) = alloc_contiguous(1) else {
        out8(io, 0x12, STATUS_FAILED);
        return Err("hdr mem");
    };
    let Some(data_phys) = alloc_contiguous(DATA_PAGES) else {
        out8(io, 0x12, STATUS_FAILED);
        return Err("data mem");
    };
    let queue = phys_to_virt(queue_phys);
    let hdr = phys_to_virt(hdr_phys);
    let data = phys_to_virt(data_phys);
    unsafe {
        core::ptr::write_bytes(queue as *mut u8, 0, pages * 4096);
        core::ptr::write_bytes(hdr as *mut u8, 0, 4096);
        core::ptr::write_bytes(data as *mut u8, 0, DATA_PAGES * 4096);
        // Не хотим INTx на каждый запрос.
        (queue as *mut u8).add(qsize as usize * 16).cast::<u16>().write_volatile(AVAIL_NO_INTERRUPT);
    }
    out32(io, 0x08, (queue_phys >> 12) as u32);
    out8(io, 0x12, STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK);

    let cap_lo = in32(io, 0x14);
    let cap_hi = in32(io, 0x18);
    let capacity = (cap_hi as u64) << 32 | cap_lo as u64;
    crate::serial_println!(
        "[virtio-blk] io {:#x} queue {} capacity {} host-features {:#x} guest-features {:#x} irq {}",
        io,
        qsize,
        capacity,
        host,
        guest,
        irq
    );

    *DEV.lock() = Some(Dev {
        io,
        qsize,
        queue,
        used_off: vring_used_off(qsize as usize),
        capacity,
        hdr,
        hdr_phys,
        data,
        data_phys,
        seen: 0,
    });
    Ok(())
}

pub fn capacity() -> Option<u64> {
    DEV.lock().as_ref().map(|d| d.capacity)
}

pub fn present() -> bool {
    DEV.lock().is_some()
}

/// Прочитать `buf.len()` байт с сектора `lba`. Длина кратна 512 и не больше DMA-страницы.
///
/// Прерывания выключены на всё время: `DEV` — обычный spinlock, таймер
/// не должен вытеснить задачу, которая его держит.
pub fn read_sectors(lba: u64, buf: &mut [u8]) -> Result<(), &'static str> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        check_len(lba, buf.len())?;
        let mut guard = DEV.lock();
        let dev = guard.as_mut().ok_or("no dev")?;
        dev.request(lba, buf.len(), false)?;
        unsafe {
            core::ptr::copy_nonoverlapping(dev.data as *const u8, buf.as_mut_ptr(), buf.len());
        }
        Ok(())
    })
}

/// Записать `buf.len()` байт с сектора `lba`.
pub fn write_sectors(lba: u64, buf: &[u8]) -> Result<(), &'static str> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        check_len(lba, buf.len())?;
        let mut guard = DEV.lock();
        let dev = guard.as_mut().ok_or("no dev")?;
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), dev.data as *mut u8, buf.len());
        }
        dev.request(lba, buf.len(), true)
    })
}

fn check_len(lba: u64, len: usize) -> Result<(), &'static str> {
    if len == 0 || len % SECTOR != 0 || len > DATA_PAGES * 4096 {
        return Err("len");
    }
    let dev = DEV.lock();
    let dev = dev.as_ref().ok_or("no dev")?;
    if lba.checked_add((len / SECTOR) as u64).ok_or("range")? > dev.capacity {
        return Err("range");
    }
    Ok(())
}

impl Dev {
    fn request(&mut self, lba: u64, len: usize, write: bool) -> Result<(), &'static str> {
        let kind = if write { T_OUT } else { T_IN };
        unsafe {
            let h = self.hdr as *mut u8;
            (h as *mut u32).write_unaligned(kind);
            (h.add(4) as *mut u32).write_unaligned(0);
            (h.add(8) as *mut u64).write_unaligned(lba);
            h.add(16).write(0xFF); // status, устройство пишет 0 при успехе
            write_desc(self.queue, 0, self.hdr_phys, 16, DESC_NEXT, 1);
            let data_flags = DESC_NEXT | if write { 0 } else { DESC_WRITE };
            write_desc(self.queue, 1, self.data_phys, len as u32, data_flags, 2);
            write_desc(self.queue, 2, self.hdr_phys + 16, 1, DESC_WRITE, 0);
        }

        let qsize = self.qsize as usize;
        let slot = (self.seen as usize) % qsize;
        let avail = self.queue + (qsize * 16) as u64;
        unsafe {
            let ring = (avail as *mut u8).add(4) as *mut u16;
            ring.add(slot).write_volatile(0); // голова цепочки — дескриптор 0
            fence(Ordering::SeqCst);
            let idx = (avail as *mut u8).add(2) as *mut u16;
            idx.write_volatile(self.seen.wrapping_add(1));
            fence(Ordering::SeqCst);
        }
        out16(self.io, 0x10, 0);
        // Чтение ISR гасит бит, если линия всё же дёрнулась.
        let _ = in8(self.io, 0x13);

        let mut spins = 0u32;
        let done = loop {
            let idx = unsafe {
                ((self.queue + self.used_off as u64 + 2) as *const u16).read_volatile()
            };
            if idx != self.seen {
                break idx;
            }
            spins += 1;
            if spins > 5_000_000 {
                crate::serial_println!("[virtio-blk] timeout lba {} write {}", lba, write as u8);
                return Err("timeout");
            }
            core::hint::spin_loop();
        };
        self.seen = done;
        fence(Ordering::SeqCst);
        let status = unsafe { ((self.hdr + 16) as *const u8).read_volatile() };
        if status != 0 {
            crate::serial_println!("[virtio-blk] status {} lba {}", status, lba);
            return Err("status");
        }
        Ok(())
    }
}

unsafe fn write_desc(queue: u64, i: usize, addr: u64, len: u32, flags: u16, next: u16) {
    let p = (queue as *mut u8).add(i * 16);
    (p as *mut u64).write_unaligned(addr);
    (p.add(8) as *mut u32).write_unaligned(len);
    (p.add(12) as *mut u16).write_unaligned(flags);
    (p.add(14) as *mut u16).write_unaligned(next);
}
