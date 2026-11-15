//! Legacy virtio-net по PCI, device id `0x1000`.
//!
//! Как у virtio-blk: QEMU с `disable-modern=on`, BAR0 — порты ввода-вывода.
//! Очередь 0 — приём, очередь 1 — передача. Прерывание не ждём.
//! Гостю оставляем только бит MAC. `VIRTIO_NET_F_MRG_RXBUF` не согласуем,
//! поэтому заголовок пакета — 10 байт, не 12.

use core::sync::atomic::{fence, Ordering};
use spin::Mutex;
use x86_64::instructions::port::Port;

use crate::memory::alloc_contiguous;

const VIRTIO_VENDOR: u16 = 0x1AF4;
const VIRTIO_NET_LEGACY: u16 = 0x1000;

const STATUS_ACK: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FAILED: u8 = 128;

const DESC_WRITE: u16 = 2;
const AVAIL_NO_INTERRUPT: u16 = 1;
const NET_HDR: usize = 10;
const RX_BUFS: usize = 8;

struct Queue {
    virt: u64,
    qsize: usize,
    used_off: usize,
    /// Свободный счётчик used.idx, который мы уже забрали.
    seen: u16,
    /// Следующий avail.idx, который запишем.
    avail: u16,
}

struct Dev {
    io: u16,
    mac: [u8; 6],
    rx: Queue,
    tx: Queue,
    rx_virt: [u64; RX_BUFS],
    nbufs: usize,
    tx_phys: u64,
    tx_virt: u64,
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
    let raw = qsize * 16 + 6 + 2 * qsize;
    (raw + 4095) & !4095
}

fn vring_pages(qsize: usize) -> usize {
    let bytes = vring_used_off(qsize) + 4 + 8 * qsize;
    (bytes + 4095) / 4096
}

pub fn present() -> bool {
    x86_64::instructions::interrupts::without_interrupts(|| DEV.lock().is_some())
}

pub fn mac() -> Option<[u8; 6]> {
    x86_64::instructions::interrupts::without_interrupts(|| DEV.lock().as_ref().map(|d| d.mac))
}

/// Поднять устройство. Повторный вызов ничего не делает, если оно уже есть.
pub fn init() -> Result<[u8; 6], &'static str> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        if let Some(dev) = DEV.lock().as_ref() {
            return Ok(dev.mac);
        }
        let Some((slot, func)) = crate::pci::find(VIRTIO_VENDOR, VIRTIO_NET_LEGACY) else {
            return Err("no 1af4:1000");
        };
        let irq = crate::pci::interrupt_line(slot, func);
        crate::interrupts::mask_irq(irq);
        crate::pci::enable_io_bus_master(slot, func);
        let Some(io) = crate::pci::bar0_io(slot, func) else {
            crate::serial_println!("[virtio-net] BAR0 is not an IO port (need disable-modern=on)");
            return Err("bar");
        };
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
        // Бит 5 — MAC. Остальное (CSUM, MRG_RXBUF, контроль) не берём.
        let guest = host & (1 << 5);
        out32(io, 0x04, guest);

        let rx = match setup_queue(io, 0) {
            Ok(q) => q,
            Err(e) => {
                out8(io, 0x12, STATUS_FAILED);
                return Err(e);
            }
        };
        let tx = match setup_queue(io, 1) {
            Ok(q) => q,
            Err(e) => {
                out8(io, 0x12, STATUS_FAILED);
                return Err(e);
            }
        };
        let nbufs = RX_BUFS.min(rx.qsize);
        if nbufs == 0 {
            out8(io, 0x12, STATUS_FAILED);
            return Err("qsize");
        }
        let mut rx_virt = [0u64; RX_BUFS];
        for i in 0..nbufs {
            let Some(phys) = alloc_contiguous(1) else {
                out8(io, 0x12, STATUS_FAILED);
                return Err("rx mem");
            };
            let virt = phys_to_virt(phys);
            unsafe { core::ptr::write_bytes(virt as *mut u8, 0, 4096) };
            rx_virt[i] = virt;
            unsafe { write_desc(rx.virt, i, phys, 4096, DESC_WRITE, 0) };
        }
        let Some(tx_phys) = alloc_contiguous(1) else {
            out8(io, 0x12, STATUS_FAILED);
            return Err("tx mem");
        };
        let tx_virt = phys_to_virt(tx_phys);
        unsafe { core::ptr::write_bytes(tx_virt as *mut u8, 0, 4096) };

        post_avail(&rx, nbufs);
        out8(io, 0x12, STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK);
        out16(io, 0x10, 0);
        let _ = in8(io, 0x13);

        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = in8(io, 0x14 + i as u16);
        }
        crate::serial_println!(
            "[virtio-net] io {:#x} mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} q {} host {:#x}",
            io,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5],
            rx.qsize,
            host
        );
        let mut rxq = rx;
        rxq.avail = nbufs as u16;
        *DEV.lock() = Some(Dev {
            io,
            mac,
            rx: rxq,
            tx,
            rx_virt,
            nbufs,
            tx_phys,
            tx_virt,
        });
        Ok(mac)
    })
}

fn setup_queue(io: u16, index: u16) -> Result<Queue, &'static str> {
    out16(io, 0x0E, index);
    let qsize = in16(io, 0x0C) as usize;
    if qsize == 0 || qsize > 1024 {
        crate::serial_println!("[virtio-net] bad queue {} size {}", index, qsize);
        return Err("qsize");
    }
    let pages = vring_pages(qsize);
    let Some(phys) = alloc_contiguous(pages) else {
        return Err("queue mem");
    };
    let virt = phys_to_virt(phys);
    unsafe {
        core::ptr::write_bytes(virt as *mut u8, 0, pages * 4096);
        (virt as *mut u8)
            .add(qsize * 16)
            .cast::<u16>()
            .write_volatile(AVAIL_NO_INTERRUPT);
    }
    out32(io, 0x08, (phys >> 12) as u32);
    Ok(Queue {
        virt,
        qsize,
        used_off: vring_used_off(qsize),
        seen: 0,
        avail: 0,
    })
}

/// Заполнить avail кольца приёма дескрипторами `0..nbufs`.
fn post_avail(rx: &Queue, nbufs: usize) {
    let avail = rx.virt + (rx.qsize * 16) as u64;
    unsafe {
        let ring = (avail as *mut u8).add(4) as *mut u16;
        for i in 0..nbufs {
            ring.add(i).write_volatile(i as u16);
        }
        fence(Ordering::SeqCst);
        let idx = (avail as *mut u8).add(2) as *mut u16;
        idx.write_volatile(nbufs as u16);
        fence(Ordering::SeqCst);
    }
}

/// Один кадр Ethernet без заголовка virtio. `None` — кольцо пусто.
pub fn recv_frame(out: &mut [u8]) -> Option<usize> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut guard = DEV.lock();
        let dev = guard.as_mut()?;
        dev.rx_one(out)
    })
}

/// Отправить кадр Ethernet. Длина 14..=1514.
pub fn send_frame(frame: &[u8]) -> Result<(), &'static str> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut guard = DEV.lock();
        let dev = guard.as_mut().ok_or("no dev")?;
        dev.tx_one(frame)
    })
}

impl Dev {
    fn rx_one(&mut self, out: &mut [u8]) -> Option<usize> {
        let used = self.rx.virt + self.rx.used_off as u64;
        let idx = unsafe { ((used + 2) as *const u16).read_volatile() };
        if idx == self.rx.seen {
            return None;
        }
        let slot = (self.rx.seen as usize) % self.rx.qsize;
        let elem = used + 4 + (slot * 8) as u64;
        let id = unsafe { (elem as *const u32).read_volatile() } as usize;
        let len = unsafe { ((elem + 4) as *const u32).read_volatile() } as usize;
        self.rx.seen = self.rx.seen.wrapping_add(1);
        fence(Ordering::SeqCst);
        let n = if id < self.nbufs && len > NET_HDR {
            let take = (len - NET_HDR).min(out.len()).min(1514);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (self.rx_virt[id] as *const u8).add(NET_HDR),
                    out.as_mut_ptr(),
                    take,
                );
            }
            take
        } else {
            0
        };
        if id < self.nbufs {
            self.repost(id);
        }
        if n == 0 {
            None
        } else {
            Some(n)
        }
    }

    fn repost(&mut self, id: usize) {
        let avail = self.rx.virt + (self.rx.qsize * 16) as u64;
        let slot = (self.rx.avail as usize) % self.rx.qsize;
        unsafe {
            let ring = (avail as *mut u8).add(4) as *mut u16;
            ring.add(slot).write_volatile(id as u16);
            fence(Ordering::SeqCst);
            let idx = (avail as *mut u8).add(2) as *mut u16;
            let next = self.rx.avail.wrapping_add(1);
            idx.write_volatile(next);
            fence(Ordering::SeqCst);
            self.rx.avail = next;
        }
        out16(self.io, 0x10, 0);
        let _ = in8(self.io, 0x13);
    }

    fn tx_one(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        if !(14..=1514).contains(&frame.len()) {
            return Err("len");
        }
        let total = NET_HDR + frame.len();
        unsafe {
            core::ptr::write_bytes(self.tx_virt as *mut u8, 0, NET_HDR);
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                (self.tx_virt as *mut u8).add(NET_HDR),
                frame.len(),
            );
            write_desc(self.tx.virt, 0, self.tx_phys, total as u32, 0, 0);
        }
        let avail = self.tx.virt + (self.tx.qsize * 16) as u64;
        let slot = (self.tx.avail as usize) % self.tx.qsize;
        unsafe {
            let ring = (avail as *mut u8).add(4) as *mut u16;
            ring.add(slot).write_volatile(0);
            fence(Ordering::SeqCst);
            let idxp = (avail as *mut u8).add(2) as *mut u16;
            let next = self.tx.avail.wrapping_add(1);
            idxp.write_volatile(next);
            fence(Ordering::SeqCst);
            self.tx.avail = next;
        }
        out16(self.io, 0x10, 1);
        let _ = in8(self.io, 0x13);
        let deadline = crate::time::monotonic_ns().saturating_add(50_000_000);
        let done = loop {
            let idx = unsafe {
                ((self.tx.virt + self.tx.used_off as u64 + 2) as *const u16).read_volatile()
            };
            if idx != self.tx.seen {
                break idx;
            }
            if crate::time::monotonic_ns() > deadline {
                crate::serial_println!("[virtio-net] tx timeout");
                return Err("timeout");
            }
            core::hint::spin_loop();
        };
        self.tx.seen = done;
        fence(Ordering::SeqCst);
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
